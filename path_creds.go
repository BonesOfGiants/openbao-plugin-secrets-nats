package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const (
	// An extra bit of time to ensure that under normal circumstances a revoke at the end of a lease is a noop
	revokeDurationBuffer = (time.Duration(5) * time.Second)
)

type credsPather interface {
	credsPath() string
}

func pathUserCreds(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: credsPathPrefix + operatorRegex + "/" + accountRegex + "/" + userRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"user":     userField,
				"signing_key": {
					Type:        framework.TypeString,
					Description: "Specify a signing key to use for these creds.",
					Required:    false,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The TTL of the generated credentials",
					Required:    false,
				},
				"not_before": {
					Type:        framework.TypeTime,
					Description: "Specify a nbf timestamp for the generated jwt.",
					Required:    false,
				},
				"tags": {
					Type:        framework.TypeStringSlice,
					Description: "Additional tags to add to the user claims.",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathUserCredsExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathUserCredsRead,
				},
			},
			HelpSynopsis:    `Generates fresh user credentials on demand.`,
			HelpDescription: `Reads the user template and generates fresh credentials with current timestamp and provided parameters.`,
		},
		{
			Pattern: credsPathPrefix + operatorRegex + "/" + accountRegex + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"after":    afterField,
				"limit":    limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathUserCredsList,
				},
			},
			HelpSynopsis:    "List available user credential templates",
			HelpDescription: "List all users that have credential templates configured",
		},
	}
}

func (b *backend) userCredsSecretType() *framework.Secret {
	return &framework.Secret{
		Type:   userCredsType,
		Renew:  nil,
		Fields: map[string]*framework.FieldSchema{},
		Revoke: b.userCredsRevoke,
	}
}

func (b *backend) pathUserCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := UserIdField(d)
	user, err := b.User(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	ttl := time.Duration(0)
	ttlRaw, ok := d.GetOk("ttl")
	if ok {
		ttl = time.Duration(ttlRaw.(int)) * time.Second
	} else if user.CredsDefaultTtl > 0 {
		ttl = user.CredsDefaultTtl
	} else {
		ttl = b.System().DefaultLeaseTTL()
	}

	var warnings []string
	if user.CredsMaxTtl > 0 && ttl > user.CredsMaxTtl {
		warnings = append(warnings, fmt.Sprintf("ttl of %s is greater than the user's creds_max_ttl of %s; capping accordingly", ttl.String(), user.CredsMaxTtl.String()))
		ttl = user.CredsMaxTtl
	}

	maxTtl := b.System().MaxLeaseTTL()
	if ttl > maxTtl {
		warnings = append(warnings, fmt.Sprintf("ttl of %s is greater than OpenBao's max lease ttl %s; capping accordingly", ttl.String(), maxTtl.String()))
		ttl = maxTtl
	}

	var tags []string = nil
	if tagsRaw, ok := d.GetOk("tags"); ok {
		tags = tagsRaw.([]string)
	}

	signingKeyName := d.Get("signing_key").(string)

	if signingKeyName == "" {
		signingKeyName = user.DefaultSigningKey
	}

	if signingKeyName == "" {
		account, err := b.Account(ctx, req.Storage, id.accountId())
		if err != nil {
			return nil, err
		}
		if account != nil {
			signingKeyName = account.DefaultSigningKey
		}
	}

	nbf := int64(0)
	if nbfRaw, ok := d.GetOk("not_before"); ok {
		nbfTime, ok := nbfRaw.(time.Time)
		if !ok {
			return nil, fmt.Errorf("failed to parse not_before; got %T", nbfRaw)
		}

		nbf = nbfTime.Unix()
	}

	userIdKey, err := b.Nkey(ctx, req.Storage, user)
	if err != nil {
		return nil, err
	}
	if userIdKey == nil {
		return nil, nil
	}

	idKey, err := userIdKey.keyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to decode user identity key: %w", err)
	}
	sub, err := idKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	limitFlags := LimitFlags(0)
	claims := jwt.NewUserClaims(sub)
	if user.RawClaims != nil {
		rawClaims := user.RawClaims

		var claimsMap map[string]json.RawMessage
		err = json.Unmarshal(rawClaims, &claimsMap)
		if err != nil {
			return nil, err
		}

		innerClaims, ok := claimsMap["nats"]
		if ok {
			// this is an old-style claims
			rawClaims = innerClaims
		}

		var opClaims jwt.User
		err = json.Unmarshal(rawClaims, &opClaims)
		if err != nil {
			return nil, err
		}

		claims.User = opClaims
		claims.Subject = sub

		limitFlags, err = readLimitFlags(rawClaims)
		if err != nil {
			return nil, err
		}
	}

	signingKey, enrichWarnings, err := b.enrichUserClaims(ctx, req.Storage, enrichUserParams{
		op:         id.op,
		acc:        id.acc,
		user:       id.user,
		claims:     claims,
		signingKey: signingKeyName,
		tags:       tags,
		limitFlags: limitFlags,
		nbf:        nbf,
	})
	if err != nil {
		return logical.ErrorResponse("failed to generate user creds: %s", err.Error()), nil
	}

	result := b.generateUserCreds(idKey, signingKey, claims, ttl)
	if len(result.errors) > 0 {
		errResp := logical.ErrorResponse("failed to generate user creds: %s", sprintErrors(result.errors))
		for _, w := range result.warnings {
			errResp.AddWarning(w)
		}

		return errResp, nil
	}

	resp := b.Secret(userCredsType).Response(map[string]any{
		"operator":   id.op,
		"account":    id.acc,
		"user":       id.user,
		"creds":      result.creds,
		"jwt":        result.jwt,
		"seed":       string(userIdKey.Seed),
		"expires_at": result.expiresAt.Unix(),
	}, map[string]any{
		"op":  id.op,
		"acc": id.acc,
		"sub": sub,
		"exp": result.expiresAt.Unix(),
	})

	if signingKeyName != "" {
		resp.Data["signing_key"] = signingKeyName
	}

	resp.Warnings = append(resp.Warnings, enrichWarnings...)
	resp.Warnings = append(resp.Warnings, result.warnings...)

	resp.Secret.LeaseOptions.TTL = ttl
	resp.Secret.LeaseOptions.MaxTTL = resp.Secret.TTL

	return resp, nil
}

func (b *backend) pathUserCredsList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// defer to user list,
	// since we don't keep storage for user creds
	return b.pathUserList(ctx, req, data)
}

func (b *backend) pathUserCredsExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	user, err := b.User(ctx, req.Storage, UserIdField(d))
	if err != nil {
		return false, err
	}

	return user != nil, nil
}

func readLimitFlags(claims json.RawMessage) (LimitFlags, error) {
	// we need to futz with the raw mapping
	// because the claims can't differentiate
	// between missing and 0
	var nats map[string]any
	err := json.Unmarshal(claims, &nats)
	if err != nil {
		return 0, err
	}

	var flags LimitFlags
	for k := range nats {
		switch k {
		case "pub", "sub", "resp", "times", "times_location",
			"bearer_token", "proxy_required", "allowed_connection_types":
			flags |= LimitFlagsOther
		case "src":
			flags |= LimitFlagsSrc
		case "subs":
			flags |= LimitFlagsSubs
		case "data":
			flags |= LimitFlagsData
		case "payload":
			flags |= LimitFlagsPayload
		}
	}

	return flags, nil
}

type userCredsResult struct {
	warnings  []string
	errors    []error
	creds     string
	jwt       string
	seed      string
	expiresAt time.Time
}

func (r *userCredsResult) AddWarning(warning ...string) {
	r.warnings = append(r.warnings, warning...)
}

func (r *userCredsResult) AddError(err ...error) {
	r.errors = append(r.errors, err...)
}

func (b *backend) generateUserCreds(idKey nkeys.KeyPair, signingKey nkeys.KeyPair, claims *jwt.UserClaims, ttl time.Duration) *userCredsResult {
	res := &userCredsResult{}

	jwtResult := encodeUserJWT(signingKey, claims, ttl)
	res.expiresAt = jwtResult.expiresAt
	res.warnings = jwtResult.warnings
	res.errors = jwtResult.errors
	if len(res.errors) > 0 {
		return res
	}
	res.jwt = jwtResult.jwt

	seed, err := idKey.Seed()
	if err != nil {
		res.AddError(fmt.Errorf("failed to decode seed: %w", err))
		return res
	}
	res.seed = string(seed)

	creds, err := jwt.FormatUserConfig(jwtResult.jwt, seed)
	if err != nil {
		res.AddError(fmt.Errorf("failed to format user creds: %w", err))
		return res
	}
	res.creds = string(creds)

	return res
}

func (b *backend) userCredsRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	expRaw := req.Secret.InternalData["exp"]

	exp := time.Unix(int64(expRaw.(float64)), 0)
	now := time.Now()
	ttl := exp.Sub(now)

	if ttl <= revokeDurationBuffer {
		// jwt is already (nearly) expired, no need to do anything
		return nil, nil
	}

	id := AccountRevocationId(
		req.Secret.InternalData["op"].(string),
		req.Secret.InternalData["acc"].(string),
		req.Secret.InternalData["sub"].(string),
	)

	account, err := b.Account(ctx, req.Storage, id.accountId())
	if err != nil {
		return nil, err
	}
	if account == nil {
		// target account does not exist, no need to do anything
		return nil, nil
	}

	revocation, err := b.AccountRevocation(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if revocation != nil {
		expirationTime := revocation.CreationTime.Add(revocation.Ttl)
		remainingTtl := expirationTime.Sub(now)

		if remainingTtl < ttl {
			revocation.Ttl = ttl
			revocation.CreationTime = now
		}
	} else {
		revocation = NewAccountRevocationWithParams(id, now, ttl)
	}

	err = storeInStorage(ctx, req.Storage, id.configPath(), revocation)
	if err != nil {
		return nil, err
	}

	accountSync, err := b.getAccountSync(ctx, req.Storage, id.operatorId())
	if err != nil {
		return nil, fmt.Errorf("unable to sync jwt for account %q: %w", id.acc, err)
	} else if accountSync != nil {
		err := b.syncAccountUpdate(ctx, req.Storage, accountSync, id.accountId())
		if err != nil {
			return nil, fmt.Errorf("unable to sync jwt for account %q: %s", id.acc, err)
		}
	}

	return nil, nil
}
