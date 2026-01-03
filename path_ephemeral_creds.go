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
	ephemeralUserSystemDefaultTtl = 5 * time.Minute
)

func pathEphemeralUserCreds(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: ephemeralCredsPathPrefix + operatorRegex + "/" + accountRegex + "/" + userRegex + "/" + sessionRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"user": {
					Type:        framework.TypeString,
					Description: "Name of the ephemeral user.",
					Required:    true,
				},
				"session": {
					Type:        framework.TypeString,
					Description: "Id for this session.",
					Required:    true,
				},
				"tags": {
					Type:        framework.TypeStringSlice,
					Description: "Additional tags to add to the user claims.",
					Required:    false,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The TTL of the generated credentials",
					Required:    false,
				},
				"signing_key": {
					Type:        framework.TypeString,
					Description: "Specify a signing key to use for these creds.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathEphemeralUserCredsRead,
				},
			},
			HelpSynopsis:    `Generates fresh user credentials on-demand.`,
			HelpDescription: `Reads the user template and generates a fresh JWT with current timestamp and provided parameters, then returns complete NATS credentials.`,
		},
	}
}

func (b *backend) pathEphemeralUserCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := EphemeralUserIdField(d)
	user, err := b.EphemeralUser(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	session := d.Get("session").(string)

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

	if ttl <= 0 {
		warnings = append(warnings, fmt.Sprintf("ephemeral users are not allowed to have an infinite ttl; using system default %s", ephemeralUserSystemDefaultTtl.String()))
		ttl = ephemeralUserSystemDefaultTtl
	}

	var tags []string = nil
	if tagsRaw, ok := d.GetOk("tags"); ok {
		tags = tagsRaw.([]string)
	}

	signingKeyName := d.Get("signing_key").(string)

	if signingKeyName == "" {
		signingKeyName = user.DefaultSigningKey
	}

	idKey, err := nkeys.CreateUser()
	if err != nil {
		return nil, fmt.Errorf("failed to create user identity key: %w", err)
	}
	sub, err := idKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	var claims *jwt.UserClaims
	if user.RawClaims != nil {
		err = json.Unmarshal(user.RawClaims, &claims)
		if err != nil {
			return nil, err
		}
	}

	limitFlags := LimitFlags(0)

	if claims == nil {
		claims = jwt.NewUserClaims(sub)
	} else {
		claims.Subject = sub

		limitFlags, err = readLimitFlags(user.RawClaims)
		if err != nil {
			return nil, err
		}
	}

	signingKey, enrichWarnings, err := b.enrichUserClaims(ctx, req.Storage, enrichUserParams{
		op:         id.op,
		acc:        id.acc,
		user:       id.user,
		session:    session,
		claims:     claims,
		signingKey: signingKeyName,
		tags:       tags,
		limitFlags: limitFlags,
	})
	if err != nil {
		return nil, err
	}

	result := b.generateUserCreds(idKey, signingKey, claims, ttl)
	if len(result.errors) > 0 {
		errResp := logical.ErrorResponse("failed to generate user creds")
		for _, w := range result.warnings {
			errResp.AddWarning(w)
		}

		errStrings := make([]string, 0, len(result.errors))
		for _, v := range result.errors {
			errStrings = append(errStrings, v.Error())
		}
		errResp.Data["data"] = map[string]any{
			"details": errStrings,
		}
		return errResp, nil
	}

	resp := b.Secret(userCredsType).Response(map[string]any{
		"operator":   user.op,
		"account":    user.acc,
		"user":       user.user,
		"session":    session,
		"creds":      result.creds,
		"jwt":        result.jwt,
		"seed":       result.seed,
		"expires_at": result.expiresAt.Unix(),
	}, map[string]any{
		"op":  user.op,
		"acc": user.acc,
		"sub": sub,
		"exp": result.expiresAt.Unix(),
	})

	for _, w := range enrichWarnings {
		resp.AddWarning(w)
	}

	for _, w := range result.warnings {
		resp.AddWarning(w)
	}

	resp.Secret.Renewable = false
	resp.Secret.LeaseOptions.TTL = ttl
	resp.Secret.LeaseOptions.MaxTTL = ttl

	return resp, nil
}
