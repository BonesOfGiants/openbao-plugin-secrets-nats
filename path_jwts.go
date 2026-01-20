package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// jwtEntry represents a JWT stored in the backend
type jwtEntry struct {
	Token  string `json:"token"`
	Issuer string `json:"issuer"`
}

func NewJwt(token string, issuer string) *jwtEntry {
	return &jwtEntry{
		Token:  token,
		Issuer: issuer,
	}
}

func pathJWT(b *backend) []*framework.Path {
	responseList := map[int][]framework.Response{
		http.StatusOK: {{
			Description: "OK",
			Fields: map[string]*framework.FieldSchema{
				"keys": {
					Type:     framework.TypeStringSlice,
					Required: true,
				},
			},
		}},
	}

	return []*framework.Path{
		{
			HelpSynopsis: `Reads account JWTs.`,
			Pattern:      accountJwtsPathPrefix + operatorRegex + "/" + accountRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
			},
			ExistenceCheck: b.pathAccountJWTExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountJWT,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"jwt": {
									Type:        framework.TypeString,
									Description: "The account JWT.",
									Required:    true,
								},
							},
						}},
					},
				},
			},
		},
		{
			HelpSynopsis: `Lists account JWTs.`,
			Pattern:      accountJwtsPathPrefix + operatorRegex + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"after":    afterField,
				"limit":    limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback:  b.pathAccountList,
					Responses: responseList,
				},
			},
		},
		{
			HelpSynopsis: `Reads operator JWTs.`,
			Pattern:      operatorJwtsPathPrefix + operatorRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
			},
			ExistenceCheck: b.pathOperatorExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathOperatorJwtRead,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"jwt": {
									Type:        framework.TypeString,
									Description: "The operator JWT.",
									Required:    true,
								},
							},
						}},
					},
				},
			},
		},
		{
			HelpSynopsis: "Lists operator JWTs.",
			Pattern:      operatorJwtsPathPrefix + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"after": afterField,
				"limit": limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback:  b.pathOperatorList,
					Responses: responseList,
				},
			},
		},
	}
}

type jwtPather interface {
	jwtPath() string
}

func (b *backend) Jwt(ctx context.Context, s logical.Storage, id jwtPather) (*jwtEntry, error) {
	var jwt *jwtEntry
	err := get(ctx, s, id.jwtPath(), &jwt)
	return jwt, err
}

func (b *backend) pathOperatorJwtRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	jwt, err := b.Jwt(ctx, req.Storage, OperatorIdField(d))
	if err != nil {
		return nil, err
	}
	if jwt == nil {
		return nil, nil
	}

	data := map[string]any{
		"jwt": jwt.Token,
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathReadAccountJWT(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	jwt, err := b.Jwt(ctx, req.Storage, AccountIdField(d))
	if err != nil {
		return nil, err
	}
	if jwt == nil {
		return nil, nil
	}

	data := map[string]any{
		"jwt": jwt.Token,
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathAccountJWTExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	jwt, err := b.Jwt(ctx, req.Storage, AccountIdField(d))
	if err != nil {
		return false, err
	}

	return jwt != nil, nil
}

type jwtWarnings []string

type jwtResult struct {
	warnings  jwtWarnings
	errors    []error
	jwt       string
	issuer    string
	expiresAt time.Time
}

func NewJwtResult() *jwtResult {
	return &jwtResult{
		warnings: jwtWarnings{},
		errors:   []error{},
	}
}

func (r *jwtResult) Error() string {
	errs := []string{}
	for _, v := range r.errors {
		errs = append(errs, v.Error())
	}

	return strings.Join(errs, ", ")
}

func (r *jwtResult) AddWarning(warning ...string) {
	r.warnings = append(r.warnings, warning...)
}

func (r *jwtResult) AddError(err ...error) {
	r.errors = append(r.errors, err...)
}

func (b *backend) issueAndSaveOperatorJWT(ctx context.Context, storage logical.Storage, id operatorId) (jwtWarnings, error) {
	idNkey, err := b.Nkey(ctx, storage, id)
	if err != nil {
		return nil, err
	}
	if idNkey == nil {
		return nil, fmt.Errorf("id key does not exist")
	}
	idKey, err := idNkey.keyPair()
	if err != nil {
		return nil, err
	}

	operator, err := b.Operator(ctx, storage, id)
	if err != nil {
		return nil, err
	}
	if operator == nil {
		return nil, fmt.Errorf("operator does not exist")
	}

	sub, err := idKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	claims := jwt.NewOperatorClaims(sub)
	if operator.RawClaims != nil {
		rawClaims := operator.RawClaims

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

		var opClaims jwt.Operator
		err = json.Unmarshal(rawClaims, &opClaims)
		if err != nil {
			return nil, err
		}

		claims.Operator = opClaims
	}

	warnings, err := b.enrichOperatorClaims(ctx, storage, id, operator.SysAccountName, claims)
	if err != nil {
		return nil, err
	}

	result := encodeOperatorJwt(idKey, claims)
	if warnings == nil {
		warnings = result.warnings
	} else {
		warnings = append(warnings, result.warnings...)
	}
	if len(result.errors) > 0 {
		return warnings, result
	}

	err = storeInStorage(ctx, storage, operator.jwtPath(), NewJwt(result.jwt, result.issuer))
	if err != nil {
		return nil, err
	}
	return warnings, nil
}

func (b *backend) enrichOperatorClaims(ctx context.Context, s logical.Storage, id operatorId, sysAccountName string, claims *jwt.OperatorClaims) (jwtWarnings, error) {
	warnings := jwtWarnings{}

	// set op name
	claims.ClaimsData.Name = id.op

	// force operator jwt not to expire
	claims.ClaimsData.Expires = 0
	// force operator jwt to always be valid
	claims.ClaimsData.NotBefore = 0

	// add system account
	if sysAccountName != "" {
		sysNkey, err := b.Nkey(ctx, s, id.accountId(sysAccountName))
		if err != nil {
			return warnings, err
		}
		if sysNkey != nil {
			sysSubject, err := sysNkey.publicKey()
			if err != nil {
				return warnings, err
			}
			claims.SystemAccount = sysSubject
		} else {
			warnings = append(warnings, fmt.Sprintf("system account %q does not exist, so it was not added to the claims", sysAccountName))
		}
	}

	// add signing keys
	var signingKeys jwt.StringList
	if claims.Operator.SigningKeys != nil {
		signingKeys = make(jwt.StringList, 0, len(claims.Operator.SigningKeys))
		copy(signingKeys, claims.Operator.SigningKeys)
	} else {
		signingKeys = jwt.StringList{}
	}

	for nkey, err := range b.listOperatorSigningKeys(ctx, s, id) {
		if err != nil {
			return warnings, err
		}

		publicKey, err := nkey.publicKey()
		if err != nil {
			return warnings, err
		}

		signingKeys.Add(publicKey)
	}

	if len(signingKeys) > 0 {
		claims.Operator.SigningKeys = signingKeys
	}

	return warnings, nil
}

func encodeOperatorJwt(signingKey nkeys.KeyPair, claims *jwt.OperatorClaims) *jwtResult {
	res := NewJwtResult()

	// validate the jwt just in case
	var vr jwt.ValidationResults
	claims.Validate(&vr)
	res.warnings = vr.Warnings()

	res.AddError(vr.Errors()...)
	if len(res.errors) != 0 {
		return res
	}

	// Convert and encode JWT
	jwt, err := claims.Encode(signingKey)
	if err != nil {
		res.AddError(fmt.Errorf("failed to encode jwt: %w", err))
		return res
	}

	res.jwt = jwt

	return res
}

func (b *backend) issueAndSaveAccountJWT(ctx context.Context, storage logical.Storage, reader AccountReader) (jwtWarnings, error) {
	warnings := jwtWarnings{}
	var signingKey nkeys.KeyPair

	account, err := reader.Account(ctx, storage)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, nil
	}

	opId := reader.AccountId().operatorId()

	desiredKey := ""
	selectedKey := ""

	// first try account signing key
	if account.SigningKey != "" {
		currentKey := fmt.Sprintf("%q (from account definition)", account.SigningKey)
		if desiredKey == "" {
			desiredKey = currentKey
		}
		nkey, err := b.Nkey(ctx, storage, opId.signingKeyId(account.SigningKey))
		if err != nil {
			return warnings, err
		}
		if nkey != nil {
			sk, err := nkey.keyPair()
			if err != nil {
				return warnings, err
			}
			signingKey = sk
			selectedKey = currentKey
		}
	}

	// then try the operator default signing key
	if signingKey == nil {
		operator, err := b.Operator(ctx, storage, opId)
		if err != nil {
			return warnings, err
		}
		if operator != nil && operator.DefaultSigningKey != "" {
			currentKey := fmt.Sprintf("%q (from operator default)", operator.DefaultSigningKey)
			if desiredKey == "" {
				desiredKey = currentKey
			}
			nkey, err := b.Nkey(ctx, storage, opId.signingKeyId(operator.DefaultSigningKey))
			if err != nil {
				return warnings, err
			}
			if nkey != nil {
				sk, err := nkey.keyPair()
				if err != nil {
					return warnings, err
				}
				signingKey = sk
				selectedKey = currentKey
			}
		}
	}

	// finally try the operator identity key
	if signingKey == nil {
		operatorNKey, err := b.Nkey(ctx, storage, account.operatorId())
		if err != nil {
			return warnings, err
		}
		if operatorNKey == nil {
			return warnings, fmt.Errorf("operator identity key does not exist")
		}
		sk, err := operatorNKey.keyPair()
		if err != nil {
			return warnings, err
		}

		signingKey = sk
		selectedKey = "operator identity key"
	}

	if signingKey == nil {
		return warnings, fmt.Errorf("failed to resolve a signing key")
	}

	if desiredKey != "" && desiredKey != selectedKey {
		warnings = append(warnings, fmt.Sprintf("could not use signing key %s as it does not exist; defaulting to %s", desiredKey, selectedKey))
	}

	idNKey, err := b.Nkey(ctx, storage, account)
	if err != nil {
		return warnings, err
	}
	if idNKey == nil {
		return warnings, fmt.Errorf("account nkey does not exist")
	}
	idKey, err := idNKey.keyPair()
	if err != nil {
		return warnings, err
	}

	sub, err := idKey.PublicKey()
	if err != nil {
		return warnings, fmt.Errorf("failed to decode public key: %w", err)
	}

	claims := jwt.NewAccountClaims(sub)
	if account.RawClaims != nil {
		rawClaims := account.RawClaims

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

		var opClaims jwt.Account
		err = json.Unmarshal(rawClaims, &opClaims)
		if err != nil {
			return nil, err
		}

		unlimitedClaims := claims.Account.Limits
		claims.Account = opClaims

		// ensure consistency with expected defaults
		if claims.SigningKeys == nil {
			claims.SigningKeys = jwt.SigningKeys{}
		}
		if claims.Mappings == nil {
			claims.Mappings = jwt.Mapping{}
		}

		// we need to futz with the raw mapping
		// because the claims obj can't differentiate
		// between missing and 0
		var nats map[string]any
		err = json.Unmarshal(rawClaims, &nats)
		if err != nil {
			goto cont
		}

		limitsRaw, ok := nats["limits"]
		if !ok {
			claims.Limits = unlimitedClaims
			goto cont
		}
		limits, ok := limitsRaw.(map[string]any)
		if !ok {
			claims.Limits = unlimitedClaims
			goto cont
		}
		_, ok = limits["subs"]
		if !ok {
			claims.Limits.Subs = jwt.NoLimit
		}
		_, ok = limits["data"]
		if !ok {
			claims.Limits.Data = jwt.NoLimit
		}
		_, ok = limits["payload"]
		if !ok {
			claims.Limits.Payload = jwt.NoLimit
		}
		_, ok = limits["imports"]
		if !ok {
			claims.Limits.Imports = jwt.NoLimit
		}
		_, ok = limits["exports"]
		if !ok {
			claims.Limits.Exports = jwt.NoLimit
		}
		_, ok = limits["wildcards"]
		if !ok {
			claims.Limits.WildcardExports = true
		}
		_, ok = limits["conn"]
		if !ok {
			claims.Limits.Conn = jwt.NoLimit
		}
		_, ok = limits["leaf"]
		if !ok {
			claims.Limits.LeafNodeConn = jwt.NoLimit
		}
	}
cont:

	enrichWarnings, err := b.enrichAccountClaims(ctx, storage, account.accountId, claims)
	if err != nil {
		return warnings, err
	}
	warnings = append(warnings, enrichWarnings...)

	result := encodeAccountJwt(signingKey, claims)
	warnings = append(warnings, result.warnings...)
	if len(result.errors) > 0 {
		return warnings, result
	}

	err = storeInStorage(ctx, storage, account.jwtPath(), NewJwt(result.jwt, result.issuer))
	if err != nil {
		return warnings, err
	}
	return warnings, nil
}

func (b *backend) enrichAccountClaims(ctx context.Context, s logical.Storage, id accountId, claims *jwt.AccountClaims) (jwtWarnings, error) {
	// set account name
	claims.ClaimsData.Name = id.acc

	// force account jwt not to expire
	claims.ClaimsData.Expires = 0

	// force account jwt to always be valid
	claims.ClaimsData.NotBefore = 0

	// add account public key to the claim
	accountNKey, err := b.Nkey(ctx, s, id)
	if err != nil {
		return nil, err
	}
	if accountNKey == nil {
		return nil, fmt.Errorf("account nkey does not exist")
	}
	accountKeyPair, err := accountNKey.keyPair()
	if err != nil {
		return nil, err
	}
	accountPublicKey, err := accountKeyPair.PublicKey()
	if err != nil {
		return nil, err
	}
	claims.ClaimsData.Subject = accountPublicKey

	// add any externally defined imports to the claim
	imports := jwt.Imports{}
	for imp, err := range b.listAccountImports(ctx, s, id) {
		if err != nil {
			return nil, err
		}

		imports = append(imports, imp.Imports...)
	}

	if len(imports) > 0 {
		claims.Imports = imports
	}

	// add any externally defined revocations to the claim
	revocations := map[string]int64{}
	for revocation, err := range b.listAccountRevocations(ctx, s, id) {
		if err != nil {
			return nil, err
		}

		revocations[revocation.sub] = revocation.CreationTime.Unix()
	}

	if len(revocations) > 0 {
		claims.Revocations = revocations
	}

	// add signing keys
	var signingKeys jwt.SigningKeys
	if claims.Account.SigningKeys != nil {
		signingKeys = make(jwt.SigningKeys, len(claims.Account.SigningKeys))
		maps.Copy(signingKeys, claims.Account.SigningKeys)
	} else {
		signingKeys = jwt.SigningKeys{}
	}

	for nkey, err := range b.listAccountSigningKeys(ctx, s, id) {
		if err != nil {
			return nil, err
		}

		publicKey, err := nkey.publicKey()
		if err != nil {
			return nil, err
		}

		if nkey.Scoped {
			scope := jwt.NewUserScope()
			scope.Key = publicKey
			scope.Role = nkey.nkeyName()

			scope.Description = nkey.UserScope.Description

			if nkey.UserScope.Template != nil {
				var template jwt.UserPermissionLimits
				err = json.Unmarshal(nkey.UserScope.Template, &template)
				if err != nil {
					return nil, err
				}
				scope.Template = template
			}

			signingKeys.AddScopedSigner(scope)
		} else {
			signingKeys.Add(publicKey)
		}
	}

	if len(signingKeys) > 0 {
		claims.Account.SigningKeys = signingKeys
	}

	return nil, nil
}

func encodeAccountJwt(signingKey nkeys.KeyPair, claims *jwt.AccountClaims) *jwtResult {
	res := NewJwtResult()

	// validate the jwt just in case
	var vr jwt.ValidationResults
	claims.Validate(&vr)
	res.warnings = vr.Warnings()

	res.AddError(vr.Errors()...)
	if len(res.errors) != 0 {
		return res
	}

	jwt, err := claims.Encode(signingKey)
	if err != nil {
		res.AddError(fmt.Errorf("failed to encode jwt: %s", err))
		return res
	}

	res.jwt = jwt

	return res
}

type LimitFlags uint8

const (
	LimitFlagsSubs    LimitFlags = 1 << iota // 1
	LimitFlagsData                           // 2
	LimitFlagsPayload                        // 4
	LimitFlagsSrc                            // 8
	LimitFlagsOther                          // 16

	LimitFlagsHasLimits = LimitFlagsSubs | LimitFlagsData | LimitFlagsPayload | LimitFlagsSrc | LimitFlagsOther
)

type enrichUserParams struct {
	op         string
	acc        string
	user       string
	session    string
	claims     *jwt.UserClaims
	signingKey string
	tags       []string
	limitFlags LimitFlags
	nbf        int64
}

func (b *backend) enrichUserClaims(ctx context.Context, s logical.Storage, p enrichUserParams) (nkeys.KeyPair, jwtWarnings, error) {
	accId := AccountId(p.op, p.acc)
	accountNkey, err := b.Nkey(ctx, s, accId)
	if err != nil {
		return nil, nil, err
	}
	if accountNkey == nil {
		return nil, nil, fmt.Errorf("unable to sign creds; account %q nkey is missing", accId.acc)
	}
	issuerKey, err := accountNkey.keyPair()
	if err != nil {
		return nil, nil, err
	}

	claims := p.claims

	warnings := jwtWarnings{}

	useDefaultLimits := true

	var signingKey nkeys.KeyPair
	if p.signingKey != "" {
		nkey, err := b.Nkey(ctx, s, accId.signingKeyId(p.signingKey))
		if err != nil {
			return nil, nil, err
		}
		if nkey == nil {
			return nil, nil, fmt.Errorf("invalid signing key %q specified", p.signingKey)
		}

		sk, err := nkey.keyPair()
		if err != nil {
			return nil, nil, err
		}
		signingKey = sk

		if nkey.Scoped {
			// scoped users are not allowed to specify any values within UserPermissionLimits
			if p.limitFlags&LimitFlagsHasLimits != 0 {
				warnings = append(warnings, "ignoring limits in user claims due to scope")
			}
			claims.UserPermissionLimits = jwt.UserPermissionLimits{}
			useDefaultLimits = false
		}
	}

	if signingKey == nil {
		signingKey = issuerKey
	}

	name := p.user
	if p.session != "" {
		name = p.session
	}

	claims.ClaimsData.Name = name

	if p.nbf > 0 {
		claims.NotBefore = p.nbf
	}

	if useDefaultLimits {
		// mimic behavior of jwt.NewUserClaims
		if p.limitFlags&LimitFlagsSrc == 0 {
			if claims.Src == nil {
				claims.Src = jwt.CIDRList{}
			}
		}
		if p.limitFlags&LimitFlagsSubs == 0 {
			claims.Limits.Subs = -1
		}
		if p.limitFlags&LimitFlagsData == 0 {
			claims.Limits.Data = -1
		}
		if p.limitFlags&LimitFlagsPayload == 0 {
			claims.Limits.Payload = -1
		}
	}

	{
		// merge + deduplicate tags
		tags := jwt.TagList{}
		if claims.Tags != nil {
			tags.Add(claims.Tags...)
		}

		if p.tags != nil {
			tags.Add(p.tags...)
		}

		claims.Tags = tags
	}

	if signingKey != issuerKey {
		accountId, err := issuerKey.PublicKey()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode issuer key: %w", err)
		}
		claims.User.IssuerAccount = accountId
	} else {
		claims.User.IssuerAccount = ""
	}

	return signingKey, warnings, nil
}

func encodeUserJWT(signingKey nkeys.KeyPair, claims *jwt.UserClaims, ttl time.Duration) *jwtResult {
	res := NewJwtResult()

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
		claims.ClaimsData.Expires = expiresAt.Unix()
	} else {
		claims.ClaimsData.Expires = 0
	}

	var vr jwt.ValidationResults
	claims.Validate(&vr)
	res.warnings = vr.Warnings()

	res.AddError(vr.Errors()...)
	if len(res.errors) != 0 {
		return res
	}

	jwt, err := claims.Encode(signingKey)
	if err != nil {
		res.AddError(fmt.Errorf("failed to encode jwt: %s", err))
		return res
	}

	res.jwt = jwt
	res.expiresAt = expiresAt

	return res
}
