package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/shimtx"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type ephemeralUserEntry struct {
	ephemeralUserId

	CredsDefaultTtl   time.Duration `json:"creds_default_ttl"`
	CredsMaxTtl       time.Duration `json:"creds_max_ttl"`
	DefaultSigningKey string        `json:"default_signing_key"`

	RawClaims json.RawMessage `json:"claims,omitempty"`
}

type ephemeralUserId struct {
	op   string
	acc  string
	user string
}

func EphemeralUserId(op, acc, user string) ephemeralUserId {
	return ephemeralUserId{
		op:   op,
		acc:  acc,
		user: user,
	}
}

func EphemeralUserIdField(d *framework.FieldData) ephemeralUserId {
	return ephemeralUserId{
		op:   d.Get("operator").(string),
		acc:  d.Get("account").(string),
		user: d.Get("user").(string),
	}
}

func (id ephemeralUserId) operatorId() operatorId {
	return OperatorId(id.op)
}

func (id ephemeralUserId) accountId() accountId {
	return AccountId(id.op, id.acc)
}

func (id ephemeralUserId) configPath() string {
	return ephemeralUsersPathPrefix + id.op + "/" + id.acc + "/" + id.user
}

func (id ephemeralUserId) ephemeralCredsPath(session string) string {
	return ephemeralCredsPathPrefix + id.op + "/" + id.acc + "/" + id.user + "/" + session
}

func pathConfigEphemeralUser(b *backend) []*framework.Path {
	responseOK := map[int][]framework.Response{
		http.StatusOK: {{
			Description: "OK",
		}},
	}
	responseNoContent := map[int][]framework.Response{
		http.StatusNoContent: {{
			Description: "No Content",
		}},
	}

	return []*framework.Path{
		{
			Pattern: ephemeralUsersPathPrefix + operatorRegex + "/" + accountRegex + "/" + userRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"user":     userField,
				"claims": {
					Type:        framework.TypeMap,
					Description: "Specify default claims for the credentials generated for this user. See https://pkg.go.dev/github.com/nats-io/jwt/v2#UserClaims for available fields. Claims are not merged; if the claims parameter is present it will overwrite any previous claims. Passing an explicit `null` to this field will clear the existing claims.",
					Required:    false,
				},
				"creds_default_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The default TTL for generated credentials, specified in seconds or as a Go duration format string, e.g. `\"1h\"`. If not set or 0, the system default will be used.",
					Default:     0,
				},
				"creds_max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The maximum TTL for generated credentials, specified in seconds or as a Go duration format string, e.g. `\"1h\"`. If not set or 0, the system default will be used.",
					Default:     0,
				},
				"default_signing_key": {
					Type:        framework.TypeString,
					Description: "Specify the name of an account signing key to use by default when generating credentials. If empty or not set, the user will be signed using the account's default signing key. This may be overridden by the creds `signing_key` parameter. The signing key need not exist when creating the user, but generating credentials will fail if the signing key doesn't exist.",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathEphemeralUserExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback:  b.pathEphemeralUserCreateUpdate,
					Responses: responseOK,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback:  b.pathEphemeralUserCreateUpdate,
					Responses: responseOK,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathEphemeralUserRead,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"claims": {
									Type:        framework.TypeMap,
									Description: "Custom claims used in the credentials issued for this user.",
									Required:    false,
								},
								"creds_default_ttl": {
									Type:        framework.TypeInt,
									Description: "The default TTL for generated credentials in seconds.",
								},
								"creds_max_ttl": {
									Type:        framework.TypeInt,
									Description: "The maximum TTL for generated credentials in seconds.",
								},
								"default_signing_key": {
									Type:        framework.TypeString,
									Description: "The name of the specified account signing key used by default when generating credentials.",
								},
							},
						}},
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback:  b.pathEphemeralUserDelete,
					Responses: responseNoContent,
				},
			},
			HelpSynopsis:    `Manages user templates for dynamic credential generation.`,
			HelpDescription: `Create and manage user templates that will be used to generate JWTs on-demand when credentials are requested.`,
		},
		{
			Pattern: ephemeralUsersPathPrefix + operatorRegex + "/" + accountRegex + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"after":    afterField,
				"limit":    limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathEphemeralUserList,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:     framework.TypeStringSlice,
									Required: true,
								},
							},
						}},
					},
				},
			},
			HelpSynopsis: "List ephemeral users.",
		},
	}
}

func NewEphemeralUser(id ephemeralUserId) *ephemeralUserEntry {
	return &ephemeralUserEntry{
		ephemeralUserId: id,
	}
}

func (b *backend) EphemeralUser(ctx context.Context, s logical.Storage, id ephemeralUserId) (*ephemeralUserEntry, error) {
	var user *ephemeralUserEntry
	err := get(ctx, s, id.configPath(), &user)
	if user != nil {
		user.ephemeralUserId = id
	}
	return user, err
}

func (b *backend) pathEphemeralUserCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := EphemeralUserIdField(d)

	accExists, err := b.accountExists(ctx, req.Storage, id.accountId())
	if err != nil {
		return nil, err
	}
	if !accExists {
		return logical.ErrorResponse("account %q does not exist", id.acc), nil
	}

	user, err := b.EphemeralUser(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		user = NewEphemeralUser(id)
	}

	if defaultSigningKey, ok := d.GetOk("default_signing_key"); ok {
		user.DefaultSigningKey = defaultSigningKey.(string)
	}

	if credsDefaultTtlRaw, ok := d.GetOk("creds_default_ttl"); ok {
		user.CredsDefaultTtl = time.Duration(credsDefaultTtlRaw.(int)) * time.Second
	}

	if credsMaxTtlRaw, ok := d.GetOk("creds_max_ttl"); ok {
		user.CredsMaxTtl = time.Duration(credsMaxTtlRaw.(int)) * time.Second
	}

	if claims, ok := d.GetOk("claims"); ok {
		if claims.(map[string]any) != nil {
			rawClaims, err := json.Marshal(claims.(map[string]any))
			if err != nil {
				return nil, err
			}
			user.RawClaims = rawClaims
		} else {
			user.RawClaims = nil
		}
	}

	resp, err := b.validateUserClaims(user.RawClaims)
	if err != nil {
		return nil, err
	}

	err = storeInStorage(ctx, req.Storage, id.configPath(), user)
	if err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *backend) pathEphemeralUserRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	user, err := b.EphemeralUser(ctx, req.Storage, EphemeralUserIdField(d))
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	data := map[string]any{}

	if user.CredsDefaultTtl > 0 {
		data["creds_default_ttl"] = user.CredsDefaultTtl.Seconds()
	}

	if user.CredsMaxTtl > 0 {
		data["creds_max_ttl"] = user.CredsMaxTtl.Seconds()
	}

	if user.DefaultSigningKey != "" {
		data["default_signing_key"] = user.DefaultSigningKey
	}

	if user.RawClaims != nil {
		var claims map[string]any
		err := json.Unmarshal(user.RawClaims, &claims)
		if err != nil {
			return nil, err
		}
		data["claims"] = claims
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathEphemeralUserExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	user, err := b.EphemeralUser(ctx, req.Storage, EphemeralUserIdField(d))
	if err != nil {
		return false, err
	}

	return user != nil, nil
}

func (b *backend) pathEphemeralUserList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	after := d.Get("after").(string)
	limit := d.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, AccountIdField(d).ephemeralUserConfigPrefix(), after, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathEphemeralUserDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	err = req.Storage.Delete(ctx, EphemeralUserIdField(d).configPath())
	if err != nil {
		return nil, fmt.Errorf("failed to delete users: %w", err)
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return nil, nil
}
