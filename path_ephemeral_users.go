package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
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
	return []*framework.Path{
		{
			Pattern: ephemeralUsersPathPrefix + operatorRegex + "/" + accountRegex + "/" + userRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"user":     userField,
				"default_signing_key": {
					Type:        framework.TypeString,
					Description: "The default signing key to use for generating user creds. If not set, users will by signed by the account key by default.",
					Required:    false,
				},
				"claims": {
					Type:        framework.TypeMap,
					Description: "Override default claims for generated user creds. See https://pkg.go.dev/github.com/nats-io/jwt/v2#UserClaims for available fields.",
					Required:    false,
				},
				"creds_default_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The default ttl for generated user creds. If not set or set to 0, will use a plugin default. Non-expiring creds are not allowed to be generated for ephemeral users.",
					Required:    false,
				},
				"creds_max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The max ttl for generated user creds. If not set or set to 0, will use a plugin default.",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathEphemeralUserExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathEphemeralUserCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathEphemeralUserCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathEphemeralUserRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathEphemeralUserDelete,
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

func NewEphemeralUserWithParams(
	id ephemeralUserId,
	revokeOnDelete bool,
	defaultTtl time.Duration,
	maxTtl time.Duration,
	defaultSigningKey string,
	claims json.RawMessage,
) *ephemeralUserEntry {
	return &ephemeralUserEntry{
		ephemeralUserId:   id,
		CredsDefaultTtl:   defaultTtl,
		CredsMaxTtl:       maxTtl,
		RawClaims:         claims,
		DefaultSigningKey: defaultSigningKey,
	}
}

func (b *backend) EphemeralUser(ctx context.Context, s logical.Storage, id ephemeralUserId) (*ephemeralUserEntry, error) {
	user, err := getFromStorage[ephemeralUserEntry](ctx, s, id.configPath())
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

	account, err := b.Account(ctx, req.Storage, id.accountId())
	if err != nil {
		return nil, err
	}
	if account == nil {
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
		user.CredsDefaultTtl = time.Duration(credsMaxTtlRaw.(int)) * time.Second
	}

	if claims, ok := d.GetOk("claims"); ok {
		c, ok := claims.(map[string]any)
		if !ok {
			return logical.ErrorResponse("claims must be a map, got %T", claims), nil
		}
		rawClaims, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		user.RawClaims = rawClaims
	}

	err = storeInStorage(ctx, req.Storage, id.configPath(), user)
	if err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return nil, nil
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

	err = deleteFromStorage(ctx, req.Storage, EphemeralUserIdField(d).configPath())
	if err != nil {
		return nil, fmt.Errorf("failed to delete users: %w", err)
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return nil, nil
}
