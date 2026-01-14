package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/shimtx"
	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type userEntry struct {
	userId

	RevokeOnDelete    bool          `json:"revoke_on_delete,omitempty"`
	CredsDefaultTtl   time.Duration `json:"creds_default_ttl,omitempty"`
	CredsMaxTtl       time.Duration `json:"creds_max_ttl,omitempty"`
	DefaultSigningKey string        `json:"default_signing_key,omitempty"`

	RawClaims json.RawMessage `json:"claims,omitempty"`
}

type userId struct {
	op   string
	acc  string
	user string
}

type userPather interface {
	configPather
	operatorId() operatorId
	accountId() accountId
}

func UserId(op, acc, user string) userId {
	return userId{
		op:   op,
		acc:  acc,
		user: user,
	}
}

func UserIdField(d *framework.FieldData) userId {
	return userId{
		op:   d.Get("operator").(string),
		acc:  d.Get("account").(string),
		user: d.Get("user").(string),
	}
}

func (id userId) nkeyName() string {
	return id.user
}

func (id userId) operatorId() operatorId {
	return OperatorId(id.op)
}

func (id userId) accountId() accountId {
	return AccountId(id.op, id.acc)
}

func (id userId) configPath() string {
	return usersPathPrefix + id.op + "/" + id.acc + "/" + id.user
}

func (id userId) credsPath() string {
	return credsPathPrefix + id.op + "/" + id.acc + "/" + id.user
}

func (id userId) nkeyPath() string {
	return userKeysPathPrefix + id.op + "/" + id.acc + "/" + id.user
}

func (id userId) rotatePath() string {
	return rotateUserPathPrefix + id.op + "/" + id.acc + "/" + id.user
}

func pathConfigUser(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: usersPathPrefix + operatorRegex + "/" + accountRegex + "/" + userRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"user":     userField,
				"claims": {
					Type:        framework.TypeMap,
					Description: "Override default claims in the generated credentials for this user. See https://pkg.go.dev/github.com/nats-io/jwt/v2#UserClaims for available fields. Fields may be replaced with bracketed template variables that may be provided when requesting creds.",
					Required:    false,
				},
				"creds_default_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "If greater than 0, credentials created by this user will have the specified ttl. Otherwise, credentials created by this user will have no expiration time.",
					Default:     0,
				},
				"creds_max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "If greater than 0, credentials created by this user will have the specified ttl. Otherwise, credentials created by this user will have no expiration time.",
					Default:     0,
				},
				"revoke_on_delete": {
					Type:        framework.TypeBool,
					Description: "If set, the user subject is added to its account's revocation list upon deletion. The ttl of the revocation is set to the creds_ttl. Defaults to false.",
					Default:     false,
				},
				"default_signing_key": {
					Type:        framework.TypeString,
					Description: "If set, the specified signing key name will be used to sign generated credentials. Otherwise, the account key will be used.",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathUserExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathUserCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathUserCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathUserRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteUserIssue,
				},
			},
			HelpSynopsis:    `Manages user templates for dynamic credential generation.`,
			HelpDescription: `Create and manage templates that will be used to generate user credentials on-demand.`,
		},
		{
			Pattern: usersPathPrefix + operatorRegex + "/" + accountRegex + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"after":    afterField,
				"limit":    limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathUserList,
				},
			},
			HelpSynopsis: "List users.",
		},
	}
}

func (b *backend) User(ctx context.Context, storage logical.Storage, id userId) (*userEntry, error) {
	user, err := getFromStorage[userEntry](ctx, storage, id.configPath())
	if user != nil {
		user.userId = id
	}
	return user, err
}

func NewUser(id userId) *userEntry {
	return &userEntry{
		userId: id,
	}
}

func (b *backend) pathUserCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := UserIdField(d)

	accExists, err := b.accountExists(ctx, req.Storage, id.accountId())
	if err != nil {
		return nil, err
	}
	if !accExists {
		return logical.ErrorResponse("account %q does not exist", id.acc), nil
	}

	newUser := false
	user, err := b.User(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		newUser = true
		user = NewUser(id)
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

	resp := &logical.Response{}

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

		// clear fields we don't want to validate
		opClaims.IssuerAccount = "" // issuer account is overridden during cred generation

		var vr jwt.ValidationResults
		opClaims.Validate(&vr)

		errors := vr.Errors()
		if len(errors) > 0 {
			errResp := logical.ErrorResponse("validation error: %s", sprintErrors(errors))
			errResp.Warnings = append(errResp.Warnings, vr.Warnings()...)

			return errResp, nil
		} else {
			resp.Warnings = append(resp.Warnings, vr.Warnings()...)
		}
	}

	err = storeInStorage(ctx, req.Storage, id.configPath(), user)
	if err != nil {
		return nil, err
	}

	if newUser {
		// create nkey
		nkey, err := NewUserNKey(user.userId)
		if err != nil {
			return nil, err
		}
		storeInStorage(ctx, req.Storage, nkey.nkeyPath(), nkey)
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *backend) pathUserRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	user, err := b.User(ctx, req.Storage, UserIdField(d))
	if err != nil || user == nil {
		return nil, err
	}

	data := map[string]any{}

	if user.RevokeOnDelete {
		data["revoke_on_delete"] = user.RevokeOnDelete
	}

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

func (b *backend) pathUserExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	user, err := b.User(ctx, req.Storage, UserIdField(d))
	if err != nil {
		return false, err
	}

	return user != nil, nil
}

func (b *backend) pathUserList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	after := d.Get("after").(string)
	limit := d.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, AccountIdField(d).userConfigPrefix(), after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathDeleteUserIssue(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := UserIdField(d)
	user, err := b.User(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	jwtDirty, err := b.deleteUser(ctx, req.Storage, id, user.RevokeOnDelete, user.CredsMaxTtl)
	if err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	if jwtDirty {
		warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id.accountId())
		if err != nil {
			b.Logger().Warn("failed to reissue account jwt", "operator", id.op, "account", id.acc, "error", err)
			resp.AddWarning(fmt.Sprintf("failed to reissue jwt for account %q: %s", id.acc, err.Error()))
		} else {
			for _, v := range warnings {
				resp.AddWarning(fmt.Sprintf("while reissueing jwt for account %q: %s", id.acc, v))
			}

			accountSync, err := b.getAccountServer(ctx, req.Storage, id.operatorId())
			if err != nil {
				b.Logger().Warn("failed to retrieve account sync", "error", err)
			} else if accountSync != nil {
				err := b.syncAccountUpdate(ctx, req.Storage, accountSync, id.accountId())
				if err != nil {
					resp.AddWarning(fmt.Sprintf("failed to sync jwt for account %q: %s", id.acc, err.Error()))
				}
			}
		}
	}

	return resp, nil
}

// deleteUser returns true if the user was revoked (meaning the account is dirty), false otherwise.
func (b *backend) deleteUser(ctx context.Context, s logical.Storage, id userId, revoke bool, revokeTtl time.Duration) (bool, error) {
	accDirty := false

	if revoke {
		// account revocation list handling for deleted user
		account, err := b.Account(ctx, s, id.accountId())
		if err != nil {
			return false, err
		}
		if account != nil {
			err = b.addUserToRevocationList(ctx, s, account.accountId, id, revokeTtl)
			if err != nil {
				return false, err
			}

			accDirty = true
		}
	}

	// delete user config
	err := deleteFromStorage(ctx, s, id.configPath())
	if err != nil {
		return false, err
	}

	// delete user nkey
	err = deleteFromStorage(ctx, s, id.nkeyPath())
	if err != nil {
		return false, err
	}

	return accDirty, nil
}
