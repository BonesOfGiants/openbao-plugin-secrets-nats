package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/shimtx"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	DefaultSysAccountName = "SYS"
)

type operatorEntry struct {
	operatorId

	CreateSystemAccount bool            `json:"create_system_account"`
	SysAccountName      string          `json:"system_account_name"`
	RawClaims           json.RawMessage `json:"claims,omitempty"`
	DefaultSigningKey   string          `json:"default_signing_key"`
}

func (o *operatorEntry) Operator(ctx context.Context, s logical.Storage) (*operatorEntry, error) {
	return o, nil
}

func (o *operatorEntry) OperatorId() operatorId {
	return o.operatorId
}

type operatorId struct {
	op string
}

func OperatorId(op string) operatorId {
	return operatorId{
		op: op,
	}
}

func OperatorIdField(d *framework.FieldData) operatorId {
	return operatorId{
		op: d.Get("operator").(string),
	}
}

func (id operatorId) Operator(ctx context.Context, s logical.Storage) (*operatorEntry, error) {
	var operator *operatorEntry
	err := get(ctx, s, id.configPath(), &operator)
	if operator != nil {
		operator.operatorId = id
	}
	return operator, err
}

func (id operatorId) OperatorId() operatorId {
	return id
}

func (id operatorId) nkeyName() string {
	return id.op
}

func (id operatorId) configPath() string {
	return operatorsPathPrefix + id.op
}

func (id operatorId) nkeyPath() string {
	return operatorKeysPathPrefix + id.op
}

func (id operatorId) rotatePath() string {
	return rotateOperatorPathPrefix + id.op
}

func (id operatorId) jwtPath() string {
	return operatorJwtsPathPrefix + id.op
}

func (id operatorId) generateServerConfigPath() string {
	return operatorGenerateServerConfigPathPrefix + id.op
}

func (id operatorId) accountServerPath() string {
	return accountServersPathPrefix + id.op
}

func (id operatorId) signingKeyPrefix() string {
	return operatorSigningKeysPathPrefix + id.op + "/"
}

func (id operatorId) accountsConfigPrefix() string {
	return accountsPathPrefix + id.op + "/"
}

func (id operatorId) accountsNkeyPrefix() string {
	return accountKeysPathPrefix + id.op + "/"
}

func (id operatorId) accountsJwtPrefix() string {
	return accountJwtsPathPrefix + id.op + "/"
}

func (id operatorId) accountId(acc string) accountId {
	return AccountId(id.op, acc)
}

func (id operatorId) signingKeyId(name string) operatorSigningKeyId {
	return OperatorSigningKeyId(id.op, name)
}

type OperatorReader interface {
	OperatorId() operatorId
	Operator(ctx context.Context, s logical.Storage) (*operatorEntry, error)
}

var (
	DefaultSysAccountClaims = json.RawMessage(`{
	  "exports": [
	  	{
		  "name": "account-monitoring-services",
		  "subject": "$SYS.REQ.ACCOUNT.*.*",
		  "type": "service",
		  "response_type": "Stream",
		  "account_token_position": 4,
		  "description": "Request account specific monitoring services for: SUBSZ, CONNZ, LEAFZ, JSZ and INFO",
		  "info_url": "https://docs.nats.io/nats-server/configuration/sys_accounts"
		},
		{
		  "name": "account-monitoring-streams",
		  "subject": "$SYS.ACCOUNT.*.>",
		  "type": "stream",
		  "account_token_position": 3,
		  "description": "Account specific monitoring stream",
		  "info_url": "https://docs.nats.io/nats-server/configuration/sys_accounts"
		}
	  ]
	}`)
)

func pathConfigOperator(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: operatorsPathPrefix + operatorRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"create_system_account": {
					Type:        framework.TypeBool,
					Description: "If true, creates a system account for this operator with proper permissions. Defaults to false.",
					Default:     true,
				},
				"system_account_name": {
					Type:        framework.TypeString,
					Description: `If set, overrides the default system account name of "SYS" for this operator.`,
				},
				"default_signing_key": {
					Type:        framework.TypeString,
					Description: `If set, use the specified signing key to sign accounts instead of the identity key. Does not apply to existing accounts.`,
				},
				"claims": {
					Type:        framework.TypeMap,
					Description: "Override default claims for the issued JWT for this operator. See https://pkg.go.dev/github.com/nats-io/jwt/v2#OperatorClaims for available fields.",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathOperatorExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathOperatorCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathOperatorCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathOperatorRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathOperatorDelete,
				},
			},
			HelpSynopsis: "Manages operators.",
		},
		{
			Pattern: operatorsPathPrefix + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"after": afterField,
				"limit": limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathOperatorList,
				},
			},
			HelpSynopsis: "List operators.",
		},
	}
}

func (b *backend) Operator(ctx context.Context, s logical.Storage, id operatorId) (*operatorEntry, error) {
	return id.Operator(ctx, s)
}

func (b *backend) operatorExists(ctx context.Context, s logical.Storage, id operatorId) (bool, error) {
	entry, err := s.Get(ctx, id.configPath())
	if err != nil {
		return false, err
	}
	if entry == nil {
		return false, nil
	}

	return true, nil
}

func (b *backend) pathOperatorCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := OperatorIdField(d)

	jwtDirty := false
	newOperator := false
	operator, err := b.Operator(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if operator == nil {
		operator = &operatorEntry{
			operatorId:          id,
			CreateSystemAccount: true,
		}
		jwtDirty = true
		newOperator = true
	}

	oldCreateSystemAccount := operator.CreateSystemAccount
	if createSystemAccount, ok := d.GetOk("create_system_account"); ok {
		jwtDirty = jwtDirty || (operator.CreateSystemAccount != createSystemAccount)
		operator.CreateSystemAccount = createSystemAccount.(bool)
	}

	if defaultSigningKey, ok := d.GetOk("default_signing_key"); ok {
		jwtDirty = jwtDirty || (operator.DefaultSigningKey != defaultSigningKey)
		operator.DefaultSigningKey = defaultSigningKey.(string)
	}

	newCreateSystemAccount := operator.CreateSystemAccount

	oldSystemAccountName := operator.SysAccountName
	if systemAccountName, ok := d.GetOk("system_account_name"); ok {
		operator.SysAccountName = systemAccountName.(string)
	}

	if operator.SysAccountName == "" {
		operator.SysAccountName = DefaultSysAccountName
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
		operator.RawClaims = rawClaims
	}

	err = storeInStorage(ctx, req.Storage, operator.configPath(), operator)
	if err != nil {
		return nil, err
	}

	if newOperator {
		// create nkey
		nkey, err := NewOperatorNKey(id)
		if err != nil {
			return nil, err
		}
		err = storeInStorage(ctx, req.Storage, nkey.nkeyPath(), nkey)
		if err != nil {
			return nil, err
		}
	}

	systemAccountNameChanged := oldSystemAccountName != operator.SysAccountName
	managedStatusChanged := oldCreateSystemAccount != newCreateSystemAccount
	jwtDirty = jwtDirty || systemAccountNameChanged

	resp := &logical.Response{}

	// clean up previous system account
	if !newOperator && (systemAccountNameChanged || managedStatusChanged) {
		oldId := id.accountId(oldSystemAccountName)
		oldAcc, err := b.Account(ctx, req.Storage, oldId)
		if err != nil {
			return nil, err
		}
		if oldAcc != nil {
			if oldAcc.Status.IsManaged {
				err := b.deleteAccount(ctx, req.Storage, oldId)
				if err != nil {
					return nil, err
				}
			} else {
				b.Logger().Debug("refusing to delete non-managed system account", "operator", operator.op, "account", oldSystemAccountName)
				oldAcc.Status.IsSystemAccount = false
				err := storeInStorage(ctx, req.Storage, oldAcc.configPath(), oldAcc)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	// create new system account
	if newOperator || systemAccountNameChanged {
		if operator.CreateSystemAccount {
			accountId := id.accountId(operator.SysAccountName)
			account, err := b.Account(ctx, req.Storage, accountId)
			if err != nil {
				return nil, err
			}
			if account != nil {
				if !account.Status.IsManaged {
					return logical.ErrorResponse("managed system account name %s clashes with existing account", operator.SysAccountName), nil
				}
			} else {
				newAcc := NewAccountWithParams(accountId, DefaultSysAccountClaims)
				newAcc.Status.IsManaged = true
				newAcc.Status.IsSystemAccount = true
				err = storeInStorage(ctx, req.Storage, newAcc.configPath(), newAcc)
				if err != nil {
					return nil, err
				}
				warnings, err := b.createAccountNkeyAndJwt(ctx, req.Storage, newAcc.accountId)
				if err != nil {
					return nil, err
				}
				for _, v := range warnings {
					// don't emit warnings for the managed system account to the client as they aren't actionable
					b.Logger().Warn("warning creating account jwt", "operator", newAcc.op, "account", newAcc.acc, "warning", v)
				}
			}
		} else {
			accountId := id.accountId(operator.SysAccountName)
			account, err := b.Account(ctx, req.Storage, accountId)
			if err != nil {
				return nil, err
			}
			if account != nil {
				account.Status.IsSystemAccount = true
				err = storeInStorage(ctx, req.Storage, account.configPath(), account)
				if err != nil {
					return nil, err
				}
			} else {
				resp.AddWarning(fmt.Sprintf("system account %q does not exist and won't be reflected in the operator jwt", operator.SysAccountName))
			}
		}
	}

	if jwtDirty {
		if !newOperator {
			resp.AddWarning(fmt.Sprintf("this operation resulted in operator %q reissuing its jwt", id.op))
		}

		warnings, err := b.issueAndSaveOperatorJWT(ctx, req.Storage, operator.operatorId)
		if err != nil {
			return logical.ErrorResponse("failed to encode operator jwt: %s", err.Error()), nil
		}

		for _, v := range warnings {
			resp.AddWarning(fmt.Sprintf("while reissuing jwt for operator %q: %s", id.op, v))
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	// changes to which account is the system account should not be synced,
	// since the nkey is passed in the operator jwt and requires a configuration update on the nats server
	// Changes to the claims of the system account may be synced, however.

	return resp, nil
}

func (b *backend) pathOperatorRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	operator, err := b.Operator(ctx, req.Storage, OperatorIdField(d))
	if err != nil || operator == nil {
		return nil, err
	}

	data := map[string]any{
		"create_system_account": operator.CreateSystemAccount,
		"system_account_name":   operator.SysAccountName,
	}

	if operator.DefaultSigningKey != "" {
		data["default_signing_key"] = operator.DefaultSigningKey
	}

	if operator.RawClaims != nil {
		var claims map[string]any
		err := json.Unmarshal(operator.RawClaims, &claims)
		if err != nil {
			return nil, err
		}
		data["claims"] = claims
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathOperatorExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	operator, err := b.Operator(ctx, req.Storage, OperatorIdField(d))
	if err != nil {
		return false, err
	}

	return operator != nil, nil
}

func (b *backend) pathOperatorList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, operatorsPathPrefix, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathOperatorDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := OperatorIdField(d)

	operator, err := b.Operator(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if operator == nil {
		return nil, nil
	}

	err = req.Storage.Delete(ctx, id.configPath())
	if err != nil {
		return nil, err
	}

	// if managed, delete system account
	if operator.CreateSystemAccount {
		err = b.deleteAccount(ctx, req.Storage, id.accountId(operator.SysAccountName))
		if err != nil {
			return nil, err
		}
	}

	// delete operator sync
	err = req.Storage.Delete(ctx, id.accountServerPath())
	if err != nil {
		return nil, err
	}

	// delete operator nkey
	err = req.Storage.Delete(ctx, id.nkeyPath())
	if err != nil {
		return nil, err
	}

	// delete operator jwt
	err = req.Storage.Delete(ctx, id.jwtPath())
	if err != nil {
		return nil, err
	}

	// delete accounts
	for acc, err := range listPaged(ctx, req.Storage, id.accountsConfigPrefix(), DefaultPagingSize) {
		if err != nil {
			return nil, err
		}

		err := b.deleteAccount(ctx, req.Storage, id.accountId(acc))
		if err != nil {
			return nil, err
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	// we're not syncing anything because we're deleting the operator
	return nil, nil
}
