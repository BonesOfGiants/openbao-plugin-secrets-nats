package natsbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

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

func (id operatorId) accountServerId() accountServerId {
	return AccountServerId(id.op)
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
			Pattern: operatorsPathPrefix + operatorRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"create_system_account": {
					Type:        framework.TypeBool,
					Description: "Whether to create a managed system account for this operator.",
					Default:     true,
				},
				"system_account_name": {
					Type:        framework.TypeString,
					Description: "The name of the account to use with this operator. If `create_system_account` is true, a managed account with this name will be created. If the named account already exists as a non-managed account, the request will fail. If `create_system_account` is false and the named account does not exist, this field is ignored and the operator JWT will not specify a system account.",
					Default:     DefaultSysAccountName,
					Required:    false,
				},
				"default_signing_key": {
					Type:        framework.TypeString,
					Description: "Specify which operator signing key to use by default when signing account JWTs. By setting this field, accounts under this operator will be unable to be signed using the operator identity key. If empty, not set, or if the specified signing key does not exist, accounts will be signed using the operator's identity key.",
					Required:    false,
				},
				"claims": {
					Type:        framework.TypeMap,
					Description: "Override default claims for the issued JWT for this operator. See https://pkg.go.dev/github.com/nats-io/jwt/v2#OperatorClaims for available fields. Claims are not merged; if the claims parameter is present it will overwrite any previous claims. Passing an explicit `null` to this field will clear the existing claims.",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathOperatorExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback:  b.pathOperatorCreateUpdate,
					Responses: responseOK,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback:  b.pathOperatorCreateUpdate,
					Responses: responseOK,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathOperatorRead,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"create_system_account": {
									Type:        framework.TypeBool,
									Description: "Whether a managed system account has been created for this operator.",
									Required:    true,
									Default:     true,
								},
								"system_account_name": {
									Type:        framework.TypeString,
									Description: "The name of the account designated as the system account for this operator.",
									Required:    true,
									Default:     DefaultSysAccountName,
								},
								"default_signing_key": {
									Type:        framework.TypeString,
									Description: "The default signing key used when signing account JWTs.",
									Required:    false,
								},
								"claims": {
									Type:        framework.TypeMap,
									Description: "Custom claims used in the JWT issued for this operator.",
									Required:    false,
								},
							},
						}},
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback:  b.pathOperatorDelete,
					Responses: responseNoContent,
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
		operator.CreateSystemAccount = createSystemAccount.(bool)
	}

	oldDefaultSigningKey := operator.DefaultSigningKey
	if defaultSigningKey, ok := d.GetOk("default_signing_key"); ok {
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
		if claims.(map[string]any) != nil {
			rawClaims, err := json.Marshal(claims)
			if err != nil {
				return nil, err
			}
			jwtDirty = jwtDirty || !bytes.Equal(rawClaims, operator.RawClaims)
			operator.RawClaims = rawClaims
		} else {
			jwtDirty = jwtDirty || operator.RawClaims != nil
			operator.RawClaims = nil
		}
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
	if newOperator || systemAccountNameChanged || managedStatusChanged {
		if operator.CreateSystemAccount {
			accountId := id.accountId(operator.SysAccountName)
			account, err := b.Account(ctx, req.Storage, accountId)
			if err != nil {
				return nil, err
			}
			if account != nil {
				if !account.Status.IsManaged {
					return logical.ErrorResponse("managed system account name %q clashes with existing account", operator.SysAccountName), nil
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
		warnings, err := b.issueAndSaveOperatorJWT(ctx, req.Storage, operator.operatorId)
		if err != nil {
			return logical.ErrorResponse("failed to encode operator jwt: %s", err.Error()), nil
		}

		for _, v := range warnings {
			resp.AddWarning(fmt.Sprintf("while reissuing jwt for operator %q: %s", id.op, v))
		}

		if !newOperator {
			resp.AddWarning(fmt.Sprintf("this operation resulted in operator %q reissuing its jwt", id.op))
			if err := b.suspendAccountServer(ctx, req.Storage, id.accountServerId()); err != nil {
				return nil, err
			}
		}
	}

	if operator.DefaultSigningKey != oldDefaultSigningKey {
		for account, err := range b.listAccounts(ctx, req.Storage, id) {
			if err != nil {
				return nil, err
			}

			// account is not using the default signing key
			if account.SigningKey != "" {
				continue
			}

			resp.AddWarning(fmt.Sprintf("reissued jwt for account %q as it is signed with the default key", account.acc))
			// reissue account jwt
			warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, account)
			if err != nil {
				return logical.ErrorResponse("failed to reissue account %q jwt: %s", account.acc, err.Error()), nil
			}

			for _, v := range warnings {
				resp.AddWarning(v)
			}
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

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
	err = req.Storage.Delete(ctx, id.accountServerId().configPath())
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
