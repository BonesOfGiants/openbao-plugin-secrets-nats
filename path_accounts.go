package natsbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	accountsrv "github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/accountsync"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/shimtx"
)

const (
	deleteAccountWALKey = "deleteAccountWALKey"
)

type accountEntry struct {
	accountId

	RawClaims         json.RawMessage `json:"claims,omitempty"`
	SigningKey        string          `json:"signing_key"`
	DefaultSigningKey string          `json:"default_signing_key"`

	Status accountStatus `json:"status"`
}

// WAL entry used for the rollback account deletions
type deleteAccountWAL struct {
	Operator string
	Account  string
}

type accountId struct {
	op  string
	acc string
}

func AccountId(op, acc string) accountId {
	return accountId{
		op:  op,
		acc: acc,
	}
}

func AccountIdField(d *framework.FieldData) accountId {
	return accountId{
		op:  d.Get("operator").(string),
		acc: d.Get("account").(string),
	}
}

func (id accountId) nkeyName() string {
	return id.acc
}

func (id accountId) operatorId() operatorId {
	return OperatorId(id.op)
}

func (id accountId) userId(user string) userId {
	return UserId(id.op, id.acc, user)
}

func (id accountId) ephemeralUserId(user string) ephemeralUserId {
	return EphemeralUserId(id.op, id.acc, user)
}

func (id accountId) revocationId(sub string) accountRevocationId {
	return AccountRevocationId(id.op, id.acc, sub)
}

func (id accountId) importId(name string) accountImportId {
	return AccountImportId(id.op, id.acc, name)
}

func (id accountId) signingKeyId(name string) accountSigningKeyId {
	return AccountSigningKeyId(id.op, id.acc, name)
}

func (id accountId) configPath() string {
	return accountsPathPrefix + id.op + "/" + id.acc
}

func (id accountId) jwtPath() string {
	return accountJwtsPathPrefix + id.op + "/" + id.acc
}

func (id accountId) nkeyPath() string {
	return accountKeysPathPrefix + id.op + "/" + id.acc
}

func (id accountId) rotatePath() string {
	return rotateAccountPathPrefix + id.op + "/" + id.acc
}

func (id accountId) revocationPrefix() string {
	return revocationsPathPrefix + id.op + "/" + id.acc + "/"
}

func (id accountId) userNkeyPrefix() string {
	return userKeysPathPrefix + id.op + "/" + id.acc + "/"
}

func (id accountId) userConfigPrefix() string {
	return usersPathPrefix + id.op + "/" + id.acc + "/"
}

func (id accountId) ephemeralUserConfigPrefix() string {
	return ephemeralUsersPathPrefix + id.op + "/" + id.acc + "/"
}

func (id accountId) importPrefix() string {
	return accountImportsPathPrefix + id.op + "/" + id.acc + "/"
}

func (id accountId) signingKeyPrefix() string {
	return accountSigningKeysPathPrefix + id.op + "/" + id.acc + "/"
}

type accountStatus struct {
	IsSystemAccount bool        `json:"is_system_account"`
	IsManaged       bool        `json:"is_managed"`
	Sync            *syncStatus `json:"account_server"`
}

type syncStatus struct {
	Synced       bool      `json:"synced"`
	LastError    string    `json:"last_error,omitempty"`
	LastSyncTime time.Time `json:"last_sync_time"`
}

func pathConfigAccount(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: accountsPathPrefix + operatorRegex + "/" + accountRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"claims": {
					Type:        framework.TypeMap,
					Description: "Override default claims in the issued JWT for this account. See https://pkg.go.dev/github.com/nats-io/jwt/v2#AccountClaims for available fields.",
					Required:    false,
				},
				"signing_key": {
					Type:        framework.TypeString,
					Description: "Specify which operator signing key to use when generating this account's JWT. If not set, will use the operator's default signing key.",
				},
				"default_signing_key": {
					Type:        framework.TypeString,
					Description: "Specify which account signing key to use when signing user JWTs. If not set, will default to the account's identity key.",
				},
			},
			ExistenceCheck: b.pathAccountExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAccountCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAccountCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathAccountRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathAccountDelete,
				},
			},
			HelpSynopsis: `Manages accounts.`,
		},
		{
			Pattern: accountsPathPrefix + operatorRegex + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"after":    afterField,
				"limit":    limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathAccountList,
				},
			},
			HelpSynopsis: "List accounts.",
		},
	}
}

func (b *backend) Account(ctx context.Context, storage logical.Storage, id accountId) (*accountEntry, error) {
	account, err := getFromStorage[accountEntry](ctx, storage, id.configPath())
	if account != nil {
		account.accountId = id
	}
	return account, err
}

func (b *backend) accountExists(ctx context.Context, s logical.Storage, id accountId) (bool, error) {
	entry, err := s.Get(ctx, id.configPath())
	if err != nil {
		return false, err
	}
	if entry == nil {
		return false, nil
	}

	return true, nil
}

func NewAccount(id accountId) *accountEntry {
	return &accountEntry{
		accountId: id,
		Status: accountStatus{
			IsManaged: false,
			Sync:      nil,
		},
	}
}

func NewAccountWithParams(id accountId, claims json.RawMessage) *accountEntry {
	return &accountEntry{
		accountId: id,
		RawClaims: claims,
		Status: accountStatus{
			IsManaged: false,
			Sync:      nil,
		},
	}
}

func (b *backend) pathAccountCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := AccountIdField(d)

	opExists, err := b.operatorExists(ctx, req.Storage, id.operatorId())
	if err != nil {
		return nil, err
	}
	if !opExists {
		return logical.ErrorResponse("operator %q does not exist", id.op), nil
	}

	newAccount := false
	jwtDirty := false
	account, err := b.Account(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if account == nil {
		account = NewAccount(id)
		newAccount = true
		jwtDirty = true
	}

	if account.Status.IsManaged {
		return logical.ErrorResponse("cannot modify a managed system account"), nil
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
		jwtDirty = jwtDirty || !bytes.Equal(account.RawClaims, rawClaims)
		account.RawClaims = rawClaims
	}

	if signingKeyName, ok := d.GetOk("signing_key"); ok {
		jwtDirty = jwtDirty || (account.SigningKey != signingKeyName)
		account.SigningKey = signingKeyName.(string)
	}

	if defaultSigningKey, ok := d.GetOk("default_signing_key"); ok {
		jwtDirty = jwtDirty || (account.DefaultSigningKey != defaultSigningKey)
		account.DefaultSigningKey = defaultSigningKey.(string)
	}

	resp := &logical.Response{}

	if newAccount {
		// create nkey
		nkey, err := NewAccountNKey(account.accountId)
		if err != nil {
			return nil, err
		}
		storeInStorage(ctx, req.Storage, nkey.nkeyPath(), nkey)

		// are there any situations where we need to update the operator on update,
		// or only create?
		operator, err := b.Operator(ctx, req.Storage, id.operatorId())
		if err != nil {
			return nil, err
		}
		if operator != nil {
			if account.acc == operator.SysAccountName {
				account.Status.IsSystemAccount = true
				resp.AddWarning(fmt.Sprintf("this operation resulted in operator %q reissuing its jwt", id.op))

				warnings, err := b.issueAndSaveOperatorJWT(ctx, req.Storage, operator.operatorId)
				if err != nil {
					return nil, err
				}

				for _, v := range warnings {
					resp.AddWarning(fmt.Sprintf("while reissuing jwt for operator %q: %s", account.op, v))
				}
			}
		}
	}

	err = storeInStorage(ctx, req.Storage, id.configPath(), account)
	if err != nil {
		return nil, err
	}

	if jwtDirty {
		warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id)
		if err != nil {
			return nil, err
		}

		for _, v := range warnings {
			resp.AddWarning(v)
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	if jwtDirty {
		accountSync, err := b.getAccountSync(ctx, req.Storage, id.operatorId())
		if err != nil {
			b.Logger().Warn("failed to retrieve account sync", "operator", id.op, "account", id.acc, "error", err)
			resp.AddWarning(fmt.Sprintf("failed to sync jwt for account %q: %s", id.acc, err))
		} else if accountSync != nil {
			err := b.syncAccountUpdate(ctx, req.Storage, accountSync, id)
			if err != nil {
				b.Logger().Warn("failed to sync account", "operator", id.op, "account", id.acc, "error", err)
				resp.AddWarning(fmt.Sprintf("failed to sync jwt for account %q: %s", id.acc, err))
			}
		}
	}

	return resp, nil
}

func (b *backend) pathAccountRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := AccountIdField(d)

	account, err := b.Account(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, nil
	}

	status := map[string]any{
		"is_managed":        account.Status.IsManaged,
		"is_system_account": account.Status.IsSystemAccount,
	}

	if account.Status.Sync != nil {
		status["sync"] = map[string]any{
			"last_sync": account.Status.Sync.LastSyncTime,
			"synced":    account.Status.Sync.Synced,
		}
	}

	data := map[string]any{
		"status": status,
	}

	if account.SigningKey != "" {
		data["signing_key"] = account.SigningKey
	}

	if account.DefaultSigningKey != "" {
		data["default_signing_key"] = account.DefaultSigningKey
	}

	if account.RawClaims != nil {
		var claims map[string]any
		err := json.Unmarshal(account.RawClaims, &claims)
		if err != nil {
			return nil, err
		}
		data["claims"] = claims
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathAccountExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	id := AccountIdField(d)

	account, err := b.Account(ctx, req.Storage, id)
	if err != nil {
		return false, err
	}

	return account != nil, nil
}

func (b *backend) pathAccountList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, OperatorIdField(data).accountsConfigPrefix(), after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathAccountDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := AccountIdField(d)

	account, err := b.Account(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, nil
	}

	resp := &logical.Response{}

	if account.Status.IsManaged {
		return logical.ErrorResponse("cannot delete a managed system account"), nil
	}

	accountSync, err := b.getAccountSync(ctx, req.Storage, id.operatorId())
	if err != nil {
		return nil, err
	} else if accountSync != nil {
		if account.Status.IsSystemAccount {
			resp.AddWarning("the deletion of a system account will not be synced as it requires an update to the nats server configuration")
		} else {
			err := b.syncAccountDelete(ctx, req.Storage, accountSync, id)
			if err != nil {
				b.Logger().Warn("failed to sync account delete", "operator", id.op, "account", id.acc, "error", err)

				if accountSync.IgnoreSyncErrorsOnDelete {
					resp.AddWarning(fmt.Sprintf("failed to sync deletion to nats server: %s", err))
				} else {
					return nil, fmt.Errorf("failed to sync deletion for account %q: %w", id.acc, err)
				}
			}
		}
	}

	walID, err := framework.PutWAL(ctx, req.Storage, deleteAccountWALKey, &deleteAccountWAL{
		Operator: account.op,
		Account:  account.acc,
	})

	// reissue operator if this was the account specified as the system account
	if account.Status.IsSystemAccount {
		resp.AddWarning(fmt.Sprintf("this operation resulted in operator %q reissuing its jwt", id.op))

		warnings, err := b.issueAndSaveOperatorJWT(ctx, req.Storage, account.operatorId())
		if err != nil {
			return resp, err
		}

		for _, v := range warnings {
			resp.AddWarning(fmt.Sprintf("while reissuing jwt for operator %q: %s", id.op, v))
		}
	}

	err = b.deleteAccount(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}

	err = framework.DeleteWAL(ctx, req.Storage, walID)
	if err != nil {
		b.Logger().Warn("unable to delete WAL", "error", err, "WAL ID", walID)
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) createAccountNkeyAndJwt(ctx context.Context, s logical.Storage, id accountId) (jwtWarnings, error) {
	nkey, err := NewAccountNKey(id)
	if err != nil {
		return nil, err
	}
	err = storeInStorage(ctx, s, nkey.nkeyPath(), nkey)
	if err != nil {
		return nil, err
	}

	// create jwt
	warnings, err := b.issueAndSaveAccountJWT(ctx, s, id)
	if err != nil {
		return warnings, err
	}
	return warnings, nil
}

func (b *backend) listAccounts(
	ctx context.Context,
	storage logical.Storage,
	id operatorId,
) iter.Seq2[*accountEntry, error] {
	return func(yield func(*accountEntry, error) bool) {
		for p, err := range listPaged(ctx, storage, id.accountsConfigPrefix(), DefaultPagingSize) {
			if err != nil {
				yield(nil, err)
				return
			}

			account, err := b.Account(ctx, storage, id.accountId(p))
			if err != nil {
				_ = yield(nil, err)
				return
			}
			if account == nil {
				continue
			}
			if !yield(account, nil) {
				return
			}
		}
	}
}

// deleteAccount removes an account and all of its dependent objects from storage.
// It does not trigger any other side effects.
func (b *backend) deleteAccount(ctx context.Context, storage logical.Storage, id accountId) error {
	// delete signing keys
	for keyId, err := range listPaged(ctx, storage, id.signingKeyPrefix(), DefaultPagingSize) {
		if err != nil {
			return err
		}
		err = deleteFromStorage(ctx, storage, id.signingKeyId(keyId).nkeyPath())
		if err != nil {
			return err
		}
	}

	// delete imports
	for impId, err := range listPaged(ctx, storage, id.importPrefix(), DefaultPagingSize) {
		if err != nil {
			return err
		}
		err = deleteFromStorage(ctx, storage, id.importId(impId).configPath())
		if err != nil {
			return err
		}
	}

	// delete revocations
	for impId, err := range listPaged(ctx, storage, id.revocationPrefix(), DefaultPagingSize) {
		if err != nil {
			return err
		}
		err = deleteFromStorage(ctx, storage, id.revocationId(impId).configPath())
		if err != nil {
			return err
		}
	}

	// delete users
	for user, err := range listPaged(ctx, storage, id.userConfigPrefix(), DefaultPagingSize) {
		if err != nil {
			return err
		}
		_, err = b.deleteUser(ctx, storage, id.userId(user), false, 0)
		if err != nil {
			return err
		}
	}

	// delete ephemeral users
	for user, err := range listPaged(ctx, storage, id.ephemeralUserConfigPrefix(), DefaultPagingSize) {
		if err != nil {
			return err
		}

		err = deleteFromStorage(ctx, storage, id.ephemeralUserId(user).configPath())
		if err != nil {
			return err
		}
	}

	// delete nkey
	err := deleteFromStorage(ctx, storage, id.nkeyPath())
	if err != nil {
		return err
	}

	// delete jwt
	err = deleteFromStorage(ctx, storage, id.jwtPath())
	if err != nil {
		return err
	}

	// delete config
	return deleteFromStorage(ctx, storage, id.configPath())
}

// todo maybe instead of syncing immediately, we should debounce
// like adding to a queue, maybe?
func (b *backend) syncAccountUpdate(
	ctx context.Context,
	s logical.Storage,
	accountSync *accountsrv.AccountSync,
	id accountId,
) error {
	// read account jwt
	jwt, err := b.Jwt(ctx, s, id)
	if err != nil {
		return err
	} else if jwt == nil {
		return fmt.Errorf("unable to sync, account does not exist")
	}

	var syncErr error
	err = accountSync.UpdateAccount(jwt.Token)
	if err != nil {
		syncErr = err

		// invalidate the cached sync
		_ = b.popOperatorSync(id.op)
		accountSync.CloseConnection()
	}

	err = b.updateAccountSyncStatus(ctx, s, id, syncErr)
	if err != nil {
		return err
	}

	// return syncErr because we want to invalidate the accountsync instance
	return syncErr
}

func (b *backend) updateAccountSyncStatus(ctx context.Context, s logical.Storage, id accountId, syncErr error) error {
	return logical.WithTransaction(ctx, s, func(s logical.Storage) error {
		account, err := b.Account(ctx, s, id)
		if err != nil {
			return err
		}
		if account.Status.Sync == nil {
			account.Status.Sync = &syncStatus{}
		}

		if syncErr != nil {
			account.Status.Sync.Synced = false
			account.Status.Sync.LastError = syncErr.Error()
		} else {
			account.Status.Sync.Synced = true
			account.Status.Sync.LastError = ""
		}

		account.Status.Sync.LastSyncTime = time.Now().UTC()

		err = storeInStorage(ctx, s, account.configPath(), account)
		if err != nil {
			return err
		}

		return nil
	})
}

func (b *backend) syncAccountDelete(
	ctx context.Context,
	storage logical.Storage,
	accountSync *accountsrv.AccountSync,
	id accountId,
) error {
	operatorNkey, err := b.Nkey(ctx, storage, id.operatorId())
	if err != nil {
		return err
	} else if operatorNkey == nil {
		return fmt.Errorf("unable to sync, operator nkey does not exist")
	}

	operatorKeyPair, err := operatorNkey.keyPair()
	if err != nil {
		return err
	}

	// read account nkey
	accNkey, err := b.Nkey(ctx, storage, id)
	if err != nil {
		return err
	} else if accNkey == nil {
		return fmt.Errorf("unable to sync, account nkey does not exist")
	}
	accountKeyPair, err := accNkey.keyPair()
	if err != nil {
		return err
	}

	err = accountSync.DeleteAccount(accountKeyPair, operatorKeyPair)
	if err != nil {
		return err
	}

	return nil
}

func (b *backend) syncAccountRotate(
	ctx context.Context,
	storage logical.Storage,
	accountSync *accountsrv.AccountSync,
	oldKeyPair nkeys.KeyPair,
	id accountId,
) error {
	operatorNkey, err := b.Nkey(ctx, storage, id.operatorId())
	if err != nil {
		return err
	} else if operatorNkey == nil {
		return fmt.Errorf("unable to sync, operator nkey does not exist")
	}

	operatorKeyPair, err := operatorNkey.keyPair()
	if err != nil {
		return err
	}

	err = accountSync.DeleteAccount(oldKeyPair, operatorKeyPair)
	if err != nil {
		return err
	}

	err = b.syncAccountUpdate(ctx, storage, accountSync, id)
	if err != nil {
		return err
	}

	return nil
}

func IsNatsUrl(url string) bool {
	url = strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(url, "nats://") || strings.HasPrefix(url, ",nats://")
}
