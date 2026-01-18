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

func (a *accountEntry) Account(ctx context.Context, s logical.Storage) (*accountEntry, error) {
	return a, nil
}

func (a *accountEntry) AccountId() accountId {
	return a.accountId
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

func (id accountId) Account(ctx context.Context, s logical.Storage) (*accountEntry, error) {
	var account *accountEntry
	err := get(ctx, s, id.configPath(), &account)
	if account != nil {
		account.accountId = id
	}
	return account, err
}

func (id accountId) AccountId() accountId {
	return id
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
	Sync            *syncStatus `json:"sync"`
}

type syncStatus struct {
	Synced             bool      `json:"synced"`
	LastError          string    `json:"last_error,omitempty"`
	LastSuccessfulSync time.Time `json:"last_successful_sync"`
}

type AccountReader interface {
	AccountId() accountId
	Account(ctx context.Context, s logical.Storage) (*accountEntry, error)
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
	return id.Account(ctx, storage)
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
		operator, err := id.operatorId().Operator(ctx, req.Storage)
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
			return logical.ErrorResponse("failed to encode account jwt: %s", err.Error()), nil
		}

		for _, v := range warnings {
			resp.AddWarning(v)
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	if jwtDirty {
		err = b.syncAccountUpdate(ctx, id)
		if err != nil {
			resp.AddWarning(fmt.Sprintf("failed to push jwt update: %s", err))
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
		sync := map[string]any{
			"synced": account.Status.Sync.Synced,
		}

		if !account.Status.Sync.LastSuccessfulSync.IsZero() {
			sync["last_successful_sync"] = account.Status.Sync.LastSuccessfulSync.Unix()
		}

		if account.Status.Sync.LastError != "" {
			sync["last_error"] = account.Status.Sync.LastError
		}

		status["sync"] = sync
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

	err = b.syncAccountDelete(ctx, id)
	if err != nil {
		b.Logger().Warn("failed to sync account delete", "operator", id.op, "account", id.acc, "error", err)

		return nil, fmt.Errorf("failed to delete account in nats server: %w", err)
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
		err = storage.Delete(ctx, id.signingKeyId(keyId).nkeyPath())
		if err != nil {
			return err
		}
	}

	// delete imports
	for impId, err := range listPaged(ctx, storage, id.importPrefix(), DefaultPagingSize) {
		if err != nil {
			return err
		}
		err = storage.Delete(ctx, id.importId(impId).configPath())
		if err != nil {
			return err
		}
	}

	// delete revocations
	for impId, err := range listPaged(ctx, storage, id.revocationPrefix(), DefaultPagingSize) {
		if err != nil {
			return err
		}
		err = storage.Delete(ctx, id.revocationId(impId).configPath())
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

		err = storage.Delete(ctx, id.ephemeralUserId(user).configPath())
		if err != nil {
			return err
		}
	}

	// delete nkey
	err := storage.Delete(ctx, id.nkeyPath())
	if err != nil {
		return err
	}

	// delete jwt
	err = storage.Delete(ctx, id.jwtPath())
	if err != nil {
		return err
	}

	// delete config
	return storage.Delete(ctx, id.configPath())
}

// todo maybe instead of syncing immediately, we should debounce
// like adding to a queue, maybe?
func (b *backend) syncAccountUpdate(
	ctx context.Context,
	id accountId,
) error {
	var syncErr error = nil

	srv, err := b.startAccountServer(ctx, id.operatorId(), false)
	if err != nil {
		syncErr = err
	} else if srv == nil {
		return nil
	} else {
		// read account jwt
		jwt, err := b.Jwt(ctx, b.s, id)
		if err != nil {
			return err
		}
		if jwt == nil {
			syncErr = fmt.Errorf("unable to sync, account jwt does not exist")
			goto update_status
		}

		err = srv.UpdateAccount(jwt.Token)
		if err != nil {
			syncErr = fmt.Errorf("failed to send account update: %w", err)
			goto update_status
		}
	}

update_status:
	if syncErr != nil {
		// invalidate the cached sync
		srv = b.popAccountServer(id.op)
		if srv != nil {
			srv.CloseConnection()
		}
	}

	err = b.updateAccountSyncStatus(ctx, b.s, id, syncErr)
	if err != nil {
		return err
	}

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
			account.Status.Sync.LastSuccessfulSync = time.Now().UTC()
			account.Status.Sync.Synced = true
			account.Status.Sync.LastError = ""
		}

		err = storeInStorage(ctx, s, account.configPath(), account)
		if err != nil {
			return err
		}

		return nil
	})
}

func (b *backend) syncAccountDelete(
	ctx context.Context,
	id accountId,
) error {
	var syncErr error = nil

	srv, err := b.startAccountServer(ctx, id.operatorId(), false)
	if err != nil {
		syncErr = err
	} else if srv == nil {
		return nil
	} else {
		operatorNkey, err := b.Nkey(ctx, b.s, id.operatorId())
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
		accNkey, err := b.Nkey(ctx, b.s, id)
		if err != nil {
			return err
		} else if accNkey == nil {
			return fmt.Errorf("unable to sync, account nkey does not exist")
		}
		accountKeyPair, err := accNkey.keyPair()
		if err != nil {
			return err
		}

		err = srv.DeleteAccount(accountKeyPair, operatorKeyPair)
		if err != nil {
			syncErr = err
		}
	}

	if syncErr != nil {
		// we don't update the account sync status because we're deleting it!
		b.Logger().Warn("failed to sync account delete", "operator", id.op, "account", id.acc, "err", syncErr)
	}

	return nil
}

func (b *backend) syncAccountRotate(
	ctx context.Context,
	oldKeyPair nkeys.KeyPair,
	id accountId,
) error {
	var syncErr error = nil

	srv, err := b.startAccountServer(ctx, id.operatorId(), false)
	if err != nil {
		syncErr = err
	} else if srv == nil {
		return nil
	} else {
		// read account jwt
		jwt, err := b.Jwt(ctx, b.s, id)
		if err != nil {
			return err
		}
		if jwt == nil {
			syncErr = fmt.Errorf("unable to sync, account does not exist")
			goto update_status
		}

		err = srv.UpdateAccount(jwt.Token)
		if err != nil {
			syncErr = err
			goto update_status
		}

		operatorNkey, err := b.Nkey(ctx, b.s, id.operatorId())
		if err != nil {
			return err
		} else if operatorNkey == nil {
			syncErr = fmt.Errorf("unable to sync, operator nkey does not exist")
			goto update_status
		}

		operatorKeyPair, err := operatorNkey.keyPair()
		if err != nil {
			return err
		}

		err = srv.DeleteAccount(oldKeyPair, operatorKeyPair)
		if err != nil {
			syncErr = err
			goto update_status
		}
	}

update_status:
	err = b.updateAccountSyncStatus(ctx, b.s, id, syncErr)
	if err != nil {
		return err
	}

	return nil
}

func IsNatsUrl(url string) bool {
	url = strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(url, "nats://") || strings.HasPrefix(url, ",nats://")
}
