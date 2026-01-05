package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"sync"
	"time"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/accountsync"
	"github.com/go-viper/mapstructure/v2"
	"github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	operatorsPathPrefix                    = "operators/"
	syncConfigPathPrefix                   = "sync-config/"
	operatorKeysPathPrefix                 = "operator-keys/"
	operatorSigningKeysPathPrefix          = "operator-signing-keys/"
	operatorJwtsPathPrefix                 = "operator-jwts/"
	operatorGenerateServerConfigPathPrefix = "generate-server-config/"

	accountsPathPrefix           = "accounts/"
	accountImportsPathPrefix     = "account-imports/"
	accountKeysPathPrefix        = "account-keys/"
	accountSigningKeysPathPrefix = "account-signing-keys/"
	accountJwtsPathPrefix        = "account-jwts/"

	revocationsPathPrefix = "revocations/"

	usersPathPrefix    = "users/"
	userKeysPathPrefix = "user-keys/"
	credsPathPrefix    = "creds/"

	ephemeralUsersPathPrefix = "ephemeral-users/"
	ephemeralCredsPathPrefix = "ephemeral-creds/"

	rotateOperatorPathPrefix           = "rotate-operator/"
	rotateAccountPathPrefix            = "rotate-account/"
	rotateOperatorSigningKeyPathPrefix = "rotate-operator-signing-key/"
	rotateAccountSigningKeyPathPrefix  = "rotate-account-signing-key/"
	rotateUserPathPrefix               = "rotate-user/"

	userCredsType = "user_creds"

	minRollbackAge    = 1 * time.Minute
	DefaultPagingSize = 100
)

type configPather interface {
	configPath() string
}

var (
	operatorField = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Name of the operator.",
		Required:    true,
	}
	accountField = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Name of the account.",
		Required:    true,
	}
	userField = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Name of the user.",
		Required:    true,
	}
	afterField = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Optional entry to list begin listing after, not required to exist.",
		Required:    false,
	}
	limitField = &framework.FieldSchema{
		Type:        framework.TypeInt,
		Description: "Optional number of entries to return; defaults to all entries.",
		Required:    false,
	}

	operatorRegex = framework.GenericNameRegex("operator")
	accountRegex  = framework.GenericNameRegex("account")
	nameRegex     = framework.GenericNameRegex("name")
	userRegex     = framework.GenericNameRegex("user")
	sessionRegex  = framework.GenericNameRegex("session")
	subRegex      = framework.GenericNameRegex("sub")

	// PluginVersion is set at build time via -ldflags
	PluginVersion string
)

type SyncConnectionFunc func(servers []string, o ...nats.Option) (abstractnats.NatsConnection, error)

type backend struct {
	*framework.Backend

	NewSyncConnection SyncConnectionFunc

	operatorSyncLock  sync.RWMutex
	operatorSyncCache map[string]*accountsync.AccountSync

	// todo metrics? (see pki/database)
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	var b = backend{}

	b.NewSyncConnection = accountsync.NewNatsConnection
	b.operatorSyncCache = map[string]*accountsync.AccountSync{}
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"operator-keys/",
			},
		},
		Paths: framework.PathAppend(
			pathUserCreds(&b),
			pathEphemeralUserCreds(&b),
			pathJWT(&b),
			pathNkey(&b),
			pathConfigOperator(&b),
			pathConfigAccount(&b),
			pathConfigUser(&b),
			pathConfigEphemeralUser(&b),
			pathConfigOperatorSync(&b),
			pathConfigAccountImport(&b),
			pathConfigAccountRevocation(&b),
			pathRotate(&b),
			pathUtilities(&b),
		),
		Secrets: []*framework.Secret{
			b.userCredsSecretType(),
		},
		BackendType:       logical.TypeLogical,
		WALRollback:       b.walRollback,
		WALRollbackMinAge: minRollbackAge,
		PeriodicFunc:      b.periodicFunc,
		Clean:             b.clean,
		RunningVersion:    PluginVersion,
	}
	return &b
}

func (b *backend) getOperatorSync(name string) *accountsync.AccountSync {
	b.operatorSyncLock.RLock()
	defer b.operatorSyncLock.RUnlock()
	return b.operatorSyncCache[name]
}

func (b *backend) putOperatorSync(name string, sync *accountsync.AccountSync) {
	b.operatorSyncLock.Lock()
	defer b.operatorSyncLock.Unlock()
	b.operatorSyncCache[name] = sync
}

func (b *backend) popOperatorSync(name string) *accountsync.AccountSync {
	b.operatorSyncLock.Lock()
	defer b.operatorSyncLock.Unlock()
	sync, ok := b.operatorSyncCache[name]
	if ok {
		delete(b.operatorSyncCache, name)
	}
	return sync
}

func (b *backend) clearOperatorSync() map[string]*accountsync.AccountSync {
	b.operatorSyncLock.Lock()
	defer b.operatorSyncLock.Unlock()
	old := b.operatorSyncCache
	b.operatorSyncCache = make(map[string]*accountsync.AccountSync)
	return old
}

const backendHelp = `
A fully-managed interface for NATS JWT authentication/authorization in OpenBao.

The best place to get started is using the "nats/operators/" endpoint to create
a new operator.
`

func getFromStorage[T any](ctx context.Context, s logical.Storage, path string) (*T, error) {
	if path == "" {
		return nil, fmt.Errorf("missing path")
	}

	// get data entry from storage backend
	entry, err := s.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("error retrieving data: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	// convert json data to T
	var t T
	if err := entry.DecodeJSON(&t); err != nil {
		return nil, fmt.Errorf("error decoding data: %w", err)
	}
	return &t, nil
}

func deleteFromStorage(ctx context.Context, s logical.Storage, path string) error {
	if err := s.Delete(ctx, path); err != nil {
		return err
	}
	return nil
}

func storeInStorage[T any](ctx context.Context, s logical.Storage, path string, t *T) error {
	entry, err := logical.StorageEntryJSON(path, t)
	if err != nil {
		return err
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func listPaged(
	ctx context.Context,
	storage logical.Storage,
	path string,
	pageSize int,
) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		after := ""

		for {
			paths, err := storage.ListPage(ctx, path, after, pageSize)
			if err != nil {
				yield("", err)
				return
			}

			if len(paths) == 0 {
				return
			}

			for _, p := range paths {
				if !yield(p, nil) {
					return
				}
			}

			after = paths[len(paths)-1]
		}
	}
}

func (b *backend) periodicFunc(ctx context.Context, req *logical.Request) error {
	b.Logger().Trace("Periodic: starting periodic func for syncing accounts to nats")
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return err
	}
	defer txRollback()

	for op, err := range listPaged(ctx, req.Storage, operatorsPathPrefix, DefaultPagingSize) {
		if err != nil {
			return err
		}

		if err = b.periodicRefreshAccounts(ctx, req.Storage, OperatorId(op)); err != nil {
			b.Logger().Warn("periodic refresh failed", "error", err)
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return err
	}

	return nil
}

func (b *backend) periodicPruneAccountRevocations(ctx context.Context, storage logical.Storage, id accountId) (bool, error) {
	now := time.Now()
	dirty := false

	for revocation, err := range b.listAccountRevocations(ctx, storage, id) {
		if err != nil {
			return false, err
		}

		if revocation.Ttl == 0 {
			continue
		}

		if revocation.CreationTime.Add(revocation.Ttl).Before(now) {
			err = deleteFromStorage(ctx, storage, revocation.configPath())
			if err != nil {
				b.Logger().Debug("failed to prune account revocation", "operator", revocation.op, "account", revocation.acc, "revocation", revocation.sub, "error", err)
			} else {
				dirty = true
			}
		}
	}
	return dirty, nil
}

func (b *backend) getAccountSync(ctx context.Context, storage logical.Storage, id operatorId) (*accountsync.AccountSync, error) {
	syncConfig, err := b.OperatorSync(ctx, storage, id)
	if err != nil {
		return nil, err
	}
	if syncConfig == nil {
		return nil, nil
	}
	if syncConfig.Suspend {
		return nil, nil
	}

	sync := b.getOperatorSync(id.op)

	if sync == nil {
		idKey, err := nkeys.CreateUser()
		if err != nil {
			return nil, fmt.Errorf("failed to create user identity key: %w", err)
		}
		sub, err := idKey.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to decode identity key: %w", err)
		}
		seed, err := idKey.Seed()
		if err != nil {
			return nil, fmt.Errorf("failed to decode identity key: %w", err)
		}

		operator, err := b.Operator(ctx, storage, id)
		if err != nil {
			return nil, fmt.Errorf("failed to read operator: %w", err)
		}
		if operator == nil {
			return nil, fmt.Errorf("operator does not exist: %w", err)
		}

		claims, err := copyClaims(&DefaultSyncUserClaims)
		if err != nil {
			return nil, fmt.Errorf("failed to copy system user claims: %w", err)
		}

		claims.Subject = sub

		signingKey, enrichWarnings, err := b.enrichUserClaims(ctx, storage, enrichUserParams{
			op:     id.op,
			acc:    operator.SysAccountName,
			user:   syncConfig.SyncUserName,
			claims: claims,
		})
		if err != nil {
			return nil, err
		}

		if len(enrichWarnings) > 0 {
			b.Logger().Debug("got warnings enriching user claims", "warnings", enrichWarnings)
		}

		result := encodeUserJWT(signingKey, claims, 1*time.Hour)
		if len(result.errors) > 0 {
			return nil, fmt.Errorf("failed to encode user jwt: %w", result)
		}

		nc, err := b.NewSyncConnection(
			syncConfig.Servers,
			nats.Name("openbao_account_sync"),
			nats.UserJWTAndSeed(result.jwt, string(seed)),
			nats.Timeout(syncConfig.ConnectTimeout),
			nats.ReconnectWait(syncConfig.ReconnectWait),
			nats.MaxReconnects(syncConfig.MaxReconnects),
			nats.DisconnectErrHandler(func(c *nats.Conn, err error) {
				b.Logger().Debug("sync: disconnected from nats", "url", c.ConnectedUrl(), "error", err)
				// invalidate cached conn
				sync := b.popOperatorSync(id.op)
				if sync != nil {
					sync.CloseConnection()
				}
			}),
			nats.ReconnectHandler(func(c *nats.Conn) {
				b.Logger().Debug("sync: reconnected to nats server", "url", c.ConnectedUrl())
			}),
			nats.ClosedHandler(func(c *nats.Conn) {
				b.Logger().Debug("sync: connection to nats server closed", "url", c.ConnectedUrl())
				// invalidate cached conn
				sync := b.popOperatorSync(id.op)
				if sync != nil {
					sync.CloseConnection()
				}
			}),
		)
		if err != nil {
			return nil, err
		}

		sync, err = accountsync.NewAccountSync(
			accountsync.Config{
				IgnoreSyncErrorsOnDelete: syncConfig.IgnoreSyncErrorsOnDelete,
			},
			b.Logger(),
			nc,
		)
		if err != nil {
			return nil, err
		}
		b.putOperatorSync(id.op, sync)
	}

	return sync, nil
}

func (b *backend) periodicRefreshAccounts(ctx context.Context, s logical.Storage, opId operatorId) error {
	var accountSync *accountsync.AccountSync

	for name, err := range listPaged(ctx, s, opId.accountsConfigPrefix(), DefaultPagingSize) {
		if err != nil {
			return err
		}

		accId := opId.accountId(name)

		b.Logger().Debug("refreshing account", "operator", accId.op, "account", accId.acc)

		accDirty, err := b.periodicPruneAccountRevocations(ctx, s, accId)
		if err != nil {
			b.Logger().Warn("failed to prune account revocations", "operator", accId.op, "account", accId.acc, "error", err)
		}

		if accDirty {
			_, err := b.issueAndSaveAccountJWT(ctx, s, accId)
			if err != nil {
				b.Logger().Warn("failed to reissue account jwt", "operator", accId.op, "account", accId.acc, "error", err)
				err = b.updateAccountSyncStatus(ctx, s, accId, err)
				if err != nil {
					return err
				}
				continue
			}

			if accountSync == nil {
				accountSync, err = b.getAccountSync(ctx, s, opId)
				if err != nil {
					b.Logger().Warn("failed to create account sync", "operator", opId.op, "error", err)
				}
			}

			if accountSync != nil {
				b.Logger().Debug("syncing account", "operator", accId.op, "account", accId.acc)
				if err = b.syncAccountUpdate(ctx, s, accountSync, accId); err != nil {
					b.Logger().Warn("account sync error", "operator", accId.op, "account", accId.acc, "error", err)

					// force the next account to refresh the accountSync
					accountSync = nil
				}
			}
		}
	}
	return nil
}

type syncErrors map[string]error

func (b *backend) syncOperatorAccounts(ctx context.Context, s logical.Storage, id operatorId) (syncErrors, error) {
	accountSync, err := b.getAccountSync(ctx, s, id)
	if err != nil {
		return nil, err
	} else if accountSync == nil {
		b.Logger().Debug("sync not configured", "operator", id.op)
		return nil, nil
	}

	startTime := time.Now()

	errors := syncErrors{}
	for acc, err := range listPaged(ctx, s, id.accountsConfigPrefix(), DefaultPagingSize) {
		if err != nil {
			return nil, err
		}

		// todo improve cache invalidation handling
		if accountSync == nil {
			accountSync, err := b.getAccountSync(ctx, s, id)
			if err != nil {
				return nil, err
			} else if accountSync == nil {
				b.Logger().Debug("sync not configured", "operator", id.op)
				return nil, nil
			}
		}

		err = b.syncAccountUpdate(ctx, s, accountSync, id.accountId(acc))
		if err != nil {
			errors[acc] = err
			accountSync = nil
		}
	}

	// update status
	err = logical.WithTransaction(ctx, s, func(s logical.Storage) error {
		syncConfig, err := b.OperatorSync(ctx, s, id)
		if err != nil {
			return err
		}
		if syncConfig == nil {
			b.Logger().Warn("sync config unexpectedly null", "operator", id.op)
			return nil
		}

		if len(errors) > 0 {
			syncConfig.Status.Status = OperatorSyncStatusError
			syncConfig.Status.Errors = make([]string, 0, len(errors))
			for k, v := range errors {
				syncConfig.Status.Errors = append(syncConfig.Status.Errors, fmt.Sprintf("account %q failed to sync: %s", k, v))
			}
		} else {
			syncConfig.Status.Status = OperatorSyncStatusActive
			syncConfig.Status.Errors = nil
			syncConfig.Status.LastSyncTime = startTime
		}
		storeInStorage(ctx, s, id.syncConfigPath(), syncConfig)

		return nil
	})

	return errors, err
}

func (b *backend) clean(_ context.Context) {
	cache := b.clearOperatorSync()

	for _, v := range cache {
		v.CloseConnection()
	}
}

func (b *backend) walRollback(ctx context.Context, req *logical.Request, kind string, data any) error {
	if kind != deleteAccountWALKey {
		return fmt.Errorf("unknown type of rollback %q", kind)
	}

	var rollbackData deleteAccountWAL
	if err := mapstructure.Decode(data, &rollbackData); err != nil {
		return err
	}

	id := AccountId(rollbackData.Operator, rollbackData.Account)

	account, err := b.Account(ctx, req.Storage, id)
	if err != nil {
		return err
	}
	if account == nil {
		// the account was deleted successfully, nothing to do here
		return nil
	}

	accountsrv, err := b.getAccountSync(ctx, req.Storage, id.operatorId())
	if err != nil {
		return err
	}
	if accountsrv == nil {
		// no sync config
		return nil
	}

	// restore the account on the endpoint
	err = b.syncAccountUpdate(ctx, req.Storage, accountsrv, id)
	if err != nil {
		return err
	}

	return nil
}

// Converts operator claims into json.RawMessage.
// If the conversion fails, panic.
func fromOperatorClaims(claims *jwt.OperatorClaims) json.RawMessage {
	data, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}

	return data
}

// Converts account claims into json.RawMessage.
// If the conversion fails, panic.
func fromAccountClaims(claims *jwt.AccountClaims) json.RawMessage {
	data, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}

	return data
}

// Converts user claims into json.RawMessage.
// If the conversion fails, panic.
func fromUserClaims(claims *jwt.UserClaims) json.RawMessage {
	data, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}

	return data
}

// copyClaims marshals claims to json and back to
// perform a deep copy.
func copyClaims[T jwt.Claims](claims T) (T, error) {
	str := claims.String()

	var r T
	err := json.Unmarshal([]byte(str), &r)
	if err != nil {
		return r, err
	}

	return r, nil
}
