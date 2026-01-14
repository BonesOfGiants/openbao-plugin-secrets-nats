package natsbackend

import (
	"context"
	"fmt"
	"iter"
	"strings"
	"sync"
	"time"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/accountserver"
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

type NatsConnectionFunc func(servers []string, o ...nats.Option) (abstractnats.NatsConnection, error)

type backend struct {
	*framework.Backend

	// A cached storage instance used for account lookups.
	s logical.Storage

	NatsConnectionFunc NatsConnectionFunc

	accServerLock  sync.RWMutex
	accServerCache map[string]*accountserver.AccountServer

	accCacheLock       sync.RWMutex
	accNkeyToNameCache map[string]map[string]string

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

	b.NatsConnectionFunc = abstractnats.NewNatsConnection
	b.accNkeyToNameCache = map[string]map[string]string{}
	b.accServerCache = map[string]*accountserver.AccountServer{}
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
		InitializeFunc:    b.initialize,
		BackendType:       logical.TypeLogical,
		WALRollback:       b.walRollback,
		WALRollbackMinAge: minRollbackAge,
		PeriodicFunc:      b.periodicFunc,
		Clean:             b.clean,
		RunningVersion:    PluginVersion,
	}
	return &b
}

func (b *backend) writeAccountToCache(id accountId, key string) {
	b.accCacheLock.Lock()
	defer b.accCacheLock.Unlock()
	opCache, ok := b.accNkeyToNameCache[id.op]
	if !ok {
		opCache = map[string]string{}
		b.accNkeyToNameCache[id.op] = opCache
	}

	opCache[key] = id.acc
}

func (b *backend) accountNameFromNkey(ctx context.Context, s logical.Storage, id operatorId, key string) (string, bool) {
	b.accCacheLock.RLock()
	opCache, ok := b.accNkeyToNameCache[id.op]
	if ok {
		acc, ok := opCache[key]
		if ok {
			return acc, true
		}
	}
	b.accCacheLock.RUnlock()

	err := b.refreshNkeyCache(ctx, s, id)
	if err != nil {
		return "", false
	}

	b.accCacheLock.RLock()
	opCache, ok = b.accNkeyToNameCache[id.op]
	if ok {
		acc, ok := opCache[key]
		if ok {
			return acc, true
		}
	}
	b.accCacheLock.RUnlock()

	return "", false
}

func (b *backend) refreshNkeyCache(ctx context.Context, s logical.Storage, id operatorId) error {
	for nkey, err := range b.listAccountIdentityKeys(ctx, s, id) {
		if err != nil {
			return err
		}

		key, err := nkey.publicKey()
		if err != nil {
			return err
		}

		b.writeAccountToCache(id.accountId(nkey.nkeyName()), key)
	}

	return nil
}

func (b *backend) accountJwtLookupFunc(id operatorId) accountserver.JwtLookupFunc {
	return func(key string) (string, error) {
		acc, ok := b.accountNameFromNkey(context.TODO(), b.s, id, key)
		if !ok {
			return "", nil
		}

		jwt, err := b.Jwt(context.TODO(), b.s, id.accountId(acc))
		if err != nil {
			return "", err
		}

		return jwt.Token, nil
	}
}

func (b *backend) putAccountServer(name string, sync *accountserver.AccountServer) {
	b.accServerLock.Lock()
	defer b.accServerLock.Unlock()
	b.accServerCache[name] = sync
}

func (b *backend) popAccountServer(name string) *accountserver.AccountServer {
	b.accServerLock.Lock()
	defer b.accServerLock.Unlock()
	sync, ok := b.accServerCache[name]
	if ok {
		delete(b.accServerCache, name)
	}
	return sync
}

func (b *backend) clearAccountServers() map[string]*accountserver.AccountServer {
	b.accServerLock.Lock()
	defer b.accServerLock.Unlock()
	old := b.accServerCache
	b.accServerCache = make(map[string]*accountserver.AccountServer)
	return old
}

func (b *backend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	b.s = req.Storage
	return nil
}

const backendHelp = `
A declarative interface for NATS JWT authentication/authorization in OpenBao.

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

type configPather interface {
	configPath() string
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
	b.Logger().Trace("starting periodic refresh")
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return err
	}
	defer txRollback()

	for op, err := range listPaged(ctx, req.Storage, operatorsPathPrefix, DefaultPagingSize) {
		if err != nil {
			return err
		}

		id := OperatorId(op)

		// ensure account server is live for applicable operators
		if _, err := b.getAccountServer(ctx, req.Storage, id); err != nil {
			b.Logger().Warn("periodic: failed to ensure account server", "error", err)
		}

		if err = b.periodicRefreshAccounts(ctx, req.Storage, id); err != nil {
			b.Logger().Warn("periodic: failed to refresh accounts", "error", err)
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

func (b *backend) getAccountServer(ctx context.Context, storage logical.Storage, id operatorId) (*accountserver.AccountServer, error) {
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

	b.accServerLock.RLock()
	srv := b.accServerCache[id.op]
	b.accServerLock.RUnlock()

	if srv == nil {
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

		claims := &jwt.UserClaims{
			ClaimsData: jwt.ClaimsData{
				Subject: sub,
			},
			User: jwt.User{
				UserPermissionLimits: jwt.UserPermissionLimits{
					Permissions: jwt.Permissions{
						Pub: jwt.Permission{
							Allow: jwt.StringList{
								accountserver.SysClaimsUpdateSubject,
								accountserver.SysClaimsDeleteSubject,
								"_INBOX.*",
							},
						},
						Sub: jwt.Permission{
							Allow: jwt.StringList{
								accountserver.SysAccountClaimsLookupSubject,
								"_INBOX.*",
							},
						},
					},
					Limits: jwt.Limits{
						NatsLimits: jwt.NatsLimits{
							Subs:    -1,
							Payload: -1,
							Data:    -1,
						},
					},
				},
			},
		}

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

		nc, err := b.NatsConnectionFunc(
			syncConfig.Servers,
			nats.Name("openbao_account_server"),
			nats.UserJWTAndSeed(result.jwt, string(seed)),
			nats.Timeout(syncConfig.ConnectTimeout),
			nats.ReconnectWait(syncConfig.ReconnectWait),
			nats.MaxReconnects(syncConfig.MaxReconnects),
			nats.DisconnectErrHandler(func(c *nats.Conn, err error) {
				b.Logger().Debug("sync: disconnected from nats", "url", c.ConnectedUrl(), "error", err)
				// invalidate cached conn
				sync := b.popAccountServer(id.op)
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
				sync := b.popAccountServer(id.op)
				if sync != nil {
					sync.CloseConnection()
				}
			}),
		)
		if err != nil {
			return nil, err
		}

		srv, err = accountserver.NewAccountServer(
			accountserver.Config{
				Operator:                 id.op,
				IgnoreSyncErrorsOnDelete: syncConfig.IgnoreSyncErrorsOnDelete,
			},
			b.accountJwtLookupFunc(id),
			b.Logger(),
			nc,
		)

		if err != nil {
			return nil, err
		}
		b.putAccountServer(id.op, srv)
	}

	return srv, nil
}

func (b *backend) periodicRefreshAccounts(ctx context.Context, s logical.Storage, opId operatorId) error {
	var accountSync *accountserver.AccountServer

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
				accountSync, err = b.getAccountServer(ctx, s, opId)
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
	srv, err := b.getAccountServer(ctx, s, id)
	if err != nil {
		return nil, err
	} else if srv == nil {
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
		if srv == nil {
			srv, err = b.getAccountServer(ctx, s, id)
			if err != nil {
				return nil, err
			} else if srv == nil {
				b.Logger().Debug("sync not configured", "operator", id.op)
				return nil, nil
			}
		}

		err = b.syncAccountUpdate(ctx, s, srv, id.accountId(acc))
		if err != nil {
			errors[acc] = err
			srv = nil
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
	cache := b.clearAccountServers()

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

	accountsrv, err := b.getAccountServer(ctx, req.Storage, id.operatorId())
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

func sprintErrors(errors []error) string {
	errs := []string{}
	for _, v := range errors {
		errs = append(errs, v.Error())
	}

	return strings.Join(errs, "; ")
}
