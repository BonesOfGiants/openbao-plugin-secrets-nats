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
	accountServersPathPrefix               = "account-servers/"
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

type operatorMap[T any] map[string]T
type nkeyToNameMap map[string]string

type backend struct {
	*framework.Backend

	// A cached storage instance used for account lookups.
	s logical.Storage

	NatsConnectionFunc NatsConnectionFunc

	accServerLock  sync.RWMutex
	accServerCache map[string]*accountserver.AccountServer

	accCacheLock       sync.RWMutex
	accNkeyToNameCache operatorMap[nkeyToNameMap]

	// accountUpdateQueue *queue.PriorityQueue
	// // queueCtx is the context for the account update queue
	// queueCtx context.Context
	// // cancelQueueCtx is used to terminate the background ticker
	// cancelQueueCtx context.CancelFunc

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
	b.accNkeyToNameCache = operatorMap[nkeyToNameMap]{}
	b.accServerCache = map[string]*accountserver.AccountServer{}
	// b.accountUpdateQueue = queue.New()
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
			pathConfigAccountServer(&b),
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
	cache, ok := b.accNkeyToNameCache[id.op]
	if !ok {
		cache = nkeyToNameMap{}
		b.accNkeyToNameCache[id.op] = cache
	}

	cache[key] = id.acc
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

func (b *backend) putAccountServer(name string, srv *accountserver.AccountServer) {
	b.accServerLock.Lock()
	defer b.accServerLock.Unlock()
	b.accServerCache[name] = srv
}

func (b *backend) popAccountServer(name string) *accountserver.AccountServer {
	b.accServerLock.Lock()
	defer b.accServerLock.Unlock()
	srv, ok := b.accServerCache[name]
	if ok {
		delete(b.accServerCache, name)
	}
	return srv
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

	for op, err := range listPaged(ctx, req.Storage, operatorsPathPrefix, DefaultPagingSize) {
		if err != nil {
			return err
		}

		id := OperatorId(op)

		if _, err := b.startAccountServer(ctx, id, false); err != nil {
			b.Logger().Warn("initialize: failed to start account server", "error", err)
		}
	}

	return nil
}

const backendHelp = `
A declarative interface for NATS JWT authentication/authorization in OpenBao.

The best place to get started is using the "nats/operators/" endpoint to create
a new operator.
`

func get(ctx context.Context, s logical.Storage, path string, d any) error {
	entry, err := s.Get(ctx, path)
	if err != nil {
		return err
	}
	if entry == nil {
		return nil
	}

	if err := entry.DecodeJSON(&d); err != nil {
		return err
	}

	return nil
}

type configPather interface {
	configPath() string
}

func storeInStorage(ctx context.Context, s logical.Storage, path string, t any) error {
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
	b.Logger().Trace("periodic: start")
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

		if _, err := b.startAccountServer(ctx, id, false); err != nil {
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
			err = storage.Delete(ctx, revocation.configPath())
			if err != nil {
				b.Logger().Debug("failed to prune account revocation", "operator", revocation.op, "account", revocation.acc, "revocation", revocation.sub, "error", err)
			} else {
				dirty = true
			}
		}
	}
	return dirty, nil
}

func (b *backend) createAuthCallback(opId operatorId) (nats.Option, error) {
	idKey, err := nkeys.CreateUser()
	if err != nil {
		return nil, fmt.Errorf("failed to create identity key: %w", err)
	}
	sub, err := idKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to decode identity key: %w", err)
	}

	return nats.UserJWT(
		func() (string, error) {
			operator, err := b.Operator(context.TODO(), b.s, opId)
			if err != nil {
				return "", fmt.Errorf("failed to read operator: %w", err)
			}
			if operator == nil {
				return "", fmt.Errorf("operator does not exist: %w", err)
			}

			accountServer, err := b.AccountServer(context.TODO(), b.s, opId)
			if err != nil {
				return "", fmt.Errorf("failed to read account server: %w", err)
			}
			if accountServer == nil {
				return "", fmt.Errorf("account server does not exist: %w", err)
			}

			claims := &jwt.UserClaims{
				ClaimsData: jwt.ClaimsData{
					Subject: sub,
					Expires: time.Now().Add(1 * time.Hour).Unix(),
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

			signingKey, enrichWarnings, err := b.enrichUserClaims(context.TODO(), b.s, enrichUserParams{
				op:     opId.op,
				acc:    operator.SysAccountName,
				user:   accountServer.AccountServerClientName,
				claims: claims,
			})
			if err != nil {
				return "", err
			}

			if len(enrichWarnings) > 0 {
				b.Logger().Debug("got warnings enriching user claims", "warnings", enrichWarnings)
			}

			result := encodeUserJWT(signingKey, claims, 1*time.Hour)
			if len(result.errors) > 0 {
				return "", fmt.Errorf("failed to encode user jwt: %w", result)
			}

			return result.jwt, nil
		},
		func(nonce []byte) ([]byte, error) {
			operator, err := b.Operator(context.TODO(), b.s, opId)
			if err != nil {
				return nil, fmt.Errorf("failed to read operator: %w", err)
			}
			if operator == nil {
				return nil, fmt.Errorf("operator does not exist: %w", err)
			}

			accountServer, err := b.AccountServer(context.TODO(), b.s, opId)
			if err != nil {
				return nil, fmt.Errorf("failed to read account server config: %w", err)
			}
			if accountServer == nil {
				return nil, fmt.Errorf("account server config does not exist: %w", err)
			}

			return idKey.Sign(nonce)
		},
	), nil
}

// startAccountServer creates an AccountServer for the given account server configuration
// or returns an existing connection. Pass true to reconnect if you want to
// ignore the cache and force a new connection.
func (b *backend) startAccountServer(ctx context.Context, id operatorId, reconnect bool) (*accountserver.AccountServer, error) {
	accountServer, err := b.AccountServer(ctx, b.s, id)
	if err != nil {
		return nil, err
	}
	if accountServer == nil {
		return nil, nil
	}
	if accountServer.Suspend {
		return nil, nil
	}

	b.accServerLock.RLock()
	srv := b.accServerCache[accountServer.op]
	b.accServerLock.RUnlock()

	var syncErr error

	if reconnect || srv == nil {
		authCb, err := b.createAuthCallback(id)
		if err != nil {
			syncErr = fmt.Errorf("failed to create auth callback: %w", err)
			goto update_status
		}

		nc, err := b.NatsConnectionFunc(
			accountServer.Servers,
			nats.Name(accountServer.AccountServerClientName),
			authCb,
			nats.Timeout(accountServer.ConnectTimeout),
			nats.ReconnectWait(accountServer.ReconnectWait),
			nats.MaxReconnects(accountServer.MaxReconnects),
			nats.DisconnectErrHandler(func(c *nats.Conn, err error) {
				b.Logger().Trace("account server: disconnected from nats", "url", c.ConnectedUrl(), "error", err)
				// invalidate cached conn

				// todo maybe with a backoff if repeated disconnects in a short time?
				b.startAccountServer(ctx, id, true)
			}),
			nats.ReconnectHandler(func(c *nats.Conn) {
				b.Logger().Trace("account server: reconnected to nats server", "url", c.ConnectedUrl())
			}),
			nats.ClosedHandler(func(c *nats.Conn) {
				b.Logger().Trace("account server: connection to nats server closed", "url", c.ConnectedUrl())
				// invalidate cached conn
				b.startAccountServer(ctx, id, true)
			}),
		)
		if err != nil {
			syncErr = fmt.Errorf("failed to create nats connection: %w", err)
		}

		newSrv, err := accountserver.NewAccountServer(
			accountserver.Config{
				Operator:            id.op,
				EnableAccountLookup: !accountServer.DisableAccountLookup,
			},
			b.accountJwtLookupFunc(id),
			b.Logger(),
			nc,
		)
		if err != nil {
			syncErr = fmt.Errorf("failed to create account server: %w", err)
		}

		b.putAccountServer(id.op, newSrv)

		if srv != nil {
			srv.CloseConnection()
		}

		srv = newSrv
	}

update_status:
	syncDirty := false
	if syncErr != nil {
		errString := syncErr.Error()
		if accountServer.Status.Error != errString {
			accountServer.Status.Error = errString
			syncDirty = true
		}
		if accountServer.Status.Status != AccountServerStatusError {
			accountServer.Status.Status = AccountServerStatusError
			accountServer.Status.LastStatusChange = time.Now()
			syncDirty = true
		}
	} else {
		if accountServer.Status.Status != AccountServerStatusActive {
			accountServer.Status.Status = AccountServerStatusActive
			accountServer.Status.LastStatusChange = time.Now()
			syncDirty = true
		}
	}

	if syncDirty {
		err = storeInStorage(ctx, b.s, id.accountServerPath(), accountServer)
		if err != nil {
			return nil, err
		}
	}

	return srv, nil
}

func (b *backend) periodicRefreshAccounts(ctx context.Context, s logical.Storage, opId operatorId) error {
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

			err = b.syncAccountUpdate(ctx, accId)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type syncErrors map[string]error

func (b *backend) syncOperatorAccounts(ctx context.Context, s logical.Storage, id operatorId) (syncErrors, error) {
	errors := syncErrors{}
	for acc, err := range listPaged(ctx, s, id.accountsConfigPrefix(), DefaultPagingSize) {
		if err != nil {
			return nil, err
		}

		err = b.syncAccountUpdate(ctx, id.accountId(acc))
		if err != nil {
			errors[acc] = err
		}
	}

	return errors, nil
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

	// restore the account on the endpoint
	err = b.syncAccountUpdate(ctx, id)
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
