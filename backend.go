package natsbackend

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/accountsync"
	lru "github.com/hashicorp/golang-lru/v2"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/rs/zerolog/log"
)

type NatsClient struct {
	*nats.Conn
}

// natsBackend defines an object that
// extends the OpenBao backend and stores the
// target API's client.
type NatsBackend struct {
	*framework.Backend
	lock                 sync.RWMutex
	client               *NatsClient
	accountNameToIdCache *lru.Cache[string, string]
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

const (
	issueOperatorPrefix = "issue/operator/"
	jwtOperatorPrefix   = "jwt/operator/"
	nkeyOperatorPrefix  = "nkey/operator/"
	userCredsType       = "user_creds"
)

// backend defines the target API backend
// for OpenBao. It must include each path
// and the secrets it will store.
func backend() *NatsBackend {
	var b = NatsBackend{}

	cache, err := lru.New[string, string](50)

	if err != nil {
		panic(fmt.Errorf("error creating cache: %w", err))
	}

	b.accountNameToIdCache = cache
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			pathNkey(&b),
			pathJWT(&b),
			pathIssue(&b),
			pathCreds(&b),
			[]*framework.Path{},
		),
		Secrets: []*framework.Secret{
			b.userCredsSecretType(),
		},
		BackendType:       logical.TypeLogical,
		Invalidate:        b.invalidate,
		WALRollbackMinAge: 30 * time.Second,
		PeriodicFunc:      b.periodicFunc,
	}
	return &b
}

// backendHelp should contain help information for the backend
const backendHelp = `
The NATS secrets backend provides an API to create, manage, and sync
NATS operator, account, and user NKeys and JWTs.
`

// reset clears any client configuration for a new
// backend to be configured
func (b *NatsBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *NatsBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

func (b *NatsBackend) writeAccountToCache(accountName, accountId string) {
	b.accountNameToIdCache.Add(accountId, accountName)
}

func (b *NatsBackend) getAccountFromCache(ctx context.Context, s logical.Storage, accountId string) (string, bool) {
	accName, exists := b.accountNameToIdCache.Get(accountId)
	if !exists {
		err := b.refreshAccountCache(ctx, s)
		if err != nil {
			return "", false
		}

		accName, exists = b.accountNameToIdCache.Get(accountId)
		return accName, exists
	}

	return accName, true
}

func getFromStorage[T any](ctx context.Context, s logical.Storage, path string) (*T, error) {
	if path == "" {
		return nil, fmt.Errorf("missing path")
	}

	// get data entry from storage backend
	entry, err := s.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("error retrieving Data: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	// convert json data to T
	var t T
	if err := entry.DecodeJSON(&t); err != nil {
		return nil, fmt.Errorf("error decoding JWT data: %w", err)
	}
	return &t, nil
}

func filterSubkeys(a []string) []string {
	var filtered []string
	for _, v := range a {
		if !strings.HasSuffix(v, "/") {
			filtered = append(filtered, v)
		}
	}

	return filtered
}

func deleteFromStorage(ctx context.Context, s logical.Storage, path string) error {
	if err := s.Delete(ctx, path); err != nil {
		return fmt.Errorf("error deleting data: %w", err)
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

func (b *NatsBackend) refreshAccountCache(ctx context.Context, s logical.Storage) error {
	b.Logger().Info("refreshing account id cache")
	operators, err := s.List(ctx, issueOperatorPrefix) // todo paginate
	if err != nil {
		return err
	}
	for _, op := range filterSubkeys(operators) {
		path := getAccountIssuePath(op, "")
		accounts, err := s.List(ctx, path)
		if err != nil {
			return err
		}

		for _, acc := range filterSubkeys(accounts) {
			accNkey, err := readAccountNkey(ctx, s, NkeyParameters{
				Operator: op,
				Account:  acc,
			})
			if err != nil {
				return err
			}
			if accNkey == nil {
				b.Logger().Warn("unable to get account nkey for account %s", acc)
				continue
			}

			accId, err := toNkeyData(accNkey)
			if err != nil {
				return err
			}

			b.writeAccountToCache(acc, accId.PublicKey)
		}
	}

	return nil
}

func (b *NatsBackend) periodicFunc(ctx context.Context, sys *logical.Request) error {
	b.Logger().Info("Periodic: starting periodic func for syncing accounts to nats")
	operators, err := sys.Storage.List(ctx, issueOperatorPrefix) // todo paginate
	if err != nil {
		return err
	}
	for _, operator := range filterSubkeys(operators) {
		operatorIssue, err := readOperatorIssue(ctx, sys.Storage, IssueOperatorParameters{
			Operator: operator,
		})
		if err != nil {
			return err
		}
		if operatorIssue == nil {
			b.Logger().Warn("unable to get operator issue %s", operator)
			continue
		}

		if err = b.periodicRefreshAccountIssues(ctx, sys.Storage, operatorIssue); err != nil {
			b.Logger().Warn(err.Error())
		}
	}
	return nil
}

func (b *NatsBackend) periodicRefreshAccountRevocations(ctx context.Context, storage logical.Storage, operator string, account string) (bool, error) {
	issues, err := readAllAccountRevocationIssues(ctx, storage, IssueAccountRevocationParameters{
		Operator: operator,
		Account:  account,
	})
	if err != nil {
		return false, err
	}
	if len(issues) == 0 {
		return false, nil
	}

	now := time.Now().Unix()
	dirty := false

	for _, issue := range issues {
		if issue.ExpirationS == 0 {
			continue
		}

		if (issue.CreationTime + int64(issue.ExpirationS)) < now {
			err = deleteAccountRevocationIssue(ctx, storage, IssueAccountRevocationParameters{
				Operator: issue.Operator,
				Account:  issue.Account,
				Subject:  issue.Subject,
			}, false)
			if err != nil {
				return false, err
			}

			dirty = true
		}
	}
	return dirty, nil
}

func (b *NatsBackend) periodicRefreshUserIssues(ctx context.Context, storage logical.Storage, operator string, account string) error {
	path := getUserIssuePath(operator, account, "")
	issuesList, err := storage.List(ctx, path) // todo paginate
	if err != nil {
		return err
	}

	for _, issueName := range filterSubkeys(issuesList) {
		issue, err := readUserIssue(ctx, storage, IssueUserParameters{
			Operator: operator,
			Account:  account,
			User:     issueName,
		})
		if err != nil {
			return err
		}

		nkeyMissing := false
		// No need to check if user jwt exists as we generate them on demand

		nkey, err := readUserNkey(ctx, storage, NkeyParameters{
			Operator: operator,
			Account:  account,
			User:     issueName,
		})
		if err != nil {
			return err
		}
		if !issue.Status.User.Nkey || nkey == nil {
			nkeyMissing = true
		}

		if nkeyMissing {
			if err := refreshUser(ctx, storage, issue); err != nil {
				return err
			}
		}
	}
	return nil
}

func createSyncAuthCallback(ctx context.Context, storage logical.Storage, op string) nats.Option {
	return nats.UserJWT(
		func() (string, error) {
			issue, err := readUserIssue(ctx, storage, IssueUserParameters{
				Operator: op,
				Account:  DefaultSysAccountName,
				User:     DefaultPushUser,
			})
			if err != nil {
				return "", fmt.Errorf("failed to read system user: %w", err)
			}

			userNkey, err := readUserNkey(ctx, storage, NkeyParameters{
				Operator: op,
				Account:  DefaultSysAccountName,
				User:     DefaultPushUser,
			})
			if err != nil {
				return "", fmt.Errorf("failed to read system user nkey: %w", err)
			}

			nkey, err := nkeys.FromSeed(userNkey.Seed)
			if err != nil {
				return "", fmt.Errorf("failed to decode system user nkey: %w", err)
			}

			result, err := generateUserJWT(ctx, storage, &userJwtParams{
				operator:   op,
				account:    DefaultSysAccountName,
				user:       DefaultPushUser,
				parameters: nil,
				claims:     &issue.ClaimsTemplate,
				nkey:       nkey,
			})
			if err != nil {
				return "", fmt.Errorf("failed to generate user jwt: %w", err)
			}

			return result.jwt, nil
		},
		func(nonce []byte) ([]byte, error) {
			userNkey, err := readUserNkey(ctx, storage, NkeyParameters{
				Operator: op,
				Account:  DefaultSysAccountName,
				User:     DefaultPushUser,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to read system user nkey: %w", err)
			}

			nkey, err := nkeys.FromSeed(userNkey.Seed)
			if err != nil {
				return nil, fmt.Errorf("failed to decode system user nkey: %w", err)
			}

			return nkey.Sign(nonce)
		},
	)
}

func getAccountSync(ctx context.Context, storage logical.Storage, op string) (*accountsync.AccountSync, error) {
	path := operatorSyncPath(op)
	syncConfig, err := getFromStorage[operatorSyncConfigEntry](ctx, storage, path)
	if err != nil {
		return nil, err
	}
	if syncConfig == nil {
		return nil, nil
	}

	return accountsync.NewAccountSync(
		accountsync.Config{
			Servers:                  syncConfig.Servers,
			ConnectTimeout:           syncConfig.ConnectTimeout,
			ReconnectWait:            syncConfig.ReconnectWait,
			MaxReconnects:            syncConfig.MaxReconnects,
			IgnoreSyncErrorsOnDelete: syncConfig.IgnoreSyncErrorsOnDelete,
		},
		nats.Name("openbao_account_sync"),
		createSyncAuthCallback(ctx, storage, op),
		nats.Timeout(time.Duration(syncConfig.ConnectTimeout)*time.Second),
		nats.ReconnectWait(time.Duration(syncConfig.ReconnectWait)*time.Second),
		nats.MaxReconnects(syncConfig.MaxReconnects),
		nats.DisconnectErrHandler(func(c *nats.Conn, err error) {
			if err != nil {
				log.Error().Msgf("Disconnected: error: %v\n", err)
			}
			if c.Status() == nats.CLOSED {
				return
			}
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info().Msgf("Reconnected [%s]", c.ConnectedUrl())
		}),
		nats.ClosedHandler(func(c *nats.Conn) {
			log.Info().Msgf("Exiting, no servers available, or connection closed")
		}),
	)
}

func (b *NatsBackend) periodicRefreshAccountIssues(ctx context.Context, storage logical.Storage, operator *IssueOperatorStorage) error {
	opName := operator.Operator

	accountSync, err := getAccountSync(ctx, storage, opName)
	if err != nil {
		b.Logger().Warn(fmt.Sprintf("Error creating account sync: %v", err))
	}
	defer accountSync.CloseConnection()

	path := getAccountIssuePath(operator.Operator, "")
	issuesList, err := storage.List(ctx, path)
	if err != nil {
		return err
	}
	for _, accName := range filterSubkeys(issuesList) {
		b.Logger().Info("Refreshing account " + accName)
		account, err := readAccountIssue(ctx, storage, IssueAccountParameters{
			Operator: opName,
			Account:  accName,
		})
		if err != nil {
			return err
		}
		if account == nil {
			b.Logger().Warn("Skipping nil account " + accName)
			continue
		}

		accountDirty := false

		accountDirty, err = b.periodicRefreshAccountRevocations(ctx, storage, opName, accName)
		if err != nil {
			b.Logger().Warn(err.Error())
		}

		if !accountDirty {
			jwt, err := readAccountJWT(ctx, storage, JWTParameters{
				Operator: opName,
				Account:  accName,
			})
			if err != nil {
				return err
			}
			if !account.Status.Account.JWT || jwt == nil {
				accountDirty = true
			}
		}

		if !accountDirty {
			nkey, err := readAccountNkey(ctx, storage, NkeyParameters{
				Operator: opName,
				Account:  accName,
			})
			if err != nil {
				return err
			}
			if !account.Status.Account.Nkey || nkey == nil {
				accountDirty = true
			}
		}

		if accountDirty {
			if err := refreshAccount(ctx, storage, account); err != nil {
				return err
			}
		}

		if err = b.periodicRefreshUserIssues(ctx, storage, opName, accName); err != nil {
			b.Logger().Warn(err.Error())
		}

		if accountSync != nil {
			b.Logger().Debug(fmt.Sprintf("Periodic: account %s in operator %s syncing to acount server", accName, opName))
			if err != nil {
				b.Logger().Info(err.Error())
			}
			if err = syncAccountUpdate(ctx, storage, accountSync, account); err != nil {
				return err
			}
			_, err = storeAccountIssueUpdate(ctx, storage, account)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
