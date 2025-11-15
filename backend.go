package natsbackend

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type NatsClient struct {
	*nats.Conn
}

// natsBackend defines an object that
// extends the OpenBao backend and stores the
// target API's client.
type NatsBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *NatsClient
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
)

// backend defines the target API backend
// for OpenBao. It must include each path
// and the secrets it will store.
func backend() *NatsBackend {
	var b = NatsBackend{}

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
		Secrets:           []*framework.Secret{},
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

func (b *NatsBackend) periodicFunc(ctx context.Context, sys *logical.Request) error {
	b.Logger().Info("Periodic: starting periodic func for syncing accounts to nats")
	operators, err := sys.Storage.List(ctx, issueOperatorPrefix) // todo paginate
	if err != nil {
		return err
	}
	for _, operator := range operators {
		operatorIssue, err := readOperatorIssue(ctx, sys.Storage, IssueOperatorParameters{
			Operator: operator,
		})
		if err != nil {
			return err
		}
		if operatorIssue != nil {
			b.Logger().Debug(fmt.Sprintf("Periodic: operator %s selected for auto sync to account server", operator))

			if err = b.periodicRefreshAccountIssues(ctx, sys.Storage, operatorIssue); err != nil {
				b.Logger().Warn(err.Error())
			}
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

	now := time.Now().Unix()

	dirty := false
	for _, issue := range issues {
		if issue.ExpirationS == 0 {
			continue
		}

		if (issue.CreationTime + issue.ExpirationS) < now {
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

	for _, issueName := range issuesList {
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

func (b *NatsBackend) periodicRefreshAccountIssues(ctx context.Context, storage logical.Storage, operator *IssueOperatorStorage) error {
	opName := operator.Operator
	sync := operator.SyncAccountServer

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

		if sync {
			b.Logger().Debug(fmt.Sprintf("Periodic: account %s in operator %s syncing to acount server", accName, opName))
			if err != nil {
				b.Logger().Info(err.Error())
			}
			if err = refreshAccountResolverPush(ctx, storage, account); err != nil {
				return err
			}
			_, err = storeAccountIssueUpdate(ctx, storage, account)
			if err != nil {
				return err
			}
		} else {
			b.Logger().Debug(fmt.Sprintf("Periodic: operator %s not configured for auto syncing to account server. Skipping.", opName))
			continue
		}
	}
	return nil
}
