package natsbackend

import (
	"context"
	"fmt"
	"iter"
	"time"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/shimtx"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type accountRevocationEntry struct {
	accountRevocationId

	CreationTime time.Time     `json:"creation_time"`
	Ttl          time.Duration `json:"ttl,omitempty"`
}

type accountRevocationId struct {
	op  string
	acc string
	sub string
}

func AccountRevocationId(op, acc, sub string) accountRevocationId {
	return accountRevocationId{
		op:  op,
		acc: acc,
		sub: sub,
	}
}

func AccountRevocationIdField(d *framework.FieldData) accountRevocationId {
	return accountRevocationId{
		op:  d.Get("operator").(string),
		acc: d.Get("account").(string),
		sub: d.Get("sub").(string),
	}
}

func (id accountRevocationId) operatorId() operatorId {
	return OperatorId(id.op)
}

func (id accountRevocationId) accountId() accountId {
	return AccountId(id.op, id.acc)
}

func (id accountRevocationId) configPath() string {
	return revocationsPathPrefix + id.op + "/" + id.acc + "/" + id.sub
}

func pathConfigAccountRevocation(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: revocationsPathPrefix + operatorRegex + "/" + accountRegex + "/" + subRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"sub": {
					Type:        framework.TypeString,
					Description: "The subject id.",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The duration of the revocation. Defaults to the ",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathAccountRevocationExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAccountRevocationCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAccountRevocationCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathAccountRevocationRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathAccountRevocationDelete,
				},
			},
			HelpSynopsis:    `Manages externally defined revocations for accounts.`,
			HelpDescription: `Create and manage revocations that will be appended to account claims when generating account jwts.`,
		},
		{
			Pattern: revocationsPathPrefix + operatorRegex + "/" + accountRegex + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"after":    afterField,
				"limit":    limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathAccountRevocationList,
				},
			},
			HelpSynopsis: "List account revocations.",
		},
	}
}

func (b *backend) AccountRevocation(ctx context.Context, storage logical.Storage, id accountRevocationId) (*accountRevocationEntry, error) {
	rev, err := getFromStorage[accountRevocationEntry](ctx, storage, id.configPath())
	if rev != nil {
		rev.accountRevocationId = id
	}
	return rev, err
}

func NewAccountRevocation(id accountRevocationId) *accountRevocationEntry {
	return &accountRevocationEntry{
		accountRevocationId: id,
	}
}

func NewAccountRevocationWithParams(id accountRevocationId, creationTime time.Time, ttl time.Duration) *accountRevocationEntry {
	return &accountRevocationEntry{
		accountRevocationId: id,
		CreationTime:        creationTime,
		Ttl:                 ttl,
	}
}

func (b *backend) pathAccountRevocationCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := AccountRevocationIdField(d)

	rev, err := b.AccountRevocation(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if rev == nil {
		rev = NewAccountRevocation(id)
	}

	account, err := b.Account(ctx, req.Storage, id.accountId())
	if err != nil {
		return nil, err
	}
	if account == nil {
		return logical.ErrorResponse("account %q does not exist under operator %q", id.acc, id.op), nil
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		rev.Ttl = time.Duration(ttlRaw.(int)) * time.Second
	}

	// always update the creation time
	rev.CreationTime = time.Now()

	err = storeInStorage(ctx, req.Storage, rev.configPath(), rev)
	if err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	// always update the jwt
	warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id.accountId())
	if err != nil {
		return nil, fmt.Errorf("failed to encode account jwt: %w", err)
	}

	for _, v := range warnings {
		resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", id.acc, v))
	}

	accountSync, err := b.getAccountServer(ctx, req.Storage, id.operatorId())
	if err != nil {
		b.Logger().Warn("failed to retrieve account sync", "operator", id.op, "account", id.acc, "error", err)
		resp.AddWarning(fmt.Sprintf("unable to sync jwt for account %q: %s", id.acc, err))
	} else if accountSync != nil {
		err := b.syncAccountUpdate(ctx, req.Storage, accountSync, id.accountId())
		if err != nil {
			b.Logger().Warn("failed to sync account", "operator", id.op, "account", id.acc, "error", err)
			resp.AddWarning(fmt.Sprintf("unable to sync jwt for account %q: %s", id.acc, err))
		}
	}

	return resp, nil
}

func (b *backend) pathAccountRevocationRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rev, err := b.AccountRevocation(ctx, req.Storage, AccountRevocationIdField(d))
	if err != nil || rev == nil {
		return nil, err
	}

	data := map[string]any{
		"ttl":           int(rev.Ttl.Seconds()),
		"creation_time": rev.CreationTime,
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathAccountRevocationExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	rev, err := b.AccountRevocation(ctx, req.Storage, AccountRevocationIdField(d))
	if err != nil {
		return false, err
	}

	return rev != nil, nil
}

func (b *backend) pathAccountRevocationList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	after := d.Get("after").(string)
	limit := d.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, AccountIdField(d).revocationPrefix(), after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathAccountRevocationDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := AccountRevocationIdField(d)

	rev, err := b.AccountRevocation(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if rev == nil {
		return nil, nil
	}

	err = deleteFromStorage(ctx, req.Storage, id.configPath())
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	// reissue account jwt
	warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id.accountId())
	if err != nil {
		return nil, err
	}

	for _, v := range warnings {
		resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", id.acc, v))
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	accountSync, err := b.getAccountServer(ctx, req.Storage, id.operatorId())
	if err != nil {
		b.Logger().Warn("failed to retrieve account sync", "operator", id.op, "account", id.acc, "error", err)
		resp.AddWarning(fmt.Sprintf("unable to sync jwt for account %q: %s", id.acc, err))
	} else if accountSync != nil {
		err := b.syncAccountUpdate(ctx, req.Storage, accountSync, id.accountId())
		if err != nil {
			b.Logger().Warn("failed to sync account", "operator", id.op, "account", id.acc, "error", err)
			resp.AddWarning(fmt.Sprintf("unable to sync jwt for account %q: %s", id.acc, err))
		}
	}

	return resp, nil
}

func (b *backend) listAccountRevocations(
	ctx context.Context,
	storage logical.Storage,
	id accountId,
) iter.Seq2[*accountRevocationEntry, error] {
	return func(yield func(*accountRevocationEntry, error) bool) {
		for p, err := range listPaged(ctx, storage, id.revocationPrefix(), DefaultPagingSize) {
			if err != nil {
				yield(nil, err)
				return
			}

			rev, err := b.AccountRevocation(ctx, storage, id.revocationId(p))
			if err != nil {
				yield(nil, err)
				return
			}
			if rev == nil {
				continue
			}
			if !yield(rev, nil) {
				return
			}
		}
	}
}

func (b *backend) addUserToRevocationList(ctx context.Context, storage logical.Storage, accId accountId, userId userId, ttl time.Duration) error {
	// get user public key
	userNkey, err := b.Nkey(ctx, storage, userId)
	if err != nil {
		return err
	}
	if userNkey == nil {
		return nil
	}

	publicKey, err := userNkey.publicKey()
	if err != nil {
		return err
	}
	id := accId.revocationId(publicKey)

	if ttl == 0 {
		ttl = b.System().MaxLeaseTTL()
	}

	rev := NewAccountRevocationWithParams(id, time.Now(), ttl)

	err = storeInStorage(ctx, storage, rev.configPath(), rev)
	if err != nil {
		return err
	}

	return nil
}
