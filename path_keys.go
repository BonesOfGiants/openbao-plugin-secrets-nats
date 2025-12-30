package natsbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/shimtx"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nats-io/nkeys"
)

type userScope struct {
	// representing jwt.UserPermissionLimits
	Template    json.RawMessage `json:"template,omitempty"`
	Description string          `json:"description,omitempty"`
}

// NkeySorage represents a Nkey stored in the backend
type nkeyEntry struct {
	nkeyId

	Seed []byte `json:"seed,omitempty"`

	// only valid for account nkeys
	Scoped    bool      `json:"scoped"`
	UserScope userScope `json:"user_scope"`
}

func (n *nkeyEntry) keyPair() (nkeys.KeyPair, error) {
	keyPair, err := nkeys.FromSeed(n.Seed)
	if err != nil {
		return nil, err
	}

	return keyPair, nil
}

func (n *nkeyEntry) publicKey() (string, error) {
	keyPair, err := n.keyPair()
	if err != nil {
		return "", err
	}

	publicKey, err := keyPair.PublicKey()
	if err != nil {
		return "", err
	}

	return publicKey, nil
}

type operatorSigningKeyId struct {
	op   string
	name string
}

func OperatorSigningKeyId(op, name string) operatorSigningKeyId {
	return operatorSigningKeyId{
		op:   op,
		name: name,
	}
}

func OperatorSigningKeyIdField(d *framework.FieldData) operatorSigningKeyId {
	return operatorSigningKeyId{
		op:   d.Get("operator").(string),
		name: d.Get("name").(string),
	}
}

func (id operatorSigningKeyId) nkeyName() string {
	return id.name
}

func (id operatorSigningKeyId) operatorId() operatorId {
	return OperatorId(id.op)
}

func (id operatorSigningKeyId) nkeyPath() string {
	return operatorSigningKeysPathPrefix + id.op + "/" + id.name
}

func (id operatorSigningKeyId) configPath() string {
	return operatorSigningKeysPathPrefix + id.op + "/" + id.name
}

func (id operatorSigningKeyId) rotatePath() string {
	return rotateOperatorSigningKeyPathPrefix + id.op + "/" + id.name
}

type accountSigningKeyId struct {
	op   string
	acc  string
	name string
}

func AccountSigningKeyId(op, acc, name string) accountSigningKeyId {
	return accountSigningKeyId{
		op:   op,
		acc:  acc,
		name: name,
	}
}

func AccountSigningKeyIdField(d *framework.FieldData) accountSigningKeyId {
	return accountSigningKeyId{
		op:   d.Get("operator").(string),
		acc:  d.Get("account").(string),
		name: d.Get("name").(string),
	}
}

func (id accountSigningKeyId) operatorId() operatorId {
	return OperatorId(id.op)
}

func (id accountSigningKeyId) accountId() accountId {
	return AccountId(id.op, id.acc)
}

func (id accountSigningKeyId) nkeyName() string {
	return id.name
}

func (id accountSigningKeyId) nkeyPath() string {
	return accountSigningKeysPathPrefix + id.op + "/" + id.acc + "/" + id.name
}

func (id accountSigningKeyId) configPath() string {
	return accountSigningKeysPathPrefix + id.op + "/" + id.acc + "/" + id.name
}

func (id accountSigningKeyId) rotatePath() string {
	return rotateAccountSigningKeyPathPrefix + id.op + "/" + id.acc + "/" + id.name
}

type nkeyPather interface {
	nkeyPath() string
}

type nkeyId interface {
	nkeyPather
	nkeyName() string
}

func pathNkey(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: userKeysPathPrefix + operatorRegex + "/" + accountRegex + "/" + framework.GenericNameRegex("user") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"user":     userField,
			},
			ExistenceCheck: b.pathUserNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathUserNkeyRead,
				},
			},
			HelpSynopsis: `Read a user's identity key.`,
		},
		{
			Pattern: accountSigningKeysPathPrefix + operatorRegex + "/" + accountRegex + "/" + nameRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the signing key.",
					Required:    true,
				},
				"scoped": {
					Type:        framework.TypeBool,
					Description: "Specify whether this signing key should be scoped.",
				},
				"description": {
					Type:        framework.TypeString,
					Description: "A description for the signing key.",
				},
				"permission_template": {
					Type:        framework.TypeMap,
					Description: "Specify permissions that will apply to users issued under this key.",
				},
			},
			ExistenceCheck: b.pathAccountSigningNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAccountSigningNkeyCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAccountSigningNkeyCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathAccountSigningNkeyRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathAccountSigningNkeyDelete,
				},
			},
			HelpSynopsis: `Manage account signing keys.`,
		},
		{
			Pattern: accountKeysPathPrefix + operatorRegex + "/" + accountRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
			},
			ExistenceCheck: b.pathAccountNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathAccountNkeyRead,
				},
			},
			HelpSynopsis: `Read an account's identity key.`,
		},
		{
			Pattern: operatorSigningKeysPathPrefix + operatorRegex + "/" + nameRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the signing key.",
					Required:    true,
				},
			},
			ExistenceCheck: b.pathOperatorSigningNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathOperatorSigningNkeyCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathOperatorSigningNkeyCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathOperatorSigningNkeyRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathOperatorSigningNkeyDelete,
				},
			},
			HelpSynopsis: `Manage operator signing keys.`,
		},
		{
			Pattern: operatorKeysPathPrefix + operatorRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
			},
			ExistenceCheck: b.pathOperatorNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathOperatorNkeyRead,
				},
			},
			HelpSynopsis: `Read an operator's identity key.`,
		},
		{
			Pattern: operatorSigningKeysPathPrefix + operatorRegex + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"after":    afterField,
				"limit":    limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathOperatorSigningNkeyList,
				},
			},
			HelpSynopsis: "List all signing keys for an operator.",
		},
		{
			Pattern: accountSigningKeysPathPrefix + operatorRegex + "/" + accountRegex + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"after":    afterField,
				"limit":    limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathAccountSigningNkeyList,
				},
			},
			HelpSynopsis: "List account signing keys.",
		},
		{
			Pattern: userKeysPathPrefix + operatorRegex + "/" + accountRegex + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"after":    afterField,
				"limit":    limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathUserNkeyList,
				},
			},
			HelpSynopsis: "List all user keys for an account.",
		},
		{
			Pattern: accountKeysPathPrefix + operatorRegex + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"after":    afterField,
				"limit":    limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathAccountNkeyList,
				},
			},
			HelpSynopsis: "List all account keys.",
		},
		{
			Pattern: operatorKeysPathPrefix + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"after": afterField,
				"limit": limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathOperatorNkeyList,
				},
			},
			HelpSynopsis: "List all operator keys.",
		},
	}
}

func (b *backend) Nkey(ctx context.Context, s logical.Storage, id nkeyId) (*nkeyEntry, error) {
	nkey, err := getFromStorage[nkeyEntry](ctx, s, id.nkeyPath())
	if err != nil {
		return nil, err
	}
	if nkey != nil {
		nkey.nkeyId = id
	}

	return nkey, nil
}

// operator-key

func (b *backend) pathOperatorNkeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nkey, err := b.Nkey(ctx, req.Storage, OperatorIdField(d))
	if err != nil {
		return nil, err
	}
	if nkey == nil {
		return nil, nil
	}

	return createNkeyResponse(nkey)
}

func (b *backend) pathOperatorNkeyExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	nkey, err := b.Nkey(ctx, req.Storage, OperatorIdField(d))
	if err != nil {
		return false, err
	}

	return nkey != nil, nil
}

func (b *backend) pathOperatorNkeyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	after := d.Get("after").(string)
	limit := d.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, operatorKeysPathPrefix, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// operator-signing-key

func (b *backend) pathOperatorSigningNkeyCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := OperatorSigningKeyIdField(d)

	opDirty := false
	nkey, err := b.Nkey(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if nkey == nil {
		nkey, err = NewOperatorNKey(id)
		if err != nil {
			return nil, err
		}

		opDirty = true
	}

	err = storeInStorage(ctx, req.Storage, nkey.nkeyPath(), nkey)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	if opDirty {
		warnings, err := b.issueAndSaveOperatorJWT(ctx, req.Storage, id.operatorId())
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

	return nil, nil
}

func (b *backend) pathOperatorSigningNkeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nkey, err := b.Nkey(ctx, req.Storage, OperatorSigningKeyIdField(d))
	if err != nil {
		return nil, err
	}
	if nkey == nil {
		return nil, nil
	}

	return createNkeyResponse(nkey)
}

func (b *backend) pathOperatorSigningNkeyExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	nkey, err := b.Nkey(ctx, req.Storage, OperatorSigningKeyIdField(d))
	if err != nil {
		return false, err
	}

	return nkey != nil, nil
}

func (b *backend) pathOperatorSigningNkeyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := OperatorSigningKeyIdField(d)

	nkey, err := b.Nkey(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if nkey == nil {
		return nil, nil
	}

	err = deleteFromStorage(ctx, req.Storage, id.nkeyPath())
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	// reissue all accounts that used this nkey (they will reset to using the operator id key)
	updatedAccounts := []accountId{}
	for account, err := range b.listAccounts(ctx, req.Storage, id.operatorId()) {
		if err != nil {
			return nil, err
		}

		if account.SigningKeyName == id.name {
			warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, account.accountId)
			if err != nil {
				return nil, err
			}

			for _, v := range warnings {
				resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", account.acc, v))
			}

			updatedAccounts = append(updatedAccounts, account.accountId)
		}
	}

	warnings, err := b.issueAndSaveOperatorJWT(ctx, req.Storage, id.operatorId())
	if err != nil {
		return nil, err
	}

	for _, v := range warnings {
		resp.AddWarning(v)
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	if len(updatedAccounts) > 0 {
		accountSync, err := b.getAccountSync(ctx, req.Storage, id.operatorId())
		if err != nil {
			b.Logger().Warn("failed to retrieve account sync", "operator", id.op, "error", err)
			resp.AddWarning(fmt.Sprintf("unable to sync account jwts: %s", err))
		} else if accountSync != nil {
			for _, accId := range updatedAccounts {
				err := b.syncAccountUpdate(ctx, req.Storage, accountSync, accId)
				if err != nil {
					b.Logger().Warn("failed to sync account", "operator", accId.op, "account", accId.acc, "error", err)
					resp.AddWarning(fmt.Sprintf("unable to sync jwt for account %q: %s", accId.acc, err))
				}
			}
		}
	}

	return nil, nil
}

func (b *backend) pathOperatorSigningNkeyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	after := d.Get("after").(string)
	limit := d.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	id := OperatorIdField(d)

	entries, err := req.Storage.ListPage(ctx, id.signingKeyPrefix(), after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) listOperatorSigningKeys(
	ctx context.Context,
	storage logical.Storage,
	id operatorId,
) iter.Seq2[*nkeyEntry, error] {
	return func(yield func(*nkeyEntry, error) bool) {
		for p, err := range listPaged(ctx, storage, id.signingKeyPrefix(), DefaultPagingSize) {
			if err != nil {
				yield(nil, err)
				return
			}

			rev, err := b.Nkey(ctx, storage, id.signingKeyId(p))
			if err != nil {
				_ = yield(nil, err)
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

// account-key

func (b *backend) pathAccountNkeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nkey, err := b.Nkey(ctx, req.Storage, AccountIdField(d))
	if err != nil || nkey == nil {
		return nil, err
	}

	return createNkeyResponse(nkey)
}

func (b *backend) pathAccountNkeyExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	nkey, err := b.Nkey(ctx, req.Storage, AccountIdField(d))
	if err != nil {
		return false, err
	}

	return nkey != nil, err
}

func (b *backend) pathAccountNkeyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	after := d.Get("after").(string)
	limit := d.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, OperatorIdField(d).accountsNkeyPrefix(), after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// account-signing-key

func (b *backend) pathAccountSigningNkeyCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := AccountSigningKeyIdField(d)

	jwtDirty := false
	nkey, err := b.Nkey(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if nkey == nil {
		nkey, err = NewAccountNKey(id)
		if err != nil {
			return nil, err
		}

		jwtDirty = true
	}

	if scoped, ok := d.GetOk("scoped"); ok {
		jwtDirty = jwtDirty || (scoped != nkey.Scoped)
		nkey.Scoped = scoped.(bool)
	}

	if description, ok := d.GetOk("description"); ok {
		jwtDirty = jwtDirty || (nkey.Scoped && description != nkey.UserScope.Description)
		nkey.UserScope.Description = description.(string)
	}

	if template, ok := d.GetOk("permission_template"); ok {
		t, ok := template.(map[string]any)
		if !ok {
			return logical.ErrorResponse("permission_template must be a map, got %T", template), nil
		}
		if t != nil {
			rawTemplate, err := json.Marshal(template)
			if err != nil {
				return nil, err
			}
			jwtDirty = jwtDirty || (nkey.Scoped && bytes.Equal(rawTemplate, nkey.UserScope.Template))
			nkey.UserScope.Template = rawTemplate
		}
	}

	resp := &logical.Response{}

	err = storeInStorage(ctx, req.Storage, nkey.nkeyPath(), nkey)
	if err != nil {
		return nil, err
	}

	if jwtDirty {
		warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id.accountId())
		if err != nil {
			return nil, err
		}

		for _, v := range warnings {
			resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", id.acc, v))
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	if jwtDirty {
		accountSync, err := b.getAccountSync(ctx, req.Storage, id.operatorId())
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
	}

	return resp, nil
}

func (b *backend) pathAccountSigningNkeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nkey, err := b.Nkey(ctx, req.Storage, AccountSigningKeyIdField(d))
	if err != nil {
		return nil, err
	}
	if nkey == nil {
		return nil, nil
	}

	resp, err := createNkeyResponse(nkey)
	if err != nil {
		return nil, err
	}

	if nkey.Scoped {
		resp.Data["scoped"] = nkey.Scoped
		if nkey.UserScope.Template != nil {
			resp.Data["template"] = nkey.UserScope.Template
		}
		if nkey.UserScope.Description != "" {
			resp.Data["description"] = nkey.UserScope.Template
		}
	}

	return resp, nil
}

func (b *backend) pathAccountSigningNkeyExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	nkey, err := b.Nkey(ctx, req.Storage, AccountSigningKeyIdField(d))
	if err != nil {
		return false, err
	}

	return nkey != nil, nil
}

func (b *backend) pathAccountSigningNkeyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := AccountSigningKeyIdField(d)

	nkey, err := b.Nkey(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if nkey == nil {
		return nil, nil
	}

	err = deleteFromStorage(ctx, req.Storage, id.nkeyPath())
	if err != nil {
		return nil, err
	}

	// re-issue account jwt
	warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id.accountId())
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	for _, v := range warnings {
		resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", id.acc, v))
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *backend) pathAccountSigningNkeyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	after := d.Get("after").(string)
	limit := d.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	id := OperatorIdField(d)

	entries, err := req.Storage.ListPage(ctx, id.signingKeyPrefix(), after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) listAccountSigningKeys(
	ctx context.Context,
	storage logical.Storage,
	id accountId,
) iter.Seq2[*nkeyEntry, error] {
	return func(yield func(*nkeyEntry, error) bool) {
		for p, err := range listPaged(ctx, storage, id.signingKeyPrefix(), DefaultPagingSize) {
			if err != nil {
				yield(nil, err)
				return
			}

			rev, err := b.Nkey(ctx, storage, id.signingKeyId(p))
			if err != nil {
				_ = yield(nil, err)
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

// user-key

func (b *backend) pathUserNkeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nkey, err := b.Nkey(ctx, req.Storage, UserIdField(d))
	if err != nil || nkey == nil {
		return nil, err
	}

	keypair, err := nkeys.FromSeed(nkey.Seed)
	if err != nil {
		return nil, err
	}

	pub, err := keypair.PublicKey()
	if err != nil {
		return nil, err
	}

	private, err := keypair.PrivateKey()
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"public_key":  pub,
		"private_key": string(private),
		"seed":        string(nkey.Seed),
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathUserNkeyExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	nkey, err := b.Nkey(ctx, req.Storage, UserIdField(d))
	if err != nil {
		return false, err
	}

	return nkey != nil, nil
}

func (b *backend) pathUserNkeyList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, AccountIdField(data).userNkeyPrefix(), after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func createNkeyResponse(nkey *nkeyEntry) (*logical.Response, error) {
	keypair, err := nkey.keyPair()
	if err != nil {
		return nil, err
	}

	pub, err := keypair.PublicKey()
	if err != nil {
		return nil, err
	}

	private, err := keypair.PrivateKey()
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"public_key":  pub,
		"private_key": string(private),
		"seed":        string(nkey.Seed),
	}

	return &logical.Response{
		Data: data,
	}, nil
}

// createSeed creates a new Nkey seed
func createSeed(prefix nkeys.PrefixByte) ([]byte, error) {
	keypair, err := nkeys.CreatePair(prefix)
	if err != nil {
		return nil, err
	}

	return keypair.Seed()
}

func validateSeed(seed []byte, expected nkeys.PrefixByte) error {
	prefix, _, err := nkeys.DecodeSeed(seed)
	if err != nil {
		return err
	}

	if prefix != expected {
		return fmt.Errorf("wrong seed type")
	}

	return nil
}

func NewOperatorNKey(id nkeyId) (*nkeyEntry, error) {
	prefix := nkeys.PrefixByteOperator

	seed, err := createSeed(prefix)
	if err != nil {
		return nil, err
	}

	err = validateSeed(seed, prefix)
	if err != nil {
		return nil, err
	}

	return &nkeyEntry{
		nkeyId: id,
		Seed:   seed,
	}, nil
}

func NewOperatorNKeyWithSeed(id nkeyId, seed []byte) (*nkeyEntry, error) {
	prefix := nkeys.PrefixByteOperator

	err := validateSeed(seed, prefix)
	if err != nil {
		return nil, err
	}

	return &nkeyEntry{
		nkeyId: id,
		Seed:   seed,
	}, nil
}

func NewAccountNKey(id nkeyId) (*nkeyEntry, error) {
	prefix := nkeys.PrefixByteAccount

	seed, err := createSeed(prefix)
	if err != nil {
		return nil, err
	}

	err = validateSeed(seed, prefix)
	if err != nil {
		return nil, err
	}

	return &nkeyEntry{
		nkeyId: id,
		Seed:   seed,
	}, nil
}

func NewAccountNKeyWithSeed(id nkeyId, seed []byte) (*nkeyEntry, error) {
	prefix := nkeys.PrefixByteAccount

	err := validateSeed(seed, prefix)
	if err != nil {
		return nil, err
	}

	return &nkeyEntry{
		nkeyId: id,
		Seed:   seed,
	}, nil
}

func NewUserNKey(id nkeyId) (*nkeyEntry, error) {
	prefix := nkeys.PrefixByteUser

	seed, err := createSeed(prefix)
	if err != nil {
		return nil, err
	}

	err = validateSeed(seed, prefix)
	if err != nil {
		return nil, err
	}

	return &nkeyEntry{
		nkeyId: id,
		Seed:   seed,
	}, nil
}

func NewUserNKeyWithSeed(id nkeyId, seed []byte) (*nkeyEntry, error) {
	prefix := nkeys.PrefixByteUser

	err := validateSeed(seed, prefix)
	if err != nil {
		return nil, err
	}

	return &nkeyEntry{
		nkeyId: id,
		Seed:   seed,
	}, nil
}
