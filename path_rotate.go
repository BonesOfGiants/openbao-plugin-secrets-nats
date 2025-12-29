package natsbackend

import (
	"context"
	"fmt"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/shimtx"
	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type rotatePather interface {
	rotatePath() string
}

func pathRotate(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: rotateAccountPathPrefix + operatorRegex + "/" + accountRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
			},
			ExistenceCheck: b.pathAccountExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRotateAccount,
				},
			},
			HelpSynopsis: `Rotates an account identity key.`,
		},
		{
			Pattern: rotateAccountSigningKeyPathPrefix + operatorRegex + "/" + accountRegex + "/" + nameRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the signing key.",
					Required:    true,
				},
			},
			ExistenceCheck: b.pathAccountSigningNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRotateAccountSigningKey,
				},
			},
			HelpSynopsis: `Rotates an account signing key.`,
		},
		{
			Pattern: rotateOperatorPathPrefix + operatorRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
			},
			ExistenceCheck: b.pathAccountSigningNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRotateOperator,
				},
			},
			HelpSynopsis: `Rotates an operator identity key. Also suspends the sync config.`,
		},
		{
			Pattern: rotateOperatorSigningKeyPathPrefix + operatorRegex + "/" + nameRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the signing key.",
					Required:    true,
				},
			},
			ExistenceCheck: b.pathAccountSigningNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRotateOperatorSigningKey,
				},
			},
			HelpSynopsis: `Rotates an operator signing key.`,
		},
		{
			Pattern: rotateUserPathPrefix + operatorRegex + "/" + accountRegex + "/" + userRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"user":     userField,
				"revoke": {
					Type:        framework.TypeBool,
					Description: "Whether to revoke the old identity key.",
					Default:     false,
				},
			},
			ExistenceCheck: b.pathUserNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathUserKeyRotate,
				},
			},
			HelpSynopsis: `Rotates a user identity key.`,
		},
	}
}

func (b *backend) pathRotateOperator(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := OperatorIdField(d)

	// read the old nkey
	oldNkey, err := b.Nkey(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if oldNkey == nil {
		return logical.ErrorResponse("operator %q does not exist", id.op), nil
	}
	oldPublicKey, err := oldNkey.publicKey()
	if err != nil {
		return nil, err
	}

	// write a new nkey
	nkey, err := NewOperatorNKey(id)
	err = storeInStorage(ctx, req.Storage, nkey.nkeyPath(), nkey)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	warnings, err := b.issueAndSaveOperatorJWT(ctx, req.Storage, id)
	if err != nil {
		return nil, fmt.Errorf("failed to encode operator jwt: %w", err)
	}

	for _, v := range warnings {
		resp.AddWarning(fmt.Sprintf("while reissuing jwt for operator %q: %s", id.op, v))
	}

	for acc, err := range listPaged(ctx, req.Storage, id.accountsJwtPrefix(), DefaultPagingSize) {
		if err != nil {
			return nil, err
		}
		accJwt, err := b.Jwt(ctx, req.Storage, id.accountId(acc))
		if err != nil {
			return nil, err
		}

		rawClaims, err := jwt.Decode(accJwt.Token)
		if err != nil {
			return nil, err
		}

		if rawClaims.Claims().Issuer != oldPublicKey {
			// this account was signed using a different key
			continue
		}

		// reissue the jwts
		warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id.accountId(acc))
		if err != nil {
			return nil, err
		}

		for _, v := range warnings {
			resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", acc, v))
		}
	}

	// suspend sync
	sync, err := b.OperatorSync(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if sync != nil {
		sync.Suspend = true
		err := storeInStorage(ctx, req.Storage, sync.configPath(), sync)
		if err != nil {
			return nil, err
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *backend) pathRotateOperatorSigningKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := OperatorSigningKeyIdField(d)

	// read the old nkey
	oldNkey, err := b.Nkey(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if oldNkey == nil {
		return logical.ErrorResponse("signing key %q does not exist", id.name), nil
	}
	oldPublicKey, err := oldNkey.publicKey()
	if err != nil {
		return nil, err
	}

	// write a new nkey
	nkey, err := NewOperatorNKey(id)
	err = storeInStorage(ctx, req.Storage, nkey.nkeyPath(), nkey)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	warnings, err := b.issueAndSaveOperatorJWT(ctx, req.Storage, id.operatorId())
	if err != nil {
		return nil, fmt.Errorf("failed to encode operator jwt: %w", err)
	}

	for _, v := range warnings {
		resp.AddWarning(fmt.Sprintf("while reissuing jwt for operator %q: %s", id.op, v))
	}

	opId := id.operatorId()
	for acc, err := range listPaged(ctx, req.Storage, opId.accountsJwtPrefix(), DefaultPagingSize) {
		if err != nil {
			return nil, err
		}
		accJwt, err := b.Jwt(ctx, req.Storage, opId.accountId(acc))
		if err != nil {
			return nil, err
		}

		rawClaims, err := jwt.Decode(accJwt.Token)
		if err != nil {
			return nil, err
		}

		if rawClaims.Claims().Issuer != oldPublicKey {
			// this account was signed using a different key
			continue
		}

		// reissue the jwts
		warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, opId.accountId(acc))
		if err != nil {
			return nil, err
		}

		for _, v := range warnings {
			resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", acc, v))
		}
	}

	// suspend sync
	sync, err := b.OperatorSync(ctx, req.Storage, id.operatorId())
	if err != nil {
		return nil, err
	}
	if sync != nil {
		sync.Suspend = true
		err := storeInStorage(ctx, req.Storage, sync.configPath(), sync)
		if err != nil {
			return nil, err
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *backend) pathRotateAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := AccountIdField(d)

	// read the old nkey
	oldNkey, err := b.Nkey(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if oldNkey == nil {
		return logical.ErrorResponse("account %q does not exist", id.acc), nil
	}
	oldKeyPair, err := oldNkey.keyPair()
	if err != nil {
		return nil, err
	}

	// write a new nkey
	nkey, err := NewAccountNKey(id)
	err = storeInStorage(ctx, req.Storage, nkey.nkeyPath(), nkey)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id)
	if err != nil {
		return nil, fmt.Errorf("failed to encode account jwt: %w", err)
	}

	for _, v := range warnings {
		resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", id.acc, v))
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	// todo I think this needs a rollback op just like account deletion
	accountSync, err := b.getAccountSync(ctx, req.Storage, id.operatorId())
	if err != nil {
		b.Logger().Warn("failed to retrieve account sync", "operator", id.op, "account", id.acc, "error", err)
		resp.AddWarning(fmt.Sprintf("unable to sync jwt for account %q: %s", id.acc, err))
	} else if accountSync != nil {
		// todo i don't love this, feels fragile
		err := b.syncAccountRotate(ctx, req.Storage, accountSync, oldKeyPair, id)
		if err != nil {
			b.Logger().Warn("failed to sync account", "operator", id.op, "account", id.acc, "error", err)
			resp.AddWarning(fmt.Sprintf("unable to sync jwt for account %q: %s", id.acc, err))
		}
	}

	return resp, nil
}

func (b *backend) pathRotateAccountSigningKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := AccountSigningKeyIdField(d)
	// read the old nkey
	oldKey, err := b.Nkey(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if oldKey == nil {
		return logical.ErrorResponse("signing key %q does not exist", id.name), nil
	}

	// write a new nkey
	nkey, err := NewAccountNKey(id)
	err = storeInStorage(ctx, req.Storage, nkey.nkeyPath(), nkey)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id.accountId())
	if err != nil {
		return nil, fmt.Errorf("failed to encode account jwt: %w", err)
	}

	for _, v := range warnings {
		resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", id.acc, v))
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

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

	return resp, nil
}

func (b *backend) pathUserKeyRotate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := UserIdField(d)
	user, err := b.User(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return logical.ErrorResponse("user %q does not exist", id.user), nil
	}

	revoke := true
	if revokeRaw, ok := d.GetOk("revoke"); ok {
		r, ok := revokeRaw.(bool)
		if !ok {
			return logical.ErrorResponse("revoke must be a bool, got %T", revokeRaw), nil
		}
		revoke = r
	}

	resp := &logical.Response{}

	if revoke {
		revokeTtl := max(user.CredsMaxTtl, b.System().MaxLeaseTTL())

		account, err := b.Account(ctx, req.Storage, id.accountId())
		if err != nil {
			return nil, err
		}
		if account != nil {
			err = b.addUserToRevocationList(ctx, req.Storage, account.accountId, id, revokeTtl)
			if err != nil {
				return nil, err
			}

			warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id.accountId())
			if err != nil {
				return nil, fmt.Errorf("failed to encode account jwt: %w", err)
			}

			for _, v := range warnings {
				resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", id.acc, v))
			}
		} else {
			b.Logger().Warn("rotate-user: unexpected null account", "operator", id.op, "account", id.acc, "user", id.user)
		}
	}

	// write a new nkey
	nkey, err := NewUserNKey(id)
	err = storeInStorage(ctx, req.Storage, nkey.nkeyPath(), nkey)
	if err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return resp, nil
}
