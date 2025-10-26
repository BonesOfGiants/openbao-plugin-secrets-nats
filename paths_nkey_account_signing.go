package natsbackend

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"
)

func pathAccountSigningNkey(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/signing/" + framework.GenericNameRegex("signing") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"account": {
					Type:        framework.TypeString,
					Description: "account identifier",
					Required:    false,
				},
				"signing": {
					Type:        framework.TypeString,
					Description: "signing identifier",
					Required:    false,
				},
				"seed": {
					Type:        framework.TypeString,
					Description: "Nkey seed - Base64 Encoded.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountSigningNkey,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountSigningNkey,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountSigningNkey,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteAccountSigningNkey,
				},
			},
			HelpSynopsis:    `Manages account signing Nkey keypairs.`,
			HelpDescription: `On Create or Update: If no account signing Nkey keypair is passed, a corresponding Nkey is generated.`,
		},
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/signing/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"account": {
					Type:        framework.TypeString,
					Description: "account identifier",
					Required:    false,
				},
				"after": {
					Type:        framework.TypeString,
					Description: `Optional entry to list begin listing after, not required to exist.`,
					Required:    false,
				},
				"limit": {
					Type:        framework.TypeInt,
					Description: `Optional number of entries to return; defaults to all entries.`,
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListAccountSigningNkeys,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddAccountSigningNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addAccountSigningNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse("%s: %s", AddingNkeyFailedError, err.Error()), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadAccountSigningNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	nkey, err := readAccountSigningNkey(ctx, req.Storage, NkeyParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
		Signing:  data.Get("signing").(string),
	})
	if err != nil || nkey == nil {
		return nil, err
	}

	return createResponseNkeyData(nkey)
}

func (b *NatsBackend) pathAccountSigningNkeyExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	nkey, err := readAccountSigningNkey(ctx, req.Storage, NkeyParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
		Signing:  data.Get("signing").(string),
	})
	if err != nil {
		return false, err
	}

	return nkey != nil, nil
}

func (b *NatsBackend) pathListAccountSigningNkeys(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	operator := data.Get("operator").(string)
	account := data.Get("account").(string)
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	path := getAccountSigningNkeyPath(operator, account, "")
	entries, err := req.Storage.ListPage(ctx, path, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(filterSubkeys(entries)), nil
}

func (b *NatsBackend) pathDeleteAccountSigningNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// when a key is given, store it
	err = deleteAccountSigningNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteNkeyFailedError), nil
	}
	return nil, nil
}

func readAccountSigningNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) (*NKeyStorage, error) {
	path := getAccountSigningNkeyPath(params.Operator, params.Account, params.Signing)
	return readNkey(ctx, storage, path)
}

func deleteAccountSigningNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	path := getAccountSigningNkeyPath(params.Operator, params.Account, params.Signing)
	return deleteNkey(ctx, storage, path)
}

func addAccountSigningNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	log.Info().
		Str("operator", params.Operator).Str("account", params.Account).Str("signing", params.Signing).
		Msg("create/update account signing nkey")

	path := getAccountSigningNkeyPath(params.Operator, params.Account, params.Signing)
	err := addNkey(ctx, storage, path, nkeys.PrefixByteAccount, params, "account")
	if err != nil {
		return err
	}

	iParams := IssueAccountParameters{
		Operator: params.Operator,
		Account:  params.Account,
	}

	issue, err := readAccountIssue(ctx, storage, iParams)
	if err != nil {
		return err
	}
	if issue == nil {
		//ignore error, try to create issue
		addAccountIssue(ctx, storage, iParams)
	}
	return nil
}

func getAccountSigningNkeyPath(operator string, account string, signing string) string {
	return "nkey/operator/" + operator + "/account/" + account + "/signing/" + signing
}
