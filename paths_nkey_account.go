package natsbackend

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"
)

func pathAccountNkey(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "$",
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
				"seed": {
					Type:        framework.TypeString,
					Description: "Nkey seed",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathAccountNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountNkey,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountNkey,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountNkey,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteAccountNkey,
				},
			},
			HelpSynopsis:    `Manages account Nkeys.`,
			HelpDescription: `On create/update: If no account Nkey seed is passed, a corresponding Nkey is generated.`,
		},
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/account/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
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
					Callback: b.pathListAccountNkeys,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddAccountNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addAccountNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("%s: %s", AddingNkeyFailedError, err.Error())), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadAccountNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	nkey, err := readAccountNkey(ctx, req.Storage, NkeyParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
	})
	if err != nil || nkey == nil {
		return nil, err
	}

	return createResponseNkeyData(nkey)
}

func (b *NatsBackend) pathAccountNkeyExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	nkey, err := readAccountNkey(ctx, req.Storage, NkeyParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
	})
	if err != nil {
		return false, err
	}

	return nkey != nil, err
}

func (b *NatsBackend) pathListAccountNkeys(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	operator := data.Get("operator").(string)
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	path := getAccountNkeyPath(operator, "")
	entries, err := req.Storage.ListPage(ctx, path, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(filterSubkeys(entries)), nil
}

func (b *NatsBackend) pathDeleteAccountNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	err = deleteAccountNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteNkeyFailedError), nil
	}
	return nil, nil
}

func readAccountNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) (*NKeyStorage, error) {
	path := getAccountNkeyPath(params.Operator, params.Account)
	return readNkey(ctx, storage, path)
}

func deleteAccountNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	path := getAccountNkeyPath(params.Operator, params.Account)
	return deleteNkey(ctx, storage, path)
}

func addAccountNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	log.Info().
		Str("operator", params.Operator).Str("account", params.Account).
		Msg("create/update account nkey")

	path := getAccountNkeyPath(params.Operator, params.Account)
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

func getAccountNkeyPath(operator string, account string) string {
	return nkeyOperatorPrefix + operator + "/account/" + account
}
