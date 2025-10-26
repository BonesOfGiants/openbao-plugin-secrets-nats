package natsbackend

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
	"github.com/nats-io/jwt/v2"
	"github.com/rs/zerolog/log"
)

func pathAccountJWT(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "jwt/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "$",
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
				"jwt": {
					Type:        framework.TypeString,
					Description: "Account JWT to import.",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathAccountJWTExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountJWT,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountJWT,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountJWT,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteAccountJWT,
				},
			},
			HelpSynopsis:    `Manages account JWT's.`,
			HelpDescription: ``,
		},
		{
			Pattern: "jwt/operator/" + framework.GenericNameRegex("operator") + "/account/?$",
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
					Callback: b.pathListAccountJWT,
				},
			},
			HelpSynopsis:    `List account JWT's.`,
			HelpDescription: ``,
		},
	}
}

func (b *NatsBackend) pathAddAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addAccountJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingJWTFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	jwt, err := readAccountJWT(ctx, req.Storage, JWTParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
	})
	if err != nil || jwt == nil {
		return nil, err
	}

	return createResponseJWTData(jwt)
}

func (b *NatsBackend) pathAccountJWTExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	jwt, err := readAccountJWT(ctx, req.Storage, JWTParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
	})
	if err != nil {
		return false, err
	}

	return jwt != nil, nil
}

func (b *NatsBackend) pathListAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	operator := data.Get("operator").(string)
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	path := getAccountJWTPath(operator, "")
	entries, err := req.Storage.ListPage(ctx, path, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(filterSubkeys(entries)), nil
}

func (b *NatsBackend) pathDeleteAccountJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// when a key is given, store it
	err = deleteAccountJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteJWTFailedError), nil
	}
	return nil, nil
}

func readAccountJWT(ctx context.Context, storage logical.Storage, params JWTParameters) (*JWTStorage, error) {
	path := getAccountJWTPath(params.Operator, params.Account)
	return readJWT(ctx, storage, path)
}

func deleteAccountJWT(ctx context.Context, storage logical.Storage, params JWTParameters) error {
	path := getAccountJWTPath(params.Operator, params.Account)
	return deleteJWT(ctx, storage, path)
}

func addAccountJWT(ctx context.Context, storage logical.Storage, params JWTParameters) error {
	log.Info().
		Str("operator", params.Operator).Str("account", params.Account).
		Msg("create/update account jwt")

	if params.JWT == "" {
		return fmt.Errorf("account JWT is required")
	} else {
		err := validateJWT[jwt.AccountClaims](params.JWT)
		if err != nil {
			return err
		}
	}

	path := getAccountJWTPath(params.Operator, params.Account)
	err := addJWT(ctx, storage, path, params)
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

func getAccountJWTPath(operator string, account string) string {
	return "jwt/operator/" + operator + "/account/" + account
}
