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

func pathOperatorJWT(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "jwt/operator/" + framework.GenericNameRegex("operator") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"jwt": {
					Type:        framework.TypeString,
					Description: "Operator JWT to import.",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathOperatorJWTExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorJWT,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorJWT,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadOperatorJWT,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteOperatorJWT,
				},
			},
			HelpSynopsis:    `Manages operator JWT.`,
			HelpDescription: ``,
		},
		{
			Pattern: "jwt/operator/?$",
			Fields: map[string]*framework.FieldSchema{
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
					Callback: b.pathListOperatorJWTs,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddOperatorJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params JWTParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addOperatorJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingJWTFailedError), nil
	}
	return nil, nil

}

func (b *NatsBackend) pathReadOperatorJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	jwt, err := readOperatorJWT(ctx, req.Storage, JWTParameters{
		Operator: data.Get("operator").(string),
	})
	if err != nil || jwt == nil {
		return nil, err
	}

	return createResponseJWTData(jwt)
}

func (b *NatsBackend) pathOperatorJWTExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	jwt, err := readOperatorJWT(ctx, req.Storage, JWTParameters{
		Operator: data.Get("operator").(string),
	})
	if err != nil {
		return false, err
	}

	return jwt != nil, nil
}

func (b *NatsBackend) pathListOperatorJWTs(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, jwtOperatorPrefix, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(filterSubkeys(entries)), nil
}

func (b *NatsBackend) pathDeleteOperatorJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	err = deleteOperatorJWT(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteJWTFailedError), nil
	}
	return nil, nil
}

func readOperatorJWT(ctx context.Context, storage logical.Storage, params JWTParameters) (*JWTStorage, error) {
	path := getOperatorJWTPath(params.Operator)
	return readJWT(ctx, storage, path)
}

func deleteOperatorJWT(ctx context.Context, storage logical.Storage, params JWTParameters) error {
	path := getOperatorJWTPath(params.Operator)
	return deleteJWT(ctx, storage, path)
}

func addOperatorJWT(ctx context.Context, storage logical.Storage, params JWTParameters) error {
	log.Info().
		Str("operator", params.Operator).
		Msg("create/update operator jwt")

	if params.JWT == "" {
		return fmt.Errorf("operator JWT is required")
	} else {
		err := validateJWT[jwt.OperatorClaims](params.JWT)
		if err != nil {
			return err
		}
	}

	path := getOperatorJWTPath(params.Operator)
	err := addJWT(ctx, storage, path, params)
	if err != nil {
		return err
	}

	iParams := IssueOperatorParameters{
		Operator: params.Operator,
	}
	issue, err := readOperatorIssue(ctx, storage, iParams)
	if err != nil {
		return err
	}
	if issue == nil {
		//ignore error, try to create issue
		addOperatorIssue(ctx, storage, iParams)
	}
	return nil
}

func getOperatorJWTPath(operator string) string {
	return "jwt/operator/" + operator
}
