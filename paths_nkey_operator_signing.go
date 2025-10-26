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

func pathOperatorSigningNkey(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/signing/" + framework.GenericNameRegex("signing") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"signing": {
					Type:        framework.TypeString,
					Description: "signing key identifier",
					Required:    false,
				},
				"seed": {
					Type:        framework.TypeString,
					Description: "Nkey seed - Base64 encoded",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathOperatorSigningNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorSigningNkey,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorSigningNkey,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadOperatorSigningNkey,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteOperatorSigningNkey,
				},
			},
			HelpSynopsis:    `Manages signing Nkeys.`,
			HelpDescription: `On create/update: If no signing Nkey seed is passed, a corresponding Nkey is generated.`,
		},
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "/signing/?$",
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
					Callback: b.pathListOperatorSigningNkeys,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddOperatorSigningNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addOperatorSigningNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("%s: %s", AddingNkeyFailedError, err.Error())), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadOperatorSigningNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	nkey, err := readOperatorSigningNkey(ctx, req.Storage, NkeyParameters{
		Operator: data.Get("operator").(string),
		Signing:  data.Get("signing").(string),
	})
	if err != nil || nkey == nil {
		return nil, err
	}

	return createResponseNkeyData(nkey)
}

func (b *NatsBackend) pathOperatorSigningNkeyExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	nkey, err := readOperatorSigningNkey(ctx, req.Storage, NkeyParameters{
		Operator: data.Get("operator").(string),
		Signing:  data.Get("signing").(string),
	})
	if err != nil {
		return false, err
	}

	return nkey != nil, nil
}

func (b *NatsBackend) pathListOperatorSigningNkeys(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	operator := data.Get("operator").(string)
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	path := getOperatorSigningNkeyPath(operator, "")
	entries, err := req.Storage.ListPage(ctx, path, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(filterSubkeys(entries)), nil
}

func (b *NatsBackend) pathDeleteOperatorSigningNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	err = deleteOperatorSigningNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteNkeyFailedError), nil
	}
	return nil, nil
}

func readOperatorSigningNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) (*NKeyStorage, error) {
	path := getOperatorSigningNkeyPath(params.Operator, params.Signing)
	return readNkey(ctx, storage, path)
}

func deleteOperatorSigningNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	path := getOperatorSigningNkeyPath(params.Operator, params.Signing)
	return deleteNkey(ctx, storage, path)
}

func addOperatorSigningNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	log.Info().
		Str("operator", params.Operator).Str("signing", params.Signing).
		Msg("create/update operator signing nkey")

	path := getOperatorSigningNkeyPath(params.Operator, params.Signing)
	err := addNkey(ctx, storage, path, nkeys.PrefixByteOperator, params, "operator")
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

func getOperatorSigningNkeyPath(operator string, signing string) string {
	return "nkey/operator/" + operator + "/signing/" + signing
}
