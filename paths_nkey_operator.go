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

func pathOperatorNkey(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "nkey/operator/" + framework.GenericNameRegex("operator") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"seed": {
					Type:        framework.TypeString,
					Description: "Nkey seed",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathOperatorNkeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorNkey,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorNkey,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadOperatorNkey,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteOperatorNkey,
				},
			},
			HelpSynopsis:    `Manages operator Nkeys.`,
			HelpDescription: `On create/update: If no operator Nkey seed is passed, a corresponding Nkey is generated.`,
		},
		{
			Pattern: "nkey/operator/?$",
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
					Callback: b.pathListOperatorNkeys,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddOperatorNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params NkeyParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	err = addOperatorNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("%s: %s", AddingNkeyFailedError, err.Error())), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadOperatorNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	nkey, err := readOperatorNkey(ctx, req.Storage, NkeyParameters{
		Operator: data.Get("operator").(string),
	})
	if err != nil || nkey == nil {
		return nil, err
	}

	return createResponseNkeyData(nkey)
}

func (b *NatsBackend) pathOperatorNkeyExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	nkey, err := readOperatorNkey(ctx, req.Storage, NkeyParameters{
		Operator: data.Get("operator").(string),
	})
	if err != nil {
		return false, err
	}

	return nkey != nil, nil
}

func (b *NatsBackend) pathListOperatorNkeys(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, nkeyOperatorPrefix, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(filterSubkeys(entries)), nil
}

func (b *NatsBackend) pathDeleteOperatorNkey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	err = deleteOperatorNkey(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteNkeyFailedError), nil
	}
	return nil, nil
}

func readOperatorNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) (*NKeyStorage, error) {
	path := getOperatorNkeyPath(params.Operator)
	return readNkey(ctx, storage, path)
}

func deleteOperatorNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	path := getOperatorNkeyPath(params.Operator)
	return deleteNkey(ctx, storage, path)
}

func addOperatorNkey(ctx context.Context, storage logical.Storage, params NkeyParameters) error {
	log.Info().
		Str("operator", params.Operator).
		Msg("create/update operator nkey")

	path := getOperatorNkeyPath(params.Operator)
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

func getOperatorNkeyPath(operator string) string {
	return "nkey/operator/" + operator
}
