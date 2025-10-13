package natsbackend

import (
	"context"
	"encoding/json"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/rs/zerolog/log"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/account/v1alpha1"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
)

type IssueAccountImportStorage struct {
	Operator string            `json:"operator"`
	Account  string            `json:"account"`
	Alias    string            `json:"alias"`
	Imports  []v1alpha1.Import `json:"imports"`
}

// IssueAccountImportParameters is the user facing interface for configuring a user issue.
// Using pascal case on purpose.
// +k8s:deepcopy-gen=true
type IssueAccountImportParameters struct {
	Operator string            `json:"operator"`
	Account  string            `json:"account"`
	Alias    string            `json:"alias"`
	Imports  []v1alpha1.Import `json:"imports"`
}

type IssueAccountImportData struct {
	Operator string            `json:"operator"`
	Account  string            `json:"account"`
	Alias    string            `json:"alias"`
	Imports  []v1alpha1.Import `json:"imports"`
}

func pathAccountImportIssue(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/import/" + framework.GenericNameRegex("alias") + "$",
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
				"alias": {
					Type:        framework.TypeString,
					Description: "import identifier",
					Required:    false,
				},
				"imports": {
					Type:        framework.TypeSlice,
					Description: "imports",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountImportIssue,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountImportIssue,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountImportIssue,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteAccountImportIssue,
				},
			},
			HelpSynopsis:    `Manages externally defined imports for accounts.`,
			HelpDescription: `Create and manage imports that will be appended to account claims when generating account jwts.`,
		},
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/import/?$",
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
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListAccountImportIssues,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddAccountImportIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	params := IssueAccountImportParameters{}
	err = json.Unmarshal(jsonString, &params) // Handle the error!
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal parameters")
		return logical.ErrorResponse("Failed to parse parameters"), logical.ErrInvalidRequest
	}

	// Add debug logging
	log.Debug().
		Interface("imports", params.Imports).
		Msg("Parsed parameters")

	err = addAccountImportIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingIssueFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadAccountImportIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueAccountImportParameters{}
	json.Unmarshal(jsonString, &params)

	issue, err := readAccountImportIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingIssueFailedError), nil
	}

	if issue == nil {
		return logical.ErrorResponse(IssueNotFoundError), logical.ErrUnsupportedPath
	}

	return createResponseIssueAccountImportData(issue)
}

func (b *NatsBackend) pathListAccountImportIssues(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueAccountImportParameters{}
	json.Unmarshal(jsonString, &params)

	entries, err := listAccountImportIssues(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListIssuesFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteAccountImportIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueAccountImportParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// delete issue and all related nkeys (no more JWT deletion)
	err = deleteAccountImportIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteIssueFailedError), nil
	}
	return nil, nil
}

func addAccountImportIssue(ctx context.Context, storage logical.Storage, params IssueAccountImportParameters) error {
	log.Info().
		Str("operator", params.Operator).Str("account", params.Account).Str("alias", params.Alias).
		Msgf("issue account import")

	// store issue
	_, err := storeAccountImportIssue(ctx, storage, params)
	if err != nil {
		return err
	}

	accountIssue, err := readAccountIssue(ctx, storage, IssueAccountParameters{
		Operator: params.Operator,
		Account:  params.Account,
	})
	if err != nil {
		return err
	}

	return refreshAccount(ctx, storage, accountIssue)
}

func readAccountImportIssue(ctx context.Context, storage logical.Storage, params IssueAccountImportParameters) (*IssueAccountImportStorage, error) {
	path := getAccountImportIssuePath(params.Operator, params.Account, params.Alias)
	return getFromStorage[IssueAccountImportStorage](ctx, storage, path)
}

func readAllAccountImportIssues(ctx context.Context, storage logical.Storage, params IssueAccountImportParameters) ([]*IssueAccountImportStorage, error) {
	path := getAccountImportIssuePath(params.Operator, params.Account, "")
	paths, err := storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	issues := []*IssueAccountImportStorage{}

	for _, e := range paths {
		e = getAccountImportIssuePath(params.Operator, params.Account, e)
		issue, err := getFromStorage[IssueAccountImportStorage](ctx, storage, e)
		if err != nil {
			return nil, err
		}
		if issue == nil {
			// weird but ok
			continue
		}
		issues = append(issues, issue)
	}

	return issues, nil
}
func listAccountImportIssues(ctx context.Context, storage logical.Storage, params IssueAccountImportParameters) ([]string, error) {
	path := getAccountImportIssuePath(params.Operator, params.Account, "")
	return listIssues(ctx, storage, path)
}

func deleteAccountImportIssue(ctx context.Context, storage logical.Storage, params IssueAccountImportParameters) error {
	// get stored issue
	issue, err := readAccountImportIssue(ctx, storage, params)
	if err != nil {
		return err
	}
	if issue == nil {
		// nothing to delete
		return nil
	}

	// delete import issue
	path := getAccountImportIssuePath(issue.Operator, issue.Account, issue.Alias)
	err = deleteFromStorage(ctx, storage, path)
	if err != nil {
		return err
	}

	account, err := readAccountIssue(ctx, storage, IssueAccountParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		// we can't return an error here, because
		// the issue has already been deleted
		log.Err(err).
			Str("operator", params.Operator).Str("account", params.Account).Str("alias", params.Alias).
			Msg("failed to read account")
		return nil
	}

	if account != nil {
		// refresh account with updated imports
		err = refreshAccount(ctx, storage, account)
		if err != nil {
			// we can't return an error here, because
			// the issue has already been deleted
			log.Err(err).
				Str("operator", params.Operator).Str("account", params.Account).Str("alias", params.Alias).
				Msg("failed to refresh account")
		}
	}

	return nil
}

func storeAccountImportIssue(ctx context.Context, storage logical.Storage, params IssueAccountImportParameters) (*IssueAccountImportStorage, error) {
	path := getAccountImportIssuePath(params.Operator, params.Account, params.Alias)

	issue, err := getFromStorage[IssueAccountImportStorage](ctx, storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		issue = &IssueAccountImportStorage{}
	}

	issue.Imports = params.Imports

	// always initialize the array
	if issue.Imports == nil {
		issue.Imports = []v1alpha1.Import{}
	}

	issue.Operator = params.Operator
	issue.Account = params.Account
	issue.Alias = params.Alias

	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func getAccountImportIssuePath(operator string, account string, alias string) string {
	return "issue/operator/" + operator + "/account/" + account + "/import/" + alias
}

func createResponseIssueAccountImportData(issue *IssueAccountImportStorage) (*logical.Response, error) {
	data := &IssueAccountImportData{
		Operator: issue.Operator,
		Account:  issue.Account,
		Alias:    issue.Alias,
		Imports:  issue.Imports,
	}

	rval := map[string]any{}
	err := stm.StructToMap(data, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}
