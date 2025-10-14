package natsbackend

import (
	"context"
	"encoding/json"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/rs/zerolog/log"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
)

type IssueAccountRevocationStorage struct {
	Operator     string `json:"operator"`
	Account      string `json:"account"`
	Subject      string `json:"sub"`
	CreationTime int64  `json:"creationTime"`
}

// IssueAccountRevocationParameters is the user facing interface for configuring a user issue.
// Using pascal case on purpose.
// +k8s:deepcopy-gen=true
type IssueAccountRevocationParameters struct {
	Operator string `json:"operator"`
	Account  string `json:"account"`
	Subject  string `json:"sub"`
}

type IssueAccountRevocationData struct {
	Operator     string `json:"operator"`
	Account      string `json:"account"`
	Subject      string `json:"sub"`
	CreationTime int64  `json:"creationTime"`
}

func pathAccountRevocationIssue(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/revocation/" + framework.GenericNameRegex("sub") + "$",
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
				"sub": {
					Type:        framework.TypeString,
					Description: "sub identifier",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountRevocationIssue,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountRevocationIssue,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountRevocationIssue,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteAccountRevocationIssue,
				},
			},
			HelpSynopsis:    `Manages externally defined revocations for accounts.`,
			HelpDescription: `Create and manage revocations that will be appended to account claims when generating account jwts.`,
		},
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/revocation/?$",
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
					Callback: b.pathListAccountRevocationIssues,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddAccountRevocationIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	params := IssueAccountRevocationParameters{}
	err = json.Unmarshal(jsonString, &params) // Handle the error!
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal parameters")
		return logical.ErrorResponse("Failed to parse parameters"), logical.ErrInvalidRequest
	}

	// Add debug logging
	log.Debug().
		Msg("Parsed parameters")

	err = addAccountRevocationIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingIssueFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadAccountRevocationIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueAccountRevocationParameters{}
	json.Unmarshal(jsonString, &params)

	issue, err := readAccountRevocationIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingIssueFailedError), nil
	}

	if issue == nil {
		return logical.ErrorResponse(IssueNotFoundError), logical.ErrUnsupportedPath
	}

	return createResponseIssueAccountRevocationData(issue)
}

func (b *NatsBackend) pathListAccountRevocationIssues(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueAccountRevocationParameters{}
	json.Unmarshal(jsonString, &params)

	entries, err := listAccountRevocationIssues(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListIssuesFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteAccountRevocationIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueAccountRevocationParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// delete issue and all related nkeys (no more JWT deletion)
	err = deleteAccountRevocationIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteIssueFailedError), nil
	}
	return nil, nil
}

func addAccountRevocationIssue(ctx context.Context, storage logical.Storage, params IssueAccountRevocationParameters) error {
	log.Info().
		Str("operator", params.Operator).Str("account", params.Account).Str("sub", params.Subject).
		Msgf("issue account revocation")

	// store issue
	_, err := storeAccountRevocationIssue(ctx, storage, params)
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

func readAccountRevocationIssue(ctx context.Context, storage logical.Storage, params IssueAccountRevocationParameters) (*IssueAccountRevocationStorage, error) {
	path := getAccountRevocationIssuePath(params.Operator, params.Account, params.Subject)
	return getFromStorage[IssueAccountRevocationStorage](ctx, storage, path)
}

func readAllAccountRevocationIssues(ctx context.Context, storage logical.Storage, params IssueAccountRevocationParameters) ([]*IssueAccountRevocationStorage, error) {
	path := getAccountRevocationIssuePath(params.Operator, params.Account, "")
	paths, err := storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	issues := []*IssueAccountRevocationStorage{}

	for _, e := range paths {
		e = getAccountRevocationIssuePath(params.Operator, params.Account, e)
		issue, err := getFromStorage[IssueAccountRevocationStorage](ctx, storage, e)
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
func listAccountRevocationIssues(ctx context.Context, storage logical.Storage, params IssueAccountRevocationParameters) ([]string, error) {
	path := getAccountRevocationIssuePath(params.Operator, params.Account, "")
	return listIssues(ctx, storage, path)
}

func deleteAccountRevocationIssue(ctx context.Context, storage logical.Storage, params IssueAccountRevocationParameters) error {
	// get stored issue
	issue, err := readAccountRevocationIssue(ctx, storage, params)
	if err != nil {
		return err
	}
	if issue == nil {
		// nothing to delete
		return nil
	}

	// delete import issue
	path := getAccountRevocationIssuePath(issue.Operator, issue.Account, issue.Subject)
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
			Str("operator", params.Operator).Str("account", params.Account).Str("sub", params.Subject).
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
				Str("operator", params.Operator).Str("account", params.Account).Str("sub", params.Subject).
				Msg("failed to refresh account")
		}
	}

	return nil
}

func storeAccountRevocationIssue(ctx context.Context, storage logical.Storage, params IssueAccountRevocationParameters) (*IssueAccountRevocationStorage, error) {
	path := getAccountRevocationIssuePath(params.Operator, params.Account, params.Subject)

	issue, err := getFromStorage[IssueAccountRevocationStorage](ctx, storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		issue = &IssueAccountRevocationStorage{
			CreationTime: time.Now().Unix(),
		}
	}

	issue.Operator = params.Operator
	issue.Account = params.Account
	issue.Subject = params.Subject

	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func getAccountRevocationIssuePath(operator string, account string, alias string) string {
	return "issue/operator/" + operator + "/account/" + account + "/recovation/" + alias
}

func createResponseIssueAccountRevocationData(issue *IssueAccountRevocationStorage) (*logical.Response, error) {
	data := &IssueAccountRevocationData{
		Operator:     issue.Operator,
		Account:      issue.Account,
		Subject:      issue.Subject,
		CreationTime: issue.CreationTime,
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
