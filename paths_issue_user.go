package natsbackend

import (
	"context"
	"encoding/json"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/rs/zerolog/log"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/user/v1alpha1"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
)

type IssueUserStorage struct {
	Operator       string              `json:"operator"`
	Account        string              `json:"account"`
	User           string              `json:"user"`
	UseSigningKey  string              `json:"useSigningKey"`
	ClaimsTemplate v1alpha1.UserClaims `json:"claimsTemplate"`
	ExpirationS    int64               `json:"expirationS,omitempty"`
	Status         IssueUserStatus     `json:"status"`
}

// IssueUserParameters is the user facing interface for configuring a user issue.
// Using pascal case on purpose.
// +k8s:deepcopy-gen=true
type IssueUserParameters struct {
	Operator       string              `json:"operator"`
	Account        string              `json:"account"`
	User           string              `json:"user"`
	UseSigningKey  string              `json:"useSigningKey,omitempty"`
	ClaimsTemplate v1alpha1.UserClaims `json:"claimsTemplate,omitempty"`
	ExpirationS    int64               `json:"expirationS,omitempty"`
}

type IssueUserData struct {
	Operator       string              `json:"operator"`
	Account        string              `json:"account"`
	User           string              `json:"user"`
	UseSigningKey  string              `json:"useSigningKey"`
	ClaimsTemplate v1alpha1.UserClaims `json:"claimsTemplate"`
	ExpirationS    int64               `json:"expirationS"`
	Status         IssueUserStatus     `json:"status"`
}

type IssueUserStatus struct {
	User IssueStatus `json:"user"`
}

func pathUserIssue(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/" + framework.GenericNameRegex("user") + "$",
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
				"user": {
					Type:        framework.TypeString,
					Description: "user identifier",
					Required:    false,
				},
				"useSigningKey": {
					Type:        framework.TypeString,
					Description: "signing key identifier",
					Required:    false,
				},
				"claimsTemplate": {
					Type:        framework.TypeMap,
					Description: "User claims template with placeholders (jwt.UserClaims from github.com/nats-io/jwt/v2)",
					Required:    false,
				},
				"expirationS": {
					Type:        framework.TypeInt,
					Description: "JWT expiration time in seconds from now",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddUserIssue,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddUserIssue,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadUserIssue,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteUserIssue,
				},
			},
			HelpSynopsis:    `Manages user templates for dynamic credential generation.`,
			HelpDescription: `Create and manage user templates that will be used to generate JWTs on-demand when credentials are requested.`,
		},
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/?$",
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
					Callback: b.pathListUserIssues,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddUserIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	params := IssueUserParameters{}
	err = json.Unmarshal(jsonString, &params) // Handle the error!
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal parameters")
		return logical.ErrorResponse("Failed to parse parameters"), logical.ErrInvalidRequest
	}

	// Add debug logging
	log.Debug().
		Interface("claimsTemplate", params.ClaimsTemplate).
		Int64("expirationS", params.ExpirationS).
		Msg("Parsed parameters")

	err = addUserIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingIssueFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadUserIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueUserParameters{}
	json.Unmarshal(jsonString, &params)

	issue, err := readUserIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingIssueFailedError), nil
	}

	if issue == nil {
		return logical.ErrorResponse(IssueNotFoundError), logical.ErrUnsupportedPath
	}

	return createResponseIssueUserData(issue)
}

func (b *NatsBackend) pathListUserIssues(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueUserParameters{}
	json.Unmarshal(jsonString, &params)

	entries, err := listUserIssues(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListIssuesFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteUserIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueUserParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// delete issue and all related nkeys (no more JWT deletion)
	err = deleteUserIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteIssueFailedError), nil
	}
	return nil, nil
}

func addUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) error {
	log.Info().
		Str("operator", params.Operator).Str("account", params.Account).Str("user", params.User).
		Msgf("issue user template")

	// store issue template
	issue, err := storeUserIssue(ctx, storage, params)
	if err != nil {
		return err
	}

	return refreshUser(ctx, storage, issue)
}

func refreshUser(ctx context.Context, storage logical.Storage, issue *IssueUserStorage) error {
	// Only create nkey during issue
	err := issueUserNKeys(ctx, storage, *issue)
	if err != nil {
		return err
	}

	// Update status (only nkey now)
	updateUserStatus(ctx, storage, issue)

	_, err = storeUserIssueUpdate(ctx, storage, issue)
	if err != nil {
		return err
	}

	// Handle DefaultPushUser logic if needed
	if issue.User == DefaultPushUser {
		op, err := readOperatorIssue(ctx, storage, IssueOperatorParameters{
			Operator: issue.Operator,
		})
		if err != nil {
			return err
		} else if op == nil {
			log.Warn().Str("operator", issue.Operator).Str("account", issue.Account).Msg("cannot refresh operator: operator issue does not exist")
			return nil
		}

		err = refreshAccountResolvers(ctx, storage, op)
		if err != nil {
			return err
		}
	}
	return nil
}

func readUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) (*IssueUserStorage, error) {
	path := getUserIssuePath(params.Operator, params.Account, params.User)
	return getFromStorage[IssueUserStorage](ctx, storage, path)
}

func listUserIssues(ctx context.Context, storage logical.Storage, params IssueUserParameters) ([]string, error) {
	path := getUserIssuePath(params.Operator, params.Account, "")
	return listIssues(ctx, storage, path)
}

func deleteUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) error {
	// get stored issue
	issue, err := readUserIssue(ctx, storage, params)
	if err != nil {
		return err
	}
	if issue == nil {
		// nothing to delete
		return nil
	}

	// account revocation list handling for deleted user
	account, err := readAccountIssue(ctx, storage, IssueAccountParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return err
	}
	if account != nil {
		// add deleted user to revocation list and update the account JWT
		err = addUserToRevocationList(ctx, storage, account, issue)
		if err != nil {
			return err
		}
	}

	// delete user nkey
	nkey := NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	}
	err = deleteUserNkey(ctx, storage, nkey)
	if err != nil {
		return err
	}

	// delete user issue
	path := getUserIssuePath(issue.Operator, issue.Account, issue.User)
	return deleteFromStorage(ctx, storage, path)
}

func storeUserIssueUpdate(ctx context.Context, storage logical.Storage, issue *IssueUserStorage) (*IssueUserStorage, error) {
	path := getUserIssuePath(issue.Operator, issue.Account, issue.User)

	err := storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func storeUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) (*IssueUserStorage, error) {
	path := getUserIssuePath(params.Operator, params.Account, params.User)

	issue, err := getFromStorage[IssueUserStorage](ctx, storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		issue = &IssueUserStorage{}
	}

	issue.ClaimsTemplate = params.ClaimsTemplate
	issue.ExpirationS = params.ExpirationS
	issue.Operator = params.Operator
	issue.Account = params.Account
	issue.User = params.User
	issue.UseSigningKey = params.UseSigningKey

	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func issueUserNKeys(ctx context.Context, storage logical.Storage, issue IssueUserStorage) error {
	p := NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	}
	stored, err := readUserNkey(ctx, storage, p)
	if err != nil {
		return err
	}
	if stored == nil {
		err := addUserNkey(ctx, storage, p)
		if err != nil {
			return err
		}
	}
	log.Info().
		Str("operator", issue.Operator).Str("account", issue.Account).Str("user", issue.User).
		Msg("nkey assigned")
	return nil
}

func getUserIssuePath(operator string, account string, user string) string {
	return "issue/operator/" + operator + "/account/" + account + "/user/" + user
}

func createResponseIssueUserData(issue *IssueUserStorage) (*logical.Response, error) {
	data := &IssueUserData{
		Operator:       issue.Operator,
		Account:        issue.Account,
		User:           issue.User,
		UseSigningKey:  issue.UseSigningKey,
		ClaimsTemplate: issue.ClaimsTemplate,
		ExpirationS:    issue.ExpirationS,
		Status:         issue.Status,
	}

	rval := map[string]interface{}{}
	err := stm.StructToMap(data, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}

func updateUserStatus(ctx context.Context, storage logical.Storage, issue *IssueUserStorage) {
	// Only check nkey status now (JWT is generated on-demand)
	nkey, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	})
	if err == nil && nkey != nil {
		issue.Status.User.Nkey = true
	} else {
		issue.Status.User.Nkey = false
	}
}
