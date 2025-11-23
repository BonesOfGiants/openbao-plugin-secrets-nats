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
	RevokeOnDelete bool                `json:"revokeOnDelete,omitempty"`
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
	RevokeOnDelete bool                `json:"revokeOnDelete,omitempty"`
	ClaimsTemplate v1alpha1.UserClaims `json:"claimsTemplate"`
	ExpirationS    int64               `json:"expirationS,omitempty"`
}

type UserRevocationParameters struct {
	Operator    string `json:"operator"`
	Account     string `json:"account"`
	User        string `json:"user"`
	ExpirationS *int64 `json:"expirationS,omitempty"`
}

type IssueUserData struct {
	Operator       string              `json:"operator"`
	Account        string              `json:"account"`
	User           string              `json:"user"`
	UseSigningKey  string              `json:"useSigningKey"`
	RevokeOnDelete bool                `json:"revokeOnDelete"`
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
			ExistenceCheck: b.pathUserIssueExistenceCheck,
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
					Callback: b.pathListUserIssues,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/" + framework.GenericNameRegex("user") + "/revocation$",
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
				"expirationS": {
					Type:        framework.TypeInt,
					Description: "revocation ttl",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathUserIssueRevocationExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddUserIssueRevocation,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddUserIssueRevocation,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadUserIssueRevocation,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteUserIssueRevocation,
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
	issue, err := readUserIssue(ctx, req.Storage, IssueUserParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
		User:     data.Get("user").(string),
	})
	if err != nil || issue == nil {
		return nil, err
	}

	return createResponseIssueUserData(issue)
}

func (b *NatsBackend) pathUserIssueExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	issue, err := readUserIssue(ctx, req.Storage, IssueUserParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
		User:     data.Get("user").(string),
	})
	if err != nil {
		return false, err
	}

	return issue != nil, nil
}

func (b *NatsBackend) pathListUserIssues(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	operator := data.Get("operator").(string)
	account := data.Get("account").(string)
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	path := getUserIssuePath(operator, account, "")
	entries, err := req.Storage.ListPage(ctx, path, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(filterSubkeys(entries)), nil
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

func (b *NatsBackend) pathAddUserIssueRevocation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	params := UserRevocationParameters{}
	err = json.Unmarshal(jsonString, &params) // Handle the error!
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal parameters")
		return logical.ErrorResponse("Failed to parse parameters"), logical.ErrInvalidRequest
	}

	log.Debug().Msg("Parsed parameters")

	if params.ExpirationS == nil {
		issue, err := readUserIssue(ctx, req.Storage, IssueUserParameters{
			Operator: params.Operator,
			Account:  params.Account,
			User:     params.User,
		})
		if err != nil {
			return logical.ErrorResponse(ReadingIssueFailedError), nil
		}

		if issue == nil {
			return logical.ErrorResponse(IssueNotFoundError), logical.ErrUnsupportedPath
		}

		v := issue.ExpirationS
		params.ExpirationS = &v
	}

	nkey, err := readUserNkey(ctx, req.Storage, NkeyParameters{
		Operator: params.Operator,
		Account:  params.Account,
		User:     params.User,
	})
	if err != nil {
		return logical.ErrorResponse(ReadingIssueFailedError), nil
	}

	if nkey == nil {
		return logical.ErrorResponse(IssueNotFoundError), logical.ErrUnsupportedPath
	}

	nkeyData, err := toNkeyData(nkey)
	if err != nil {
		return logical.ErrorResponse(ReadingIssueFailedError), nil
	}

	if nkeyData == nil {
		return logical.ErrorResponse(IssueNotFoundError), logical.ErrUnsupportedPath
	}

	err = addAccountRevocationIssue(ctx, req.Storage, IssueAccountRevocationParameters{
		Operator:    params.Operator,
		Account:     params.Account,
		Subject:     nkeyData.PublicKey,
		ExpirationS: *params.ExpirationS,
	}, true)
	if err != nil {
		return logical.ErrorResponse(AddingIssueFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadUserIssueRevocation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	operator := data.Get("operator").(string)
	account := data.Get("account").(string)
	user := data.Get("user").(string)

	nkey, err := readUserNkey(ctx, req.Storage, NkeyParameters{
		Operator: operator,
		Account:  account,
		User:     user,
	})
	if err != nil {
		return nil, err
	}

	if nkey == nil {
		return nil, nil
	}

	nkeyData, err := toNkeyData(nkey)
	if err != nil {
		return nil, err
	}

	if nkeyData == nil {
		return nil, nil
	}

	issue, err := readAccountRevocationIssue(ctx, req.Storage, IssueAccountRevocationParameters{
		Operator: operator,
		Account:  account,
		Subject:  nkeyData.PublicKey,
	})
	if err != nil {
		return nil, err
	}

	if issue == nil {
		return nil, nil
	}

	return createResponseIssueAccountRevocationData(issue)
}

func (b *NatsBackend) pathUserIssueRevocationExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	operator := data.Get("operator").(string)
	account := data.Get("account").(string)
	user := data.Get("user").(string)

	nkey, err := readUserNkey(ctx, req.Storage, NkeyParameters{
		Operator: operator,
		Account:  account,
		User:     user,
	})
	if err != nil {
		return false, err
	}

	if nkey == nil {
		return false, nil
	}

	nkeyData, err := toNkeyData(nkey)
	if err != nil {
		return false, err
	}

	if nkeyData == nil {
		return false, nil
	}

	issue, err := readAccountRevocationIssue(ctx, req.Storage, IssueAccountRevocationParameters{
		Operator: operator,
		Account:  account,
		Subject:  nkeyData.PublicKey,
	})
	if err != nil {
		return false, err
	}

	return issue != nil, nil
}

func (b *NatsBackend) pathDeleteUserIssueRevocation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	params := UserRevocationParameters{}
	err = json.Unmarshal(jsonString, &params) // Handle the error!
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal parameters")
		return logical.ErrorResponse("Failed to parse parameters"), logical.ErrInvalidRequest
	}

	log.Debug().
		Msg("Parsed parameters")

	nkey, err := readUserNkey(ctx, req.Storage, NkeyParameters{
		Operator: params.Operator,
		Account:  params.Account,
		User:     params.User,
	})
	if err != nil {
		return logical.ErrorResponse(ReadingIssueFailedError), nil
	}

	if nkey == nil {
		return logical.ErrorResponse(IssueNotFoundError), logical.ErrUnsupportedPath
	}

	nkeyData, err := toNkeyData(nkey)
	if err != nil {
		return logical.ErrorResponse(ReadingIssueFailedError), nil
	}

	if nkeyData == nil {
		return logical.ErrorResponse(IssueNotFoundError), logical.ErrUnsupportedPath
	}

	err = deleteAccountRevocationIssue(ctx, req.Storage, IssueAccountRevocationParameters{
		Operator: params.Operator,
		Account:  params.Account,
		Subject:  nkeyData.PublicKey,
	}, true)
	if err != nil {
		return logical.ErrorResponse(AddingIssueFailedError), nil
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
	// create nkeys
	err := refreshUserNKeys(ctx, storage, *issue)
	if err != nil {
		return err
	}

	// Update status
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

		err = syncOperatorAccounts(ctx, storage, op)
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

	if params.RevokeOnDelete {
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

	issue.Operator = params.Operator
	issue.Account = params.Account
	issue.User = params.User
	issue.UseSigningKey = params.UseSigningKey
	issue.RevokeOnDelete = params.RevokeOnDelete
	issue.ClaimsTemplate = params.ClaimsTemplate
	issue.ExpirationS = params.ExpirationS

	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func refreshUserNKeys(ctx context.Context, storage logical.Storage, issue IssueUserStorage) error {
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
	return issueOperatorPrefix + operator + "/account/" + account + "/user/" + user
}

func createResponseIssueUserData(issue *IssueUserStorage) (*logical.Response, error) {
	data := &IssueUserData{
		Operator:       issue.Operator,
		Account:        issue.Account,
		User:           issue.User,
		UseSigningKey:  issue.UseSigningKey,
		RevokeOnDelete: issue.RevokeOnDelete,
		ClaimsTemplate: issue.ClaimsTemplate,
		ExpirationS:    issue.ExpirationS,
		Status:         issue.Status,
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
