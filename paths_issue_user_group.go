package natsbackend

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/user/v1alpha1"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
)

type userGroupIssueEntry struct {
	operator string
	account  string
	group    string

	UseSigningKey  string               `json:"useSigningKey,omitempty"`
	ClaimsTemplate *v1alpha1.UserClaims `json:"claimsTemplate,omitempty"`
	ExpirationS    int                  `json:"expirationS,omitempty"`
}

func pathUserGroupIssue(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user-group/" + framework.GenericNameRegex("group") + "$",
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
				"group": {
					Type:        framework.TypeString,
					Description: "user group name",
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
			ExistenceCheck: b.pathUserGroupExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathUserGroupCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathUserGroupCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathUserGroupRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathUserGroupDelete,
				},
			},
			HelpSynopsis:    `Manages user templates for dynamic credential generation.`,
			HelpDescription: `Create and manage user templates that will be used to generate JWTs on-demand when credentials are requested.`,
		},
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user-group/?$",
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
					Callback: b.pathUserGroupList,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) UserGroupIssue(ctx context.Context, s logical.Storage, operator, account, group string) (*userGroupIssueEntry, error) {
	path := userGroupIssuePath(operator, account, group)
	issue, err := getFromStorage[userGroupIssueEntry](ctx, s, path)
	if issue != nil {
		issue.operator = operator
		issue.account = account
		issue.group = group
	}
	return issue, err
}

func userGroupIssuePath(operator, account, group string) string {
	return issueOperatorPrefix + operator + "/account/" + account + "/user-group/" + group
}

func (b *NatsBackend) pathUserGroupCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	op := d.Get("operator").(string)
	acc := d.Get("account").(string)
	group := d.Get("group").(string)

	issue, err := b.UserGroupIssue(ctx, req.Storage, op, acc, group)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		issue = &userGroupIssueEntry{}
	}

	createOperation := req.Operation == logical.CreateOperation

	if useSigningKey, ok := d.GetOk("useSigningKey"); ok {
		issue.UseSigningKey = useSigningKey.(string)
	} else if createOperation {
		issue.UseSigningKey = d.Get("useSigningKey").(string)
	}

	if expirationS, ok := d.GetOk("expirationS"); ok {
		issue.ExpirationS = expirationS.(int)
	} else if createOperation {
		issue.ExpirationS = d.Get("expirationS").(int)
	}

	if claimsTemplate, ok := d.GetOk("claimsTemplate"); ok {
		stm.MapToStruct(claimsTemplate.(map[string]any), &issue.ClaimsTemplate)
	}

	entry, err := logical.StorageEntryJSON(userGroupIssuePath(op, acc, group), issue)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *NatsBackend) pathUserGroupRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	op := d.Get("operator").(string)
	acc := d.Get("account").(string)
	group := d.Get("group").(string)

	path := userGroupIssuePath(op, acc, group)
	issue, err := getFromStorage[userGroupIssueEntry](ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		return nil, nil
	}

	data := map[string]any{}

	if issue.ExpirationS > 0 {
		data["expirationS"] = issue.ExpirationS
	}

	if issue.UseSigningKey != "" {
		data["useSigningKey"] = issue.UseSigningKey
	}

	if issue.ClaimsTemplate != nil {
		var claimTemplate map[string]any
		stm.StructToMap(&issue.ClaimsTemplate, &claimTemplate)
		data["claimsTemplate"] = claimTemplate
	}

	return &logical.Response{Data: data}, nil
}

func (b *NatsBackend) pathUserGroupExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	op := d.Get("operator").(string)
	acc := d.Get("account").(string)
	group := d.Get("group").(string)

	issue, err := b.UserGroupIssue(ctx, req.Storage, op, acc, group)
	if err != nil {
		return false, err
	}

	return issue != nil, nil
}

func (b *NatsBackend) pathUserGroupList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	operator := d.Get("operator").(string)
	account := d.Get("account").(string)
	after := d.Get("after").(string)
	limit := d.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	path := userGroupIssuePath(operator, account, "")
	entries, err := req.Storage.ListPage(ctx, path, after, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list user groups: %w", err)
	}

	return logical.ListResponse(filterSubkeys(entries)), nil
}

func (b *NatsBackend) pathUserGroupDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	operator := d.Get("operator").(string)
	account := d.Get("account").(string)
	group := d.Get("group").(string)

	path := userGroupIssuePath(operator, account, group)
	err := deleteFromStorage(ctx, req.Storage, path)
	if err != nil {
		return nil, fmt.Errorf("failed to delete user group: %w", err)
	}
	return nil, nil
}
