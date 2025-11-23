package natsbackend

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type operatorSyncConfigEntry struct {
	Servers        []string `json:"servers"`
	ConnectTimeout int      `json:"connectTimeout"`
	MaxReconnects  int      `json:"maxReconnects"`
	ReconnectWait  int      `json:"reconnectWait"`
	// Whether to continue with a deletion if the delete fails to sync to the target server
	IgnoreSyncErrorsOnDelete bool `json:"ignoreSyncErrorsOnDelete"`
}

// IssueOperatorSyncParameters is the user facing interface for configuring a user issue.
// Using pascal case on purpose.
// +k8s:deepcopy-gen=true
type IssueOperatorSyncParameters struct {
	Operator       string   `json:"operator"`
	Servers        []string `json:"servers"`
	ConnectTimeout int      `json:"connectTimeout"`
	MaxReconnects  int      `json:"maxReconnects"`
	ReconnectWait  int      `json:"reconnectWait"`
}

func pathOperatorSyncIssue(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/sync$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: `The operator identifier.`,
					Required:    true,
				},
				"servers": {
					Type:        framework.TypeStringSlice,
					Description: "A list of nats servers to connect to.",
					Required:    false,
				},
				"connectTimeout": {
					Type:        framework.TypeInt,
					Description: "Connection timeout for the nats connection.",
					Required:    false,
				},
				"maxReconnects": {
					Type:        framework.TypeInt,
					Description: "Maximum reconnects for the nats connection.",
					Required:    false,
				},
				"reconnectWait": {
					Type:        framework.TypeInt,
					Description: "Reconnect wait for the nats connection.",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathOperatorSyncIssueExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathOperatorSyncCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathOperatorSyncCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadOperatorSyncIssue,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteOperatorSyncIssue,
				},
			},
			HelpSynopsis: `Manages sync config for operator issue.`,
		},
	}
}

func (b *NatsBackend) pathOperatorSyncCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	op := d.Get("operator").(string)

	exists, err := b.pathOperatorIssueExistenceCheck(ctx, req, d)
	if err != nil {
		return nil, err
	}
	if !exists {
		return logical.ErrorResponse("operator does not exist"), err
	}

	path := operatorSyncPath(op)
	issue, err := getFromStorage[operatorSyncConfigEntry](ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		issue = &operatorSyncConfigEntry{}
	}

	createOperation := req.Operation == logical.CreateOperation

	if serversRaw, ok := d.GetOk("servers"); ok {
		issue.Servers = serversRaw.([]string)
	} else if createOperation {
		return logical.ErrorResponse("must provide at least one server"), err
	}

	if connectTimeout, ok := d.GetOk("connectTimeout"); ok {
		issue.ConnectTimeout = connectTimeout.(int)
	} else if createOperation {
		issue.ConnectTimeout = d.Get("connectTimeout").(int)
	}

	if maxReconnects, ok := d.GetOk("maxReconnects"); ok {
		issue.MaxReconnects = maxReconnects.(int)
	} else if createOperation {
		issue.MaxReconnects = d.Get("maxReconnects").(int)
	}

	if reconnectWait, ok := d.GetOk("reconnectWait"); ok {
		issue.ReconnectWait = reconnectWait.(int)
	} else if createOperation {
		issue.ReconnectWait = d.Get("reconnectWait").(int)
	}

	entry, err := logical.StorageEntryJSON(path, issue)
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

func (b *NatsBackend) pathReadOperatorSyncIssue(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	op := d.Get("operator").(string)

	path := operatorSyncPath(op)
	issue, err := getFromStorage[operatorSyncConfigEntry](ctx, req.Storage, path)
	if err != nil || issue == nil {
		return nil, err
	}

	data := map[string]any{
		"servers":        issue.Servers,
		"connectTimeout": issue.ConnectTimeout,
		"maxReconnects":  issue.MaxReconnects,
		"reconnectWait":  issue.ReconnectWait,
	}

	return &logical.Response{Data: data}, nil
}

func (b *NatsBackend) pathOperatorSyncIssueExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	op := d.Get("operator").(string)

	path := operatorSyncPath(op)
	issue, err := getFromStorage[operatorSyncConfigEntry](ctx, req.Storage, path)
	if err != nil {
		return false, err
	}

	return issue != nil, nil
}

func (b *NatsBackend) pathDeleteOperatorSyncIssue(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	op := d.Get("operator").(string)

	path := operatorSyncPath(op)
	err := deleteFromStorage(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func operatorSyncPath(operator string) string {
	return issueOperatorPrefix + operator + "/sync"
}
