package natsbackend

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/shimtx"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	DefaultSyncUserName = "openbao"
)

type operatorSyncConfigEntry struct {
	operatorId

	Suspend        bool          `json:"suspend"`
	Servers        []string      `json:"servers"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	MaxReconnects  int           `json:"max_reconnects"`
	ReconnectWait  time.Duration `json:"reconnect_wait"`

	SyncUserName string `json:"sync_user_name"`

	// Whether to abort a deletion if the delete fails to sync
	IgnoreSyncErrorsOnDelete bool `json:"ignore_sync_errors_on_delete"`

	Status operatorSyncStatus `json:"status"`
}

type OperatorSyncStatus string

const (
	OperatorSyncStatusCreated   OperatorSyncStatus = "created"
	OperatorSyncStatusActive    OperatorSyncStatus = "active"
	OperatorSyncStatusSuspended OperatorSyncStatus = "suspended"
	OperatorSyncStatusError     OperatorSyncStatus = "error"
)

type operatorSyncStatus struct {
	LastSyncTime time.Time          `json:"last_sync_time"`
	Status       OperatorSyncStatus `json:"status"`
	Errors       []string           `json:"errors,omitempty"`
}

var (
	DefaultSyncUserTtl = 5 * time.Minute
)

func pathConfigOperatorSync(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: syncConfigPathPrefix + operatorRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"servers": {
					Type:        framework.TypeStringSlice,
					Description: "A list of nats servers to connect to.",
					Required:    false,
				},
				"suspend": {
					Type:        framework.TypeBool,
					Description: "Whether to temporarily disabled the syncing of accounts.",
					Required:    false,
				},
				"connect_timeout": {
					Type:        framework.TypeDurationSecond,
					Description: "Connection timeout for the nats connection.",
					Required:    false,
				},
				"max_reconnects": {
					Type:        framework.TypeInt,
					Description: "Maximum reconnects for the nats connection.",
					Required:    false,
				},
				"reconnect_wait": {
					Type:        framework.TypeDurationSecond,
					Description: "Reconnect wait for the nats connection.",
					Required:    false,
				},
				"sync_user_name": {
					Type:        framework.TypeString,
					Description: "The name to use for sync operations. Defaults to '" + DefaultSyncUserName + "'.",
					Default:     DefaultSyncUserName,
				},
				"ignore_sync_errors_on_delete": {
					Type:        framework.TypeBool,
					Description: "Whether to abort a deletion if the delete fails to sync.",
				},
				"sync_now": {
					Type:        framework.TypeBool,
					Description: "Whether to attempt a sync immediately after creating/updating the sync config.",
					Default:     true,
				},
			},
			ExistenceCheck: b.pathOperatorSyncExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathOperatorSyncCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathOperatorSyncCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathOperatorSyncRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathOperatorSyncDelete,
				},
			},
			HelpSynopsis: "Manage configuration for an operator's sync job.",
		},
	}
}

func (b *backend) OperatorSync(ctx context.Context, s logical.Storage, id operatorId) (*operatorSyncConfigEntry, error) {
	operator, err := getFromStorage[operatorSyncConfigEntry](ctx, s, id.syncConfigPath())
	if operator != nil {
		operator.operatorId = id
	}
	return operator, err
}

func NewOperatorSync(id operatorId) *operatorSyncConfigEntry {
	return &operatorSyncConfigEntry{
		operatorId:   id,
		SyncUserName: DefaultSyncUserName,
		Status: operatorSyncStatus{
			Status: OperatorSyncStatusCreated,
		},
	}
}

func (b *backend) pathOperatorSyncCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := OperatorIdField(d)

	operator, err := b.Operator(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if operator == nil {
		return logical.ErrorResponse("operator %q does not exist", id.op), nil
	}

	sysAccount, err := b.Account(ctx, req.Storage, id.accountId(operator.SysAccountName))
	if err != nil {
		return nil, err
	}
	if sysAccount == nil {
		return logical.ErrorResponse("a system account is required for sync: operator %q system account %q does not exist", id.op, operator.SysAccountName), nil
	}

	syncDirty := false
	sync, err := b.OperatorSync(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if sync == nil {
		sync = NewOperatorSync(id)
		syncDirty = true
	}

	if suspend, ok := d.GetOk("suspend"); ok {
		syncDirty = syncDirty || (sync.Suspend != suspend)
		sync.Suspend = suspend.(bool)
	}

	if serversRaw, ok := d.GetOk("servers"); ok {
		sync.Servers = serversRaw.([]string)
	}

	if connectTimeout, ok := d.GetOk("connect_timeout"); ok {
		t := time.Duration(connectTimeout.(int)) * time.Second
		syncDirty = syncDirty || (sync.ConnectTimeout != t)
		sync.ConnectTimeout = t
	}

	if maxReconnects, ok := d.GetOk("max_reconnects"); ok {
		syncDirty = syncDirty || (sync.MaxReconnects != maxReconnects)
		sync.MaxReconnects = maxReconnects.(int)
	}

	if reconnectWait, ok := d.GetOk("reconnect_wait"); ok {
		t := time.Duration(reconnectWait.(int)) * time.Second
		syncDirty = syncDirty || (sync.ReconnectWait != t)
		sync.ReconnectWait = t
	}

	if ignoreSyncErrorsOnDelete, ok := d.GetOk("ignore_sync_errors_on_delete"); ok {
		syncDirty = syncDirty || (sync.IgnoreSyncErrorsOnDelete != ignoreSyncErrorsOnDelete)
		sync.IgnoreSyncErrorsOnDelete = ignoreSyncErrorsOnDelete.(bool)
	}

	oldSyncUserName := sync.SyncUserName
	if syncUserName, ok := d.GetOk("sync_user_name"); ok {
		syncDirty = syncDirty || (oldSyncUserName != syncUserName)
		sync.SyncUserName = syncUserName.(string)
	}

	syncNow := d.Get("sync_now").(bool)

	if len(sync.Servers) == 0 {
		return logical.ErrorResponse("must provide at least one server"), nil
	}

	err = storeInStorage(ctx, req.Storage, id.syncConfigPath(), sync)
	if err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	if syncDirty {
		accountSync := b.popAccountServer(id.op)
		if accountSync != nil {
			accountSync.CloseConnection()
		}
	}

	// get account server to ensure it exists for lookups
	_, err = b.getAccountServer(ctx, req.Storage, operator.operatorId)
	if err != nil {
		return nil, err
	}

	// todo investigate sync having issues when servers are changed
	// especially changing from a broken to a working server url
	// it feels like the sync is getting stuck
	if syncNow && syncDirty && !sync.Suspend {
		// attempt an immediate sync
		syncErrs, syncErr := b.syncOperatorAccounts(ctx, req.Storage, operator.operatorId)
		if syncErr != nil {
			resp.AddWarning(fmt.Sprintf("failed to sync accounts: %s", syncErr))
		} else if syncErrs != nil {
			for _, v := range slices.Sorted(maps.Keys(syncErrs)) {
				resp.AddWarning(fmt.Sprintf("failed to sync account %q: %s", v, syncErrs[v]))
			}
		}
	}

	return resp, nil
}

func (b *backend) pathOperatorSyncRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	sync, err := b.OperatorSync(ctx, req.Storage, OperatorIdField(d))
	if err != nil {
		return nil, err
	}
	if sync == nil {
		return nil, nil
	}

	status := map[string]any{
		"status": sync.Status.Status,
	}

	if sync.Status.LastSyncTime != (time.Time{}) {
		status["last_sync_time"] = sync.Status.LastSyncTime
	}

	if len(sync.Status.Errors) > 0 {
		status["errors"] = sync.Status.Errors
	}

	data := map[string]any{
		"servers":                      sync.Servers,
		"connect_timeout":              int(sync.ConnectTimeout.Seconds()),
		"max_reconnects":               sync.MaxReconnects,
		"reconnect_wait":               int(sync.ReconnectWait.Seconds()),
		"ignore_sync_errors_on_delete": sync.IgnoreSyncErrorsOnDelete,
		"sync_user_name":               sync.SyncUserName,
		"status":                       status,
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathOperatorSyncExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	sync, err := b.OperatorSync(ctx, req.Storage, OperatorIdField(d))
	if err != nil {
		return false, err
	}

	return sync != nil, nil
}

func (b *backend) pathOperatorSyncDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	err = deleteFromStorage(ctx, req.Storage, OperatorIdField(d).syncConfigPath())
	if err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return nil, nil
}
