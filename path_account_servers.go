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
	DefaultAccountServerClientName = "openbao"
)

type accountServerEntry struct {
	operatorId

	Suspend        bool          `json:"suspend"`
	Servers        []string      `json:"servers"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	MaxReconnects  int           `json:"max_reconnects"`
	ReconnectWait  time.Duration `json:"reconnect_wait"`

	AccountServerClientName string `json:"client_name"`

	// Whether to disable account lookup request support
	DisableAccountLookup bool `json:"disable_lookups"`

	DisableAccountUpdate bool `json:"disable_updates"`
	DisableAccountDelete bool `json:"disable_deletes"`

	Status accountServerStatus `json:"status"`
}

func (e *accountServerEntry) IsSuspended() bool {
	return e.Suspend || (e.DisableAccountLookup && e.DisableAccountUpdate && e.DisableAccountDelete)
}

type AccountServerStatus string

const (
	AccountServerStatusCreated   AccountServerStatus = "created"
	AccountServerStatusActive    AccountServerStatus = "active"
	AccountServerStatusSuspended AccountServerStatus = "suspended"
	AccountServerStatusError     AccountServerStatus = "error"
)

type accountServerStatus struct {
	LastStatusChange time.Time           `json:"last_status_change"`
	Status           AccountServerStatus `json:"status"`
	Error            string              `json:"error,omitempty"`
}

var (
	DefaultSyncUserTtl = 5 * time.Minute
)

func pathConfigAccountServer(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: accountServersPathPrefix + operatorRegex + "$",
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
					Description: "The name to use for sync operations. Defaults to '" + DefaultAccountServerClientName + "'.",
					Default:     DefaultAccountServerClientName,
				},
				"disable_lookups": {
					Type:        framework.TypeBool,
					Description: "Whether to disable responding to account lookup requests from the NATS cluster.",
					Default:     false,
				},
				"disable_updates": {
					Type:        framework.TypeBool,
					Description: "Whether to disable sending account updates to the NATS cluster.",
					Default:     false,
				},
				"disable_deletes": {
					Type:        framework.TypeBool,
					Description: "Whether to disable sending account deletes to the NATS cluster.",
					Default:     false,
				},
				"sync_now": {
					Type:        framework.TypeBool,
					Description: "Whether to immediately sync all accounts after creating/updating the account server.",
					Default:     true,
				},
			},
			ExistenceCheck: b.pathAccountServerExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAccountServerCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAccountServerCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathAccountServerRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathAccountServerDelete,
				},
			},
			HelpSynopsis: "Manage configuration for the account server for an operator.",
		},
	}
}

func (b *backend) AccountServer(ctx context.Context, s logical.Storage, id operatorId) (*accountServerEntry, error) {
	var sync *accountServerEntry
	err := get(ctx, s, id.accountServerPath(), &sync)
	if sync != nil {
		sync.operatorId = id
	}
	return sync, err
}

func NewAccountServer(id operatorId) *accountServerEntry {
	return &accountServerEntry{
		operatorId:              id,
		AccountServerClientName: DefaultAccountServerClientName,
		Status: accountServerStatus{
			Status: AccountServerStatusCreated,
		},
	}
}

func (b *backend) pathAccountServerCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
	sync, err := b.AccountServer(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if sync == nil {
		sync = NewAccountServer(id)
		syncDirty = true
	}

	oldSuspend := sync.IsSuspended()

	if suspend, ok := d.GetOk("suspend"); ok {
		syncDirty = syncDirty || (sync.Suspend != suspend)
		sync.Suspend = suspend.(bool)
	}

	if serversRaw, ok := d.GetOk("servers"); ok {
		sync.Servers = serversRaw.([]string)
	}

	if len(sync.Servers) == 0 {
		return logical.ErrorResponse("must provide at least one server"), nil
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

	if disableAccountLookup, ok := d.GetOk("disable_lookups"); ok {
		syncDirty = syncDirty || (sync.DisableAccountLookup != disableAccountLookup)
		sync.DisableAccountLookup = disableAccountLookup.(bool)
	}

	if disableAccountUpdate, ok := d.GetOk("disable_updates"); ok {
		syncDirty = syncDirty || (sync.DisableAccountUpdate != disableAccountUpdate)
		sync.DisableAccountUpdate = disableAccountUpdate.(bool)
	}

	if disableAccountDelete, ok := d.GetOk("disable_deletes"); ok {
		syncDirty = syncDirty || (sync.DisableAccountDelete != disableAccountDelete)
		sync.DisableAccountDelete = disableAccountDelete.(bool)
	}

	oldSyncUserName := sync.AccountServerClientName
	if syncUserName, ok := d.GetOk("sync_user_name"); ok {
		syncDirty = syncDirty || (oldSyncUserName != syncUserName)
		sync.AccountServerClientName = syncUserName.(string)
	}

	syncNow := d.Get("sync_now").(bool)

	newSuspend := sync.IsSuspended()
	if newSuspend && oldSuspend != newSuspend {
		if sync.Status.Status != AccountServerStatusSuspended {
			sync.Status.Status = AccountServerStatusSuspended
			sync.Status.LastStatusChange = time.Now()
		}
	} else {
		if sync.Status.Status != AccountServerStatusCreated {
			sync.Status.Status = AccountServerStatusCreated
			sync.Status.LastStatusChange = time.Now()
		}
	}

	err = storeInStorage(ctx, req.Storage, id.accountServerPath(), sync)
	if err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	// get account server to ensure it exists for lookups
	_, err = b.startAccountServer(ctx, id, syncDirty)
	if err != nil {
		return nil, err
	}

	// todo investigate sync having issues when servers are changed
	// especially changing from a broken to a working server url
	// it feels like the sync is getting stuck
	if syncNow && syncDirty && !sync.IsSuspended() {
		// attempt an immediate sync
		syncErrs, err := b.syncOperatorAccounts(ctx, req.Storage, operator.operatorId)
		if err != nil {
			resp.AddWarning(fmt.Sprintf("failed to sync accounts: %s", err))
		} else if syncErrs != nil {
			for _, v := range slices.Sorted(maps.Keys(syncErrs)) {
				resp.AddWarning(fmt.Sprintf("failed to sync account %q: %s", v, syncErrs[v]))
			}
		}
	}

	return resp, nil
}

func (b *backend) pathAccountServerRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	sync, err := b.AccountServer(ctx, req.Storage, OperatorIdField(d))
	if err != nil {
		return nil, err
	}
	if sync == nil {
		return nil, nil
	}

	status := map[string]any{
		"status": sync.Status.Status,
	}

	if sync.Status.LastStatusChange != (time.Time{}) {
		status["last_status_change"] = sync.Status.LastStatusChange
	}

	if sync.Status.Error != "" {
		status["error"] = sync.Status.Error
	}

	data := map[string]any{
		"servers":        sync.Servers,
		"sync_user_name": sync.AccountServerClientName,
		"status":         status,
	}

	if sync.ConnectTimeout > 0 {
		data["connect_timeout"] = int(sync.ConnectTimeout.Seconds())
	}

	if sync.MaxReconnects > 0 {
		data["max_reconnects"] = sync.MaxReconnects
	}

	if sync.ReconnectWait > 0 {
		data["reconnect_wait"] = int(sync.ReconnectWait.Seconds())
	}

	if sync.DisableAccountLookup {
		data["disable_lookups"] = sync.DisableAccountLookup
	}

	if sync.DisableAccountUpdate {
		data["disable_updates"] = sync.DisableAccountUpdate
	}

	if sync.DisableAccountDelete {
		data["disable_deletes"] = sync.DisableAccountDelete
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathAccountServerExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	sync, err := b.AccountServer(ctx, req.Storage, OperatorIdField(d))
	if err != nil {
		return false, err
	}

	return sync != nil, nil
}

func (b *backend) pathAccountServerDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	err = req.Storage.Delete(ctx, OperatorIdField(d).accountServerPath())
	if err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return nil, nil
}
