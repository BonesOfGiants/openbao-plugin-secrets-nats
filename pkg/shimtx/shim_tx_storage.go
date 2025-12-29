package shimtx

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// StartTxStorageWithShim can begin a longer-running transaction by modifying the `Storage` field of the `req` param.
// It returns a rollback function to defer in the calling context.
//
// If the storage backend does not support transactions, StartTxStorageWithShim will fall back
// to tracking writes and deletes in memory.
func StartTxStorageWithShim(ctx context.Context, req *logical.Request) (func(), error) {
	if txnStorage, ok := req.Storage.(logical.TransactionalStorage); ok {
		txn, err := txnStorage.BeginTx(ctx)
		if err != nil {
			return nil, err
		}
		req.OriginalStorage = req.Storage
		req.Storage = txn
		return func() { txn.Rollback(ctx) }, nil
	} else {
		txn := NewInmemTransaction(req.Storage)
		req.OriginalStorage = req.Storage
		req.Storage = txn
		return func() { txn.Rollback(ctx) }, nil
	}
}
