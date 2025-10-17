package natsbackend

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/hashicorp/go-hclog"
)

func getTestBackend(tb testing.TB) (*NatsBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*NatsBackend), config.StorageView
}
