package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stretchr/testify/assert"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
)

func TestCRUDOperatorSyncConfig(t *testing.T) {

	b, reqStorage := getTestBackend(t)

	t.Run("Test initial state of sync config", func(t *testing.T) {
		// call read/delete/list without creating the issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "issue/operator/op1/sync",
			Storage:   reqStorage,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("sync config ReadOperation request failed, err: %s, resp %#v", err, resp)
		}

		if resp != nil {
			t.Fatalf("expected nil resp for sync config ReadOperation resp: %#v", resp)
		}

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "issue/operator/op1/sync",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

	})

	t.Run("Test CRUD logic for sync config issuer", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var path string = "issue/operator/op1/sync"
		var request map[string]any
		var expected operatorSyncConfigEntry
		var current operatorSyncConfigEntry

		// first create operator issue to be able to create sync config
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then create sync config
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/sync",
			Storage:   reqStorage,
			Data: map[string]any{
				"servers": []string{"nats://localhost:4222"},
			},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		expected = operatorSyncConfigEntry{
			Servers: []string{"nats://localhost:4222"},
		}

		//////////////////////////
		// read the created issue
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Compare the expected and current
		//////////////////////////////////
		stm.MapToStruct(resp.Data, &current)
		assert.Equal(t, expected, current)

		//////////////////////////
		// That will be requested
		//////////////////////////

		config := operatorSyncConfigEntry{
			Servers: []string{
				"nats://localhost:8080",
			},
			ConnectTimeout: 10,
			MaxReconnects:  10,
			ReconnectWait:  10,
		}
		tmp, err := json.Marshal(config)
		assert.Nil(t, err)
		json.Unmarshal(tmp, &request)

		//////////////////////////
		// That will be expected
		//////////////////////////
		expected = operatorSyncConfigEntry{
			Servers: []string{
				"nats://localhost:8080",
			},
			ConnectTimeout: 10,
			MaxReconnects:  10,
			ReconnectWait:  10,
		}

		//////////////////////////////////
		// Update with the requested data
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      request,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Read the updated data back
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Compare the expected and current
		//////////////////////////////////
		stm.MapToStruct(resp.Data, &current)

		assert.Equal(t, expected, current)

		/////////////////////////
		// Then delete the key
		/////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// ... and try to read it
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("sync config ReadOperation request failed, err: %s, resp %#v", err, resp)
		}

		if resp != nil {
			t.Fatalf("expected nil resp for sync config ReadOperation resp: %#v", resp)
		}

		//////////////////////////
		// Then recreate the key
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data: map[string]any{
				"servers": []string{"nats://localhost:4222"},
			},
		})
		fmt.Printf("resp: %+v", resp)
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// ... read the key
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// ... and delete again
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
	})
}
