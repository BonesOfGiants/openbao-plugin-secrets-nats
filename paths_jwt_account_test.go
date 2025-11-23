package natsbackend

import (
	"context"
	"fmt"
	"testing"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stretchr/testify/assert"
)

func TestCRUDAccountJWTs(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test CRUD for account jwts", func(t *testing.T) {

		path := "jwt/operator/op1/account/Acc1"

		// first call read/delete/list without creating the key
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("operator signing nkey ReadOperation request failed, err: %s, resp %#v", err, resp)
		}

		if resp != nil {
			t.Fatalf("expected nil resp for operator signing nkey ReadOperation resp: %#v", resp)
		}

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/op1/account",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, resp.Data, map[string]any{})

		// then create the key and read it
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data: map[string]any{
				"jwt": createAccountJWT(),
			},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.True(t, resp.Data["jwt"].(string) != "")

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/op1/account/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]any{"keys": []string{"Acc1"}}, resp.Data)

		// then delete the key and read it
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("operator signing nkey ReadOperation request failed, err: %s, resp %#v", err, resp)
		}

		if resp != nil {
			t.Fatalf("expected nil resp for operator signing nkey ReadOperation resp: %#v", resp)
		}

		// then recreate the key and read and delete it
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data: map[string]any{
				"jwt": createAccountJWT(),
			},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
	})

	t.Run("Test CRUD for multiple account jwts", func(t *testing.T) {
		// create 3 keys
		for i := range 3 {
			path := fmt.Sprintf("jwt/operator/op1/account/acc%d", i)
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      path,
				Storage:   reqStorage,
				Data: map[string]any{
					"jwt": createAccountJWT(),
				},
			})
			assert.NoError(t, err)
			assert.False(t, resp.IsError())
		}

		// list the keys
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/op1/account",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]any{
			"keys": []string{"acc0", "acc1", "acc2"},
		}, resp.Data)

		// delete the keys
		for i := range 3 {
			path := fmt.Sprintf("jwt/operator/op1/account/acc%d", i)
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.DeleteOperation,
				Path:      path,
				Storage:   reqStorage,
			})
			assert.NoError(t, err)
			assert.False(t, resp.IsError())
		}

		// list the keys
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "jwt/operator/op1/account",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]any{}, resp.Data)

	})

	t.Run("Test account jwt wrong type", func(t *testing.T) {

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "jwt/operator/op1/account/acc1",
			Storage:   reqStorage,
			Data: map[string]any{
				"jwt": createOperatorJWT(),
			},
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "jwt/operator/op1/account/acc1",
			Storage:   reqStorage,
			Data: map[string]any{
				"jwt": "wrong jwt",
			},
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())
	})

	t.Run("Test account jwt by id", func(t *testing.T) {
		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// create an account issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/acc1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1/account/acc1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		var nkeyData NkeyData
		stm.MapToStruct(resp.Data, &nkeyData)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/acc1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		var expected JWTData
		var current JWTData

		stm.MapToStruct(resp.Data, &expected)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account-id/" + nkeyData.PublicKey,
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		stm.MapToStruct(resp.Data, &current)
		assert.Equal(t, expected, current)
	})

	t.Run("Test account jwt by id does not exist", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account-id/foo",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("operator signing nkey ReadOperation request failed, err: %s, resp %#v", err, resp)
		}

		if resp != nil {
			t.Fatalf("expected nil resp for operator signing nkey ReadOperation resp: %#v", resp)
		}
	})
}
