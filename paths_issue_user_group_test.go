package natsbackend

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stretchr/testify/assert"
)

func TestCRUDUserGroupIssue(t *testing.T) {

	b, reqStorage := getTestBackend(t)

	t.Run("Test initial state of user group issuer", func(t *testing.T) {

		path := "issue/operator/op1/account/ac1/user-group/g1"

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then create account issue to be able to create user issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// call read/delete/list without creating the issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.Nil(t, err)
		assert.Nil(t, resp)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.Nil(t, err)
		assert.Nil(t, resp)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/acc1/user-group",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, resp.Data, map[string]any{})
	})

	t.Run("Test CRUD logic for user group issuer", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var path string = "issue/operator/op1/account/ac1/user-group/g1"
		var expected map[string]any

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then create account issue to be able to create user issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// That will be expected - FIXED: JWT status should be false since no JWT is stored
		//////////////////////////
		expected = map[string]any{}

		/////////////////////////////
		// create the issue only
		// with defaults and read it
		/////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

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

		assert.Equal(t, expected, resp.Data)

		//////////////////////////
		// That will be expected - FIXED: JWT status should still be false
		//////////////////////////
		expected = map[string]any{
			"claimsTemplate": map[string]any{
				"user": map[string]any{
					"subs": float64(1),
				},
			},
		}

		//////////////////////////////////
		// Update with the requested data
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      expected,
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
		assert.EqualValues(t, expected, resp.Data)

		//////////////////////////////////
		// List the issues
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/ac1/user-group",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Check, only one key is listed
		//////////////////////////////////
		assert.Equal(t, map[string]any{"keys": []string{"g1"}}, resp.Data)

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
		assert.Nil(t, err)
		assert.Nil(t, resp)

		//////////////////////////
		// Then recreate the key
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
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
