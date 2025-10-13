package natsbackend

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
)

func TestCRUDAccountRevocationIssue(t *testing.T) {

	b, reqStorage := getTestBackend(t)

	t.Run("Test initial state of account revocation issuer", func(t *testing.T) {

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

		// then create user issue to be able to create import issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then read user issue to be able to create import issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		userNkey := NkeyData{}
		stm.MapToStruct(resp.Data, &userNkey)

		path := "issue/operator/op1/account/ac1/revocation/" + userNkey.PublicKey

		// call read/delete/list without creating the issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.Equal(t, logical.ErrUnsupportedPath, err)
		assert.True(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/acc1/revocation",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, resp.Data, map[string]any{})

	})

	t.Run("Test CRUD logic for account revocation issuer", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var request map[string]any
		var expected IssueAccountRevocationData
		var current IssueAccountRevocationData

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

		// then create user issue to be able to create import issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then read user issue to be able to create import issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		userNkey := NkeyData{}
		stm.MapToStruct(resp.Data, &userNkey)

		path := "issue/operator/op1/account/ac1/revocation/" + userNkey.PublicKey

		//////////////////////////
		// That will be requested
		//////////////////////////
		stm.StructToMap(&IssueAccountImportParameters{}, &request)

		//////////////////////////
		// That will be expected - FIXED: JWT status should be false since no JWT is stored
		//////////////////////////
		expected = IssueAccountRevocationData{
			Operator: "op1",
			Account:  "ac1",
			Subject:  userNkey.PublicKey,
		}

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

		//////////////////////////////////
		// Compare the expected and current
		//////////////////////////////////
		stm.MapToStruct(resp.Data, &current)
		assert.Equal(t, expected.Operator, current.Operator)
		assert.Equal(t, expected.Account, current.Account)
		assert.Equal(t, expected.Subject, current.Subject)
		assert.NotZero(t, current.CreationTime)

		//////////////////////////////////
		// Update should fail as there are no parameters to update
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      request,
		})
		assert.Equal(t, logical.ErrUnsupportedOperation, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// List the issues
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/ac1/revocation",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Check, only one key is listed
		//////////////////////////////////
		assert.Equal(t, map[string]any{"keys": []string{userNkey.PublicKey}}, resp.Data)

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
		assert.Equal(t, logical.ErrUnsupportedPath, err)
		assert.True(t, resp.IsError())

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

	t.Run("Test issued account for revocation inclusion", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////

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

		// then create user issue to be able to create import issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then read user issue to be able to create import issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		userNkey := NkeyData{}
		stm.MapToStruct(resp.Data, &userNkey)

		path := "issue/operator/op1/account/ac1/revocation/" + userNkey.PublicKey

		/////////////////////////////
		// create the issue only
		// and read it
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

		//////////////////////////
		// read the account jwt
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/ac1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// Verify jwt response contains expected fields
		assert.Contains(t, resp.Data, "jwt")

		claims, err := jwt.DecodeAccountClaims(resp.Data["jwt"].(string))
		assert.NoError(t, err)
		assert.Contains(t, claims.Revocations, userNkey.PublicKey)

		/////////////////////////
		// Then delete the issue
		/////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		/////////////////////////////
		// ... and try to read again
		/////////////////////////////

		//////////////////////////
		// read the account jwt
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/ac1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// Verify jwt response contains expected fields
		assert.Contains(t, resp.Data, "jwt")

		claims, err = jwt.DecodeAccountClaims(resp.Data["jwt"].(string))
		assert.NoError(t, err)
		assert.NotContains(t, claims.Revocations, userNkey.PublicKey)
	})
}
