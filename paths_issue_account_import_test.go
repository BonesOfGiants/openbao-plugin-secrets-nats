package natsbackend

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"

	v1alpha1 "github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/account/v1alpha1"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
)

func TestCRUDAccountImportIssue(t *testing.T) {

	b, reqStorage := getTestBackend(t)

	t.Run("Test initial state of account import issuer", func(t *testing.T) {

		path := "issue/operator/op1/account/ac1/import/imp1"

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then create account issue to be able to create import issue
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
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("account import ReadOperation request failed, err: %s, resp %#v", err, resp)
		}

		if resp != nil {
			t.Fatalf("expected nil resp for account import ReadOperation resp: %#v", resp)
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
			Path:      "issue/operator/op1/account/acc1/import",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, resp.Data, map[string]any{})

	})

	t.Run("Test CRUD logic for account import issuer", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var path string = "issue/operator/op1/account/ac1/import/imp1"
		var request map[string]any
		var expected IssueAccountImportData
		var current IssueAccountImportData

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
		// That will be requested
		//////////////////////////
		stm.StructToMap(&IssueAccountImportParameters{}, &request)

		//////////////////////////
		// That will be expected - FIXED: JWT status should be false since no JWT is stored
		//////////////////////////
		expected = IssueAccountImportData{
			Operator: "op1",
			Account:  "ac1",
			Alias:    "imp1",
			Imports:  []v1alpha1.Import{},
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
		assert.Equal(t, expected, current)

		//////////////////////////
		// That will be requested
		//////////////////////////

		issue := IssueAccountImportData{
			Imports: []v1alpha1.Import{
				{
					Name:    "import_name",
					Account: "ac1",
					Subject: ">",
					Type:    "Service",
				},
			},
		}
		tmp, err := json.Marshal(issue)
		assert.Nil(t, err)
		json.Unmarshal(tmp, &request)

		//////////////////////////
		// That will be expected - FIXED: JWT status should still be false
		//////////////////////////
		expected = IssueAccountImportData{
			Operator: "op1",
			Account:  "ac1",
			Alias:    "imp1",
			Imports: []v1alpha1.Import{
				{
					Name:    "import_name",
					Account: "ac1",
					Subject: ">",
					Type:    "Service",
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

		//////////////////////////////////
		// List the issues
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/ac1/import",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Check, only one key is listed
		//////////////////////////////////
		assert.Equal(t, map[string]any{"keys": []string{"imp1"}}, resp.Data)

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
			t.Fatalf("account import ReadOperation request failed, err: %s, resp %#v", err, resp)
		}

		if resp != nil {
			t.Fatalf("expected nil resp for account import ReadOperation resp: %#v", resp)
		}

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

	t.Run("Test issued account for import inclusion", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var path string = "issue/operator/op1/account/ac1/import/imp1"
		var request map[string]any

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
		// That will be requested
		//////////////////////////
		imp := v1alpha1.Import{
			Name:    "import1",
			Account: "account-foo",
			Subject: ">",
			Type:    "Service",
		}

		stm.StructToMap(&IssueAccountImportParameters{
			Imports: []v1alpha1.Import{
				imp,
			},
		}, &request)

		/////////////////////////////
		// create the issue only
		// and read it
		/////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      request,
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
		containsImport(t, claims.Imports, imp)

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
		notContainsImport(t, claims.Imports, imp)
	})
}

func containsImport(t *testing.T, list jwt.Imports, cmp v1alpha1.Import) {
	for _, item := range list {
		typ := ""

		switch item.Type {
		case jwt.Stream:
			typ = "Stream"
		case jwt.Service:
			typ = "Service"
		}

		imp := v1alpha1.Import{
			Name:         item.Name,
			Subject:      string(item.Subject),
			Account:      item.Account,
			Token:        item.Token,
			LocalSubject: string(item.LocalSubject),
			Type:         typ,
			Share:        item.Share,
		}

		if assert.ObjectsAreEqual(cmp, imp) {
			return
		}
	}

	// do a Contains call for a more pretty error msg?
	assert.Contains(t, list, cmp)
}

func notContainsImport(t *testing.T, list jwt.Imports, cmp v1alpha1.Import) {
	for _, item := range list {
		typ := ""

		switch item.Type {
		case jwt.Stream:
			typ = "Stream"
		case jwt.Service:
			typ = "Service"
		}

		imp := v1alpha1.Import{
			Name:         item.Name,
			Subject:      string(item.Subject),
			Account:      item.Account,
			Token:        item.Token,
			LocalSubject: string(item.LocalSubject),
			Type:         typ,
			Share:        item.Share,
		}
		assert.NotEqual(t, cmp, imp)
	}
}
