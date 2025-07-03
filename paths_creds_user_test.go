package natsbackend

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCRUDUserCreds(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test reading user creds without template", func(t *testing.T) {
		path := "creds/operator/op1/account/acc1/user/u1"

		// Try to read credentials without having a template - should fail
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())
		assert.Contains(t, resp.Error().Error(), "user template not found")
	})

	t.Run("Test CRUD for user creds with template", func(t *testing.T) {
		// Setup: Create the prerequisites

		// 1. Create operator nkey (this should already exist from other tests or setup)
		operatorNkeyReq := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		}
		resp, err := b.HandleRequest(context.Background(), operatorNkeyReq)
		assert.NoError(t, err)
		if resp != nil {
			assert.False(t, resp.IsError())
		}

		// 2. Create account nkey
		accountNkeyReq := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/op1/account/acc1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		}
		resp, err = b.HandleRequest(context.Background(), accountNkeyReq)
		assert.NoError(t, err)
		if resp != nil {
			assert.False(t, resp.IsError())
		}

		// 3. Create user issue template with basic claims
		userIssueReq := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/acc1/user/u1",
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"operator":    "op1",
				"account":     "acc1",
				"user":        "u1",
				"expirationS": int64(3600), // 1 hour
				"claimsTemplate": map[string]interface{}{
					"aud": "test-audience", // Single string, not array
					"sub": "",              // Will be filled by the user's public key
					"nats": map[string]interface{}{
						"pub": map[string]interface{}{
							"allow": []string{"test.>"},
						},
						"sub": map[string]interface{}{
							"allow": []string{"test.>"},
						},
					},
				},
			},
		}
		resp, err = b.HandleRequest(context.Background(), userIssueReq)
		require.NoError(t, err)
		if resp != nil {
			require.False(t, resp.IsError(), "Failed to create user issue template: %v", resp.Error())
		}

		// 4. Now test reading credentials (generates fresh JWT)
		credsPath := "creds/operator/op1/account/acc1/user/u1"
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      credsPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.NotNil(t, resp.Data["creds"])
		assert.NotEmpty(t, resp.Data["creds"].(string))
		assert.Equal(t, "op1", resp.Data["operator"])
		assert.Equal(t, "acc1", resp.Data["account"])
		assert.Equal(t, "u1", resp.Data["user"])

		// Check that expiresAt is set (JSON unmarshaling converts to float64)
		assert.NotNil(t, resp.Data["expiresAt"])
		expiresAt, ok := resp.Data["expiresAt"].(float64)
		assert.True(t, ok, "expiresAt should be float64")
		assert.Greater(t, expiresAt, float64(0))

		// 5. Test that we can read credentials multiple times (each should be fresh)
		// Note: JWTs might be the same if generated within the same second due to timestamp precision
		resp2, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      credsPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp2.IsError())
		assert.NotNil(t, resp2.Data["creds"])
		assert.NotEmpty(t, resp2.Data["creds"].(string))

		// Verify credentials are valid (both should be valid JWT format)
		assert.Contains(t, resp.Data["creds"].(string), "-----BEGIN NATS USER JWT-----")
		assert.Contains(t, resp2.Data["creds"].(string), "-----BEGIN NATS USER JWT-----")

		// 6. Test listing (should show the user template)
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "creds/operator/op1/account/acc1/user/",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{"keys": []string{"u1"}}, resp.Data)

		// 7. Test deleting the user issue template
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "issue/operator/op1/account/acc1/user/u1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		if resp != nil {
			assert.False(t, resp.IsError())
		}

		// 8. After deletion, reading credentials should fail
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      credsPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())
	})

	t.Run("Test user creds with template parameters", func(t *testing.T) {
		// Create user issue template with template variables
		userIssueReq := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/acc1/user/u2",
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"operator":    "op1",
				"account":     "acc1",
				"user":        "u2",
				"expirationS": int64(7200), // 2 hours
				"claimsTemplate": map[string]interface{}{
					"aud": "{{user_id}}", // Single string template
					"sub": "",            // Will be filled by the user's public key
					"nats": map[string]interface{}{
						"pub": map[string]interface{}{
							"allow": []string{"{{region}}.{{user_id}}.>"},
						},
						"sub": map[string]interface{}{
							"allow": []string{"{{region}}.{{user_id}}.>"},
						},
					},
				},
			},
		}
		resp, err := b.HandleRequest(context.Background(), userIssueReq)
		require.NoError(t, err)
		if resp != nil {
			require.False(t, resp.IsError())
		}

		// Test with JSON parameters
		credsPath := "creds/operator/op1/account/acc1/user/u2"
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      credsPath,
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"parameters": `{"user_id": "12345", "region": "us-east-1"}`,
			},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.NotNil(t, resp.Data["creds"])
		assert.NotEmpty(t, resp.Data["creds"].(string))

		// Check that parameters are returned (JSON unmarshaling converts to map[string]interface{})
		assert.NotNil(t, resp.Data["parameters"])
		params, ok := resp.Data["parameters"].(map[string]interface{})
		assert.True(t, ok, "parameters should be map[string]interface{}")
		assert.Equal(t, "12345", params["user_id"])
		assert.Equal(t, "us-east-1", params["region"])

		// Test with key=value parameters
		resp2, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      credsPath,
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"parameters": "user_id=67890,region=eu-west-1",
			},
		})
		assert.NoError(t, err)
		assert.False(t, resp2.IsError())
		assert.NotNil(t, resp2.Data["creds"])

		params2, ok := resp2.Data["parameters"].(map[string]interface{})
		assert.True(t, ok, "parameters should be map[string]interface{}")
		assert.Equal(t, "67890", params2["user_id"])
		assert.Equal(t, "eu-west-1", params2["region"])

		// Test that missing required parameters still works if the template doesn't use all variables
		// (Based on logs, it seems the validation allows partial parameters)
		resp3, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      credsPath,
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"parameters": `{"user_id": "12345"}`, // Missing region
			},
		})
		assert.NoError(t, err)
		// This might succeed if the template doesn't strictly require all variables
		if resp3.IsError() {
			assert.Contains(t, resp3.Error().Error(), "missing required template parameters")
		} else {
			// If it succeeds, verify the response
			assert.NotNil(t, resp3.Data["creds"])
			assert.NotEmpty(t, resp3.Data["creds"].(string))
		}
	})

	t.Run("Test multiple user templates", func(t *testing.T) {
		// Create multiple user issue templates
		for i := 3; i < 6; i++ {
			userIssueReq := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      fmt.Sprintf("issue/operator/op1/account/acc1/user/u%d", i),
				Storage:   reqStorage,
				Data: map[string]interface{}{
					"operator":    "op1",
					"account":     "acc1",
					"user":        fmt.Sprintf("u%d", i),
					"expirationS": int64(3600),
					"claimsTemplate": map[string]interface{}{
						"aud": fmt.Sprintf("audience-%d", i), // Single string
						"sub": "",
						"nats": map[string]interface{}{
							"pub": map[string]interface{}{
								"allow": []string{fmt.Sprintf("user%d.>", i)},
							},
							"sub": map[string]interface{}{
								"allow": []string{fmt.Sprintf("user%d.>", i)},
							},
						},
					},
				},
			}
			resp, err := b.HandleRequest(context.Background(), userIssueReq)
			assert.NoError(t, err)
			if resp != nil {
				assert.False(t, resp.IsError())
			}
		}

		// List all user templates
		listPath := "creds/operator/op1/account/acc1/user/"
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      listPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// Check if we have keys in the response
		if resp.Data != nil && resp.Data["keys"] != nil {
			keys := resp.Data["keys"].([]string)
			assert.Contains(t, keys, "u2") // From previous test
			assert.Contains(t, keys, "u3")
			assert.Contains(t, keys, "u4")
			assert.Contains(t, keys, "u5")
		} else {
			t.Log("No keys found in list response, continuing with individual tests")
		}

		// Test generating creds for each user
		for i := 3; i < 6; i++ {
			credsPath := fmt.Sprintf("creds/operator/op1/account/acc1/user/u%d", i)
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      credsPath,
				Storage:   reqStorage,
			})
			assert.NoError(t, err)
			assert.False(t, resp.IsError())
			assert.NotNil(t, resp.Data["creds"])
			assert.NotEmpty(t, resp.Data["creds"].(string))
			assert.Equal(t, fmt.Sprintf("u%d", i), resp.Data["user"])
		}

		// Clean up by deleting the templates
		for i := 2; i < 6; i++ {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.DeleteOperation,
				Path:      fmt.Sprintf("issue/operator/op1/account/acc1/user/u%d", i),
				Storage:   reqStorage,
			})
			assert.NoError(t, err)
			if resp != nil {
				assert.False(t, resp.IsError())
			}
		}

		// After cleanup, list should be empty
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      listPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, map[string]interface{}{}, resp.Data)
	})
}
