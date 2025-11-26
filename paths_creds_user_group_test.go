package natsbackend

import (
	"context"
	"fmt"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCRUDUserGroupCreds(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test reading user creds without creating group", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/operator/op1/account/acc1/user-group/g1/user/u1",
			Storage:   reqStorage,
		})
		assert.Nil(t, err)
		assert.Nil(t, resp)
	})

	t.Run("Test user creds generation", func(t *testing.T) {
		// 1. Create operator nkey (this should already exist from other tests or setup)
		operatorNkeyReq := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "nkey/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]any{},
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
			Data:      map[string]any{},
		}
		resp, err = b.HandleRequest(context.Background(), accountNkeyReq)
		assert.NoError(t, err)
		if resp != nil {
			assert.False(t, resp.IsError())
		}

		// 3. Create user group issue template with basic claims
		userIssueReq := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/acc1/user-group/g1",
			Storage:   reqStorage,
			Data: map[string]any{
				"expirationS": int64(3600), // 1 hour
				"claimsTemplate": map[string]any{
					"aud": "test-audience", // Single string, not array
					"sub": "",              // Will be filled by the user's public key
					"nats": map[string]any{
						"pub": map[string]any{
							"allow": []string{"test.>"},
						},
						"sub": map[string]any{
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
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/operator/op1/account/acc1/user-group/g1/user/u1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.NotNil(t, resp.Data["creds"])
		assert.NotEmpty(t, resp.Data["creds"].(string))
		assert.Equal(t, "op1", resp.Data["operator"])
		assert.Equal(t, "acc1", resp.Data["account"])
		assert.Equal(t, "u1", resp.Data["user"])

		// Check that expiresAt is set
		assert.NotNil(t, resp.Data["expiresAt"])
		assert.IsType(t, int64(0), resp.Data["expiresAt"])
		assert.Greater(t, resp.Data["expiresAt"].(int64), int64(0))

		assert.NotNil(t, resp.Secret)
		assert.Equal(t, "op1", resp.Secret.InternalData["op"])
		assert.Equal(t, "acc1", resp.Secret.InternalData["acc"])
		assert.Equal(t, "user_creds", resp.Secret.InternalData["secret_type"])
		fmt.Printf("INTERNAL DATA: %+v", resp.Secret.InternalData)

		first_sub := resp.Secret.InternalData["sub"]

		// 5. Generate another credentials for the same user
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/operator/op1/account/acc1/user-group/g1/user/u1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.NotNil(t, resp.Data["creds"])
		assert.NotEmpty(t, resp.Data["creds"].(string))
		assert.Equal(t, "op1", resp.Data["operator"])
		assert.Equal(t, "acc1", resp.Data["account"])
		assert.Equal(t, "u1", resp.Data["user"])

		// Check that expiresAt is set
		assert.NotNil(t, resp.Data["expiresAt"])
		assert.IsType(t, int64(0), resp.Data["expiresAt"])
		assert.Greater(t, resp.Data["expiresAt"].(int64), int64(0))

		assert.NotNil(t, resp.Secret)
		assert.Equal(t, "op1", resp.Secret.InternalData["op"])
		assert.Equal(t, "acc1", resp.Secret.InternalData["acc"])
		assert.Equal(t, "user_creds", resp.Secret.InternalData["secret_type"])

		// the subs should be different between invocations, even for the same user
		assert.NotEqual(t, first_sub, resp.Secret.InternalData["sub"])
	})
}
