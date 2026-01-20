package natsbackend

import (
	"errors"
	"testing"
	"testing/synctest"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackend_User_Config(t *testing.T) {

	testCases := []struct {
		name     string
		data     map[string]any
		expected map[string]any
		err      error
	}{
		{
			name: "invalid claims",
			data: map[string]any{
				"claims": fromUserClaims(
					&jwt.User{
						UserPermissionLimits: jwt.UserPermissionLimits{
							Permissions: jwt.Permissions{
								Pub: jwt.Permission{
									Allow: []string{""},
								},
							},
						},
					},
				),
			},
			err: errors.New(`validation error: subject cannot be empty`),
		},
		{
			name:     "default behavior",
			data:     map[string]any{},
			expected: map[string]any{},
		},
		{
			name: "ttl string",
			data: map[string]any{
				"creds_max_ttl":     "1h",
				"creds_default_ttl": "1h",
			},
			expected: map[string]any{
				"creds_max_ttl":     float64(3600),
				"creds_default_ttl": float64(3600),
			},
		},
		{
			name: "ttl int",
			data: map[string]any{
				"creds_max_ttl":     3600,
				"creds_default_ttl": 3600,
			},
			expected: map[string]any{
				"creds_max_ttl":     float64(3600),
				"creds_default_ttl": float64(3600),
			},
		},
		{
			name: "default signing key",
			data: map[string]any{
				"default_signing_key": "sk1",
			},
			expected: map[string]any{
				"default_signing_key": "sk1",
			},
		},
		{
			name: "set basic claims",
			data: map[string]any{
				"claims": map[string]any{},
			},
			expected: map[string]any{
				"claims": map[string]any{},
			},
		},
		{
			name: "set old-style claims",
			data: map[string]any{
				"claims": map[string]any{
					"tags": []string{"tag1", "tag2"},
				},
			},
			expected: map[string]any{
				"claims": map[string]any{
					"tags": []any{"tag1", "tag2"},
				},
			},
		},
		{
			name: "set complex claims",
			data: map[string]any{
				"claims": fromUserClaims(
					&jwt.User{
						UserPermissionLimits: jwt.UserPermissionLimits{
							Permissions: jwt.Permissions{
								Pub: jwt.Permission{
									Allow: []string{"test-subject"},
								},
							},
						},
						GenericFields: jwt.GenericFields{
							Tags: jwt.TagList{"k1:v1"},
						},
					},
				),
			},
			expected: map[string]any{
				"claims": fromUserClaims(
					&jwt.User{
						UserPermissionLimits: jwt.UserPermissionLimits{
							Permissions: jwt.Permissions{
								Pub: jwt.Permission{
									Allow: []string{"test-subject"},
								},
							},
						},
						GenericFields: jwt.GenericFields{
							Tags: jwt.TagList{"k1:v1"},
						},
					},
				),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(_t *testing.T) {
			t := testBackend(_t)

			// create config
			id := UserId("op1", "acc1", "u1")
			SetupTestAccount(t, id.accountId(), nil)

			resp, err := WriteConfig(t, id, tc.data)
			if err != nil || (resp != nil && resp.IsError()) {
				if tc.err == nil {
					t.Fatalf("err: %s; resp: %#v\n", err, resp)
				} else if err != nil && err.Error() == tc.err.Error() {
					return
				} else if err == nil && resp.Error().Error() == tc.err.Error() {
					return
				} else {
					t.Fatalf("expected err message: %q, got %q, response error: %q", tc.err, err, resp.Error())
				}
			}

			if tc.err != nil {
				if resp == nil || !resp.IsError() {
					t.Fatalf("expected err, got none")
				}
			}

			// read config
			checkFound, exists, err := ExistenceCheckConfig(t, id)
			assert.True(t, checkFound)
			assert.True(t, exists)

			resp, err = ReadConfig(t, id)
			RequireNoRespError(t, resp, err)

			assert.EqualValues(t, tc.expected, resp.Data)

			// ensure nkey exists
			resp, err = ReadNkeyRaw(t, id)
			RequireNoRespError(t, resp, err)
			assert.NotNil(t, resp)

			// delete config
			resp, err = DeleteConfig(t, id, nil)
			RequireNoRespError(t, resp, err)

			// ensure nkey is deleted
			resp, err = ReadNkeyRaw(t, id)
			RequireNoRespError(t, resp, err)
			assert.Nil(t, resp)

			// ensure config is deleted
			resp, err = ReadConfig(t, id)
			RequireNoRespError(t, resp, err)
			assert.Nil(t, resp)
		})
	}

	t.Run("list", func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		uid1 := accId.userId("user1")
		uid2 := accId.userId("user2")
		uid3 := accId.userId("user3")

		resp, err := WriteConfig(t, uid1, nil)
		RequireNoRespError(t, resp, err)
		resp, err = WriteConfig(t, uid2, nil)
		RequireNoRespError(t, resp, err)
		resp, err = WriteConfig(t, uid3, nil)
		RequireNoRespError(t, resp, err)

		// config
		resp, err = ListPath(t, accId.userConfigPrefix())
		RequireNoRespError(t, resp, err)

		assert.ElementsMatch(t, []string{"user1", "user2", "user3"}, resp.Data["keys"])

		// keys
		resp, err = ListPath(t, accId.userNkeyPrefix())
		RequireNoRespError(t, resp, err)

		assert.ElementsMatch(t, []string{"user1", "user2", "user3"}, resp.Data["keys"])
	})

	t.Run("existence check", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, nil)

		resp, err := WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		hasCheck, found, err := ExistenceCheckConfig(t, id)
		assert.NoError(t, err)
		assert.True(t, hasCheck, "existence check not found")
		assert.True(t, found, "item not found")
	})
}

func TestBackend_User_Claims(t *testing.T) {
	t.Run("clear existing claims", func(_t *testing.T) {
		t := testBackend(_t)

		userId := UserId("op1", "acc1", "user1")
		SetupTestUser(t, userId, map[string]any{
			"claims": map[string]any{
				"tags": []any{"test-tag"},
			},
		})

		WriteConfig(t, userId, map[string]any{
			"claims": nil,
		})

		resp, err := ReadConfig(t, userId)
		RequireNoRespError(t, resp, err)

		assert.NotContains(t, resp.Data, "claims")
	})
}

func TestBackend_User_Delete(t *testing.T) {
	t.Run("revoke on delete", func(_t *testing.T) {
		t := testBackend(_t)

		userId := UserId("op1", "acc1", "user1")
		SetupTestUser(t, userId, map[string]any{
			"revoke_on_delete": true,
		})

		userPublicKey := ReadPublicKey(t, userId)

		DeleteConfig(t, userId, nil)

		accJwt := ReadAccountJwt(t, userId.accountId())

		// revokeTtl := max(user.CredsMaxTtl, b.System().MaxLeaseTTL())
		// t.System().MaxLeaseTTL()

		assert.Contains(t, accJwt.Revocations, userPublicKey)
	})
	t.Run("revoke on delete respects user max ttl", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			userId := UserId("op1", "acc1", "user1")
			SetupTestUser(t, userId, map[string]any{
				"revoke_on_delete": true,
				"creds_max_ttl":    "10s",
			})

			userPublicKey := ReadPublicKey(t, userId)

			DeleteConfig(t, userId, nil)

			resp, err := ReadConfig(t, userId.accountId().revocationId(userPublicKey))
			RequireNoRespError(t, resp, err)
		})
	})
	t.Run("no revoke on delete", func(_t *testing.T) {
		t := testBackend(_t)

		userId := UserId("op1", "acc1", "user1")
		SetupTestUser(t, userId, map[string]any{
			"revoke_on_delete": false,
		})

		userPublicKey := ReadPublicKey(t, userId)

		DeleteConfig(t, userId, nil)

		accJwt := ReadAccountJwt(t, userId.accountId())

		assert.NotContains(t, accJwt.Revocations, userPublicKey)
	})
	t.Run("revoke on delete is synced", func(_t *testing.T) {
		n := abstractnats.NewMock(_t)
		defer n.AssertNoLingering(_t)
		t := testBackendWithNats(_t, n)

		userId := UserId("op1", "acc1", "user1")
		SetupTestUser(t, userId, map[string]any{
			"revoke_on_delete": true,
		})

		resp, err := WriteConfig(t, userId.operatorId().accountServerId(), map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		userPublicKey := ReadPublicKey(t, userId)

		var receivedJwt string
		ExpectUpdateSync(t, n, &receivedJwt)

		DeleteConfig(t, userId, nil)

		accClaims, err := jwt.DecodeAccountClaims(receivedJwt)
		require.NoError(t, err)

		assert.Contains(t, accClaims.Revocations, userPublicKey)
	})
}
