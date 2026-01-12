package natsbackend

import (
	"errors"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
)

func TestBackend_User_Config(_t *testing.T) {

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
		_t.Run(tc.name, func(_t *testing.T) {
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

			resp, err = ReadConfigRaw(t, id)
			RequireNoRespError(t, resp, err)

			assert.EqualValues(t, tc.expected, resp.Data)

			// ensure nkey exists
			resp, err = ReadNkeyRaw(t, id)
			RequireNoRespError(t, resp, err)
			assert.NotNil(t, resp)

			// delete config
			resp, err = DeleteConfig(t, id)
			RequireNoRespError(t, resp, err)

			// ensure nkey is deleted
			resp, err = ReadNkeyRaw(t, id)
			RequireNoRespError(t, resp, err)
			assert.Nil(t, resp)

			// ensure config is deleted
			resp, err = ReadConfigRaw(t, id)
			RequireNoRespError(t, resp, err)
			assert.Nil(t, resp)
		})
	}
}
