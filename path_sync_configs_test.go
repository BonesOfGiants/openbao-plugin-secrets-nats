package natsbackend

import (
	"errors"
	"strings"
	"testing"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/accountserver"
	"github.com/stretchr/testify/assert"
)

func TestBackend_Operator_SyncConfig(t *testing.T) {
	testCases := []struct {
		name     string
		data     map[string]any
		expected map[string]any
		err      error
	}{
		{
			name: "must provide a server",
			data: map[string]any{},
			err:  errors.New(`must provide at least one server`),
		},
		{
			name: "minimal config",
			data: map[string]any{
				"servers": []string{"nats://localhost:4222"},
			},
			expected: map[string]any{
				"connect_timeout":              0,
				"ignore_sync_errors_on_delete": false,
				"max_reconnects":               0,
				"reconnect_wait":               0,
				"servers":                      []string{"nats://localhost:4222"},
				"sync_user_name":               DefaultSyncUserName,

				"status": map[string]any{
					"status": OperatorSyncStatusCreated,
				},
			},
		},
		{
			name: "override defaults",
			data: map[string]any{
				"servers":         []string{"nats://localhost:4222"},
				"connect_timeout": "10s",
				"max_reconnects":  5,
				"reconnect_wait":  "10s",
				"sync_user_name":  "test-name",
			},
			expected: map[string]any{
				"connect_timeout":              10,
				"ignore_sync_errors_on_delete": false,
				"max_reconnects":               5,
				"reconnect_wait":               10,
				"servers":                      []string{"nats://localhost:4222"},
				"sync_user_name":               "test-name",

				"status": map[string]any{
					"status": OperatorSyncStatusCreated,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(_t *testing.T) {
			t := testBackend(_t)

			id := OperatorId("op1")
			resp := SetupTestOperator(t, id, map[string]any{
				"create_system_account": true,
			})

			// create config
			resp, err := WriteSyncConfig(t, id, tc.data)
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
			resp, err = ReadSyncConfigRaw(t, id)
			RequireNoRespError(t, resp, err)

			assert.EqualValues(t, tc.expected, resp.Data)

			// delete config
			DeleteSyncConfig(t, id)
		})
	}
}

func TestBackend_Operator_SyncConfig_NonExistentOperator(_t *testing.T) {
	t := testBackend(_t)

	id := OperatorId("op1")
	resp, err := WriteSyncConfig(t, id, nil)
	assert.NoError(t, err)
	assert.ErrorContains(t, resp.Error(), "operator \"op1\" does not exist")
}

func TestBackend_Operator_SyncConfig_Update(t *testing.T) {
	t.Run("sync account creation", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		t := testBackendWithNats(_t, nats)

		id := OperatorId("op1")
		SetupTestOperator(t, id, map[string]any{
			"create_system_account": true,
		})

		resp, err := WriteSyncConfig(t, id, map[string]any{
			"servers":  []string{"nats://localhost:4222"},
			"sync_now": false,
		})
		RequireNoRespError(t, resp, err)

		var receivedJwt string
		ExpectUpdateSync(t, nats, &receivedJwt)

		accId := id.accountId("acc1")
		SetupTestAccount(t, accId, nil)

		resp, err = ReadJwtRaw(t, accId)
		RequireNoRespError(t, resp, err)

		assert.Equal(t, resp.Data["jwt"].(string), receivedJwt)
	})

	t.Run("sync account deletion", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		t := testBackendWithNats(_t, nats)

		id := OperatorId("op1")
		SetupTestOperator(t, id, map[string]any{
			"create_system_account": true,
		})

		opPublicKey := ReadPublicKey(t, id)

		// create config disabled
		resp, err := WriteSyncConfig(t, id, map[string]any{
			"servers":  []string{"nats://localhost:4222"},
			"suspend":  true,
			"sync_now": false,
		})
		RequireNoRespError(t, resp, err)

		accId := id.accountId("acc1")
		SetupTestAccount(t, accId, nil)

		// re-enable config
		resp, err = WriteSyncConfig(t, id, map[string]any{
			"suspend":  false,
			"sync_now": false,
		})
		RequireNoRespError(t, resp, err)

		accPublicKey := ReadPublicKey(t, accId)

		ExpectDeleteSync(t, nats, opPublicKey, accPublicKey)

		DeleteConfig(t, accId)
	})
}

func TestBackend_Operator_SyncConfig_Lookup(t *testing.T) {
	t.Run("lookup", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		t := testBackendWithNats(_t, nats)

		id := OperatorId("op1")
		SetupTestOperator(t, id, map[string]any{
			"create_system_account": true,
		})

		accId := id.accountId("acc1")
		SetupTestAccount(t, accId, nil)

		publicKey := ReadPublicKey(t, accId)
		resp, err := ReadJwtRaw(t, accId)
		RequireNoRespError(t, resp, err)
		jwt := resp.Data["jwt"].(string)

		subject := strings.Replace(accountserver.SysAccountClaimsLookupSubject, "*", publicKey, 1)
		reply := "_INBOX.123"
		sub := nats.ExpectSubscription(accountserver.SysAccountClaimsLookupSubject)

		// queue up the call
		sub.Publish(subject, reply, nil)

		nats.ExpectPublish(reply, func(m abstractnats.MockNatsConnection, subj, reply string, data []byte) error {
			assert.Equal(t, jwt, string(data))
			return nil
		})

		resp, err = WriteSyncConfig(t, id, map[string]any{
			"servers":  []string{"nats://localhost:4222"},
			"sync_now": false,
		})
		RequireNoRespError(t, resp, err)
	})
}
