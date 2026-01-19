package natsbackend

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/accountserver"
	nats "github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackend_Operator_AccountServer_Config(t *testing.T) {
	type testConfig struct {
		data         map[string]any
		expected     map[string]any
		expectLookup bool
		err          error
	}
	runTest := func(_t *testing.T, tc testConfig) {
		n := abstractnats.NewMock(_t)
		t := testBackendWithNats(_t, n)

		id := AccountServerId("op1")
		resp := SetupTestOperator(t, id.operatorId(), nil)

		if tc.expectLookup {
			n.ExpectSubscription(accountserver.SysAccountClaimsLookupSubject)
		}

		// disable syncing for config tests
		tc.data["sync_now"] = false

		// create config
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
		resp, err = ReadConfigRaw(t, id)
		RequireNoRespError(t, resp, err)

		assert.EqualValues(t, tc.expected, resp.Data)

		// delete config
		DeleteConfig(t, id, nil)
	}

	t.Run("must provide a server", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			runTest(t, testConfig{
				data: map[string]any{},
				err:  errors.New(`must provide at least one server`),
			})
		})
	})

	t.Run("minimal config", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			runTest(t, testConfig{
				data: map[string]any{
					"servers": []string{"nats://localhost:4222"},
				},
				expectLookup: true,
				expected: map[string]any{
					"servers":     []string{"nats://localhost:4222"},
					"client_name": DefaultAccountServerClientName,

					"status": map[string]any{
						"status":             AccountServerStatusActive,
						"last_status_change": time.Now(),
					},
				},
			})
		})
	})

	t.Run("override defaults", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			runTest(t, testConfig{
				data: map[string]any{
					"servers":         []string{"nats://localhost:4222"},
					"connect_timeout": "10s",
					"max_reconnects":  5,
					"reconnect_wait":  "10s",
					"client_name":     "test-name",
					"disable_lookups": true,
					"sync_now":        false,
					"suspend":         true,
				},
				expectLookup: false,
				expected: map[string]any{
					"connect_timeout": 10,
					"disable_lookups": true,
					"max_reconnects":  5,
					"reconnect_wait":  10,
					"servers":         []string{"nats://localhost:4222"},
					"suspend":         true,
					"client_name":     "test-name",

					"status": map[string]any{
						"status":             AccountServerStatusSuspended,
						"last_status_change": time.Now(),
					},
				},
			})
		})
	})

	t.Run("missing operator", func(_t *testing.T) {
		t := testBackend(_t)

		id := AccountServerId("op1")
		resp, err := WriteConfig(t, id, nil)
		assert.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "operator \"op1\" does not exist")
	})

	t.Run("missing system account", func(_t *testing.T) {
		n := abstractnats.NewMock(_t)
		defer n.AssertNoLingering(_t)
		t := testBackendWithNats(_t, n)

		id := AccountServerId("op1")
		SetupTestOperator(t, id.operatorId(), map[string]any{
			"create_system_account": false,
		})

		resp, err := WriteConfig(t, id, map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"sync_now":        false,
			"disable_lookups": true,
		})
		assert.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "a system account is required for sync: operator \"op1\" system account \"SYS\" does not exist")
	})
}

func TestBackend_Operator_AccountServer_NonExistentOperator(_t *testing.T) {
	t := testBackend(_t)

	id := AccountServerId("op1")
	resp, err := WriteConfig(t, id, nil)
	assert.NoError(t, err)
	assert.ErrorContains(t, resp.Error(), "operator \"op1\" does not exist")
}

func TestBackend_Operator_AccountServer_Update(t *testing.T) {
	t.Run("sync account creation", func(_t *testing.T) {
		n := abstractnats.NewMock(_t)
		defer n.AssertNoLingering(_t)
		t := testBackendWithNats(_t, n)

		id := AccountServerId("op1")
		SetupTestOperator(t, id.operatorId(), nil)

		resp, err := WriteConfig(t, id, map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		var receivedJwt string
		ExpectUpdateSync(t, n, &receivedJwt)

		accId := id.operatorId().accountId("acc1")
		SetupTestAccount(t, accId, nil)

		resp, err = ReadJwtRaw(t, accId)
		RequireNoRespError(t, resp, err)

		assert.Equal(t, resp.Data["jwt"].(string), receivedJwt)
	})

	t.Run("sync account deletion", func(_t *testing.T) {
		n := abstractnats.NewMock(_t)
		defer n.AssertNoLingering(_t)
		t := testBackendWithNats(_t, n)

		id := AccountServerId("op1")
		opId := id.operatorId()
		SetupTestOperator(t, opId, nil)

		opPublicKey := ReadPublicKey(t, opId)

		// create config disabled
		resp, err := WriteConfig(t, id, map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"suspend":         true,
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		accId := opId.accountId("acc1")
		SetupTestAccount(t, accId, nil)

		// re-enable config
		resp, err = WriteConfig(t, id, map[string]any{
			"suspend":  false,
			"sync_now": false,
		})
		RequireNoRespError(t, resp, err)

		accPublicKey := ReadPublicKey(t, accId)

		ExpectDeleteSync(t, n, opPublicKey, accPublicKey)

		DeleteConfig(t, accId, nil)
	})

	t.Run("no sync account creation if suspended", func(_t *testing.T) {
		n := abstractnats.NewMock(_t)
		defer n.AssertNoLingering(_t)
		t := testBackendWithNats(_t, n)

		id := AccountServerId("op1")
		opId := id.operatorId()
		SetupTestOperator(t, opId, nil)

		// create config disabled
		resp, err := WriteConfig(t, id, map[string]any{
			"servers": []string{"nats://localhost:4222"},
			"suspend": true,
		})
		RequireNoRespError(t, resp, err)

		accId := opId.accountId("acc1")
		SetupTestAccount(t, accId, nil)
	})

	t.Run("no sync account delete if suspended", func(_t *testing.T) {
		n := abstractnats.NewMock(_t)
		defer n.AssertNoLingering(_t)
		t := testBackendWithNats(_t, n)

		id := AccountServerId("op1")
		opId := id.operatorId()
		SetupTestOperator(t, opId, nil)

		// create config disabled
		resp, err := WriteConfig(t, id, map[string]any{
			"servers": []string{"nats://localhost:4222"},
			"suspend": true,
		})
		RequireNoRespError(t, resp, err)

		accId := opId.accountId("acc1")
		SetupTestAccount(t, accId, nil)

		DeleteConfig(t, accId, nil)
	})
}

func TestBackend_Operator_AccountServer_Lookup(_t *testing.T) {
	n := abstractnats.NewMock(_t)
	defer n.AssertNoLingering(_t)
	t := testBackendWithNats(_t, n)

	id := AccountServerId("op1")
	opId := id.operatorId()
	SetupTestOperator(t, opId, map[string]any{
		"create_system_account": true,
	})

	accId := opId.accountId("acc1")
	SetupTestAccount(t, accId, nil)

	publicKey := ReadPublicKey(t, accId)
	resp, err := ReadJwtRaw(t, accId)
	RequireNoRespError(t, resp, err)
	jwt := resp.Data["jwt"].(string)

	subject := strings.Replace(accountserver.SysAccountClaimsLookupSubject, "*", publicKey, 1)
	reply := nats.NewInbox()
	sub := n.ExpectSubscription(accountserver.SysAccountClaimsLookupSubject)

	// queue up the call
	sub.Publish(subject, reply, nil)

	n.ExpectPublish(reply, func(m abstractnats.MockNatsConnection, subj, reply string, data []byte) error {
		assert.Equal(t, jwt, string(data))
		return nil
	})

	resp, err = WriteConfig(t, id, map[string]any{
		"servers":  []string{"nats://localhost:4222"},
		"sync_now": false,
	})
	RequireNoRespError(t, resp, err)
}

func TestBackend_Operator_AccountServer_Disable_Behaviors(t *testing.T) {
	t.Run("disable lookups", func(_t *testing.T) {
		n := abstractnats.NewMock(_t)
		t := testBackendWithNats(_t, n)

		id := AccountServerId("op1")
		opId := id.operatorId()
		SetupTestOperator(t, opId, nil)

		resp, err := WriteConfig(t, id, map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"disable_lookups": true,
			"sync_now":        false,
		})
		RequireNoRespError(t, resp, err)

		n.AssertNoLingering(_t)
	})
	t.Run("disable updates", func(_t *testing.T) {
		n := abstractnats.NewMock(_t)
		t := testBackendWithNats(_t, n)

		id := AccountServerId("op1")
		opId := id.operatorId()
		SetupTestOperator(t, opId, nil)

		resp, err := WriteConfig(t, id, map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"disable_lookups": true,
			"disable_updates": true,
			"sync_now":        false,
		})
		RequireNoRespError(t, resp, err)

		resp, err = WriteConfig(t, opId.accountId("acc1"), nil)
		RequireNoRespError(t, resp, err)

		n.AssertNoLingering(_t)
	})
	t.Run("disable deletes", func(_t *testing.T) {
		n := abstractnats.NewMock(_t)
		t := testBackendWithNats(_t, n)

		id := AccountServerId("op1")
		opId := id.operatorId()
		SetupTestOperator(t, opId, nil)

		resp, err := WriteConfig(t, opId.accountId("acc1"), nil)
		RequireNoRespError(t, resp, err)

		resp, err = WriteConfig(t, id, map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"disable_lookups": true,
			"disable_deletes": true,
			"sync_now":        false,
		})
		RequireNoRespError(t, resp, err)

		resp, err = DeleteConfig(t, opId.accountId("acc1"), nil)
		RequireNoRespError(t, resp, err)

		n.AssertNoLingering(_t)
	})
}

func TestBackend_Operator_AccountServer_Status(t *testing.T) {
	t.Run("active", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			nats := abstractnats.NewMock(_t)
			t := testBackendWithNats(_t, nats)

			id := AccountServerId("op1")
			opId := id.operatorId()
			SetupTestOperator(t, opId, map[string]any{
				"create_system_account": true,
			})

			resp, err := WriteConfig(t, id, map[string]any{
				"servers":         []string{"nats://localhost:4222"},
				"sync_now":        false,
				"disable_lookups": true,
			})
			RequireNoRespError(t, resp, err)

			resp, err = ReadConfigRaw(t, id)
			RequireNoRespError(t, resp, err)

			require.Contains(t, resp.Data, "status")

			assert.Equal(t,
				map[string]any{
					"status":             AccountServerStatusActive,
					"last_status_change": time.Now(),
				},
				resp.Data["status"],
			)
		})
	})

	t.Run("suspended", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			id := AccountServerId("op1")
			SetupTestOperator(t, id.operatorId(), map[string]any{
				"create_system_account": true,
			})

			resp, err := WriteConfig(t, id, map[string]any{
				"servers": []string{"nats://localhost:4222"},
				"suspend": true,
			})
			RequireNoRespError(t, resp, err)

			resp, err = ReadConfigRaw(t, id)
			RequireNoRespError(t, resp, err)

			require.Contains(t, resp.Data, "status")

			assert.Equal(t,
				map[string]any{
					"status":             AccountServerStatusSuspended,
					"last_status_change": time.Now(),
				},
				resp.Data["status"],
			)
		})
	})

	t.Run("update to suspended", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			nats := abstractnats.NewMock(_t)
			t := testBackendWithNats(_t, nats)

			id := AccountServerId("op1")
			SetupTestOperator(t, id.operatorId(), map[string]any{
				"create_system_account": true,
			})

			resp, err := WriteConfig(t, id, map[string]any{
				"servers":         []string{"nats://localhost:4222"},
				"sync_now":        false,
				"disable_lookups": true,
			})
			RequireNoRespError(t, resp, err)

			resp, err = WriteConfig(t, id, map[string]any{
				"suspend": true,
			})
			RequireNoRespError(t, resp, err)

			resp, err = ReadConfigRaw(t, id)
			RequireNoRespError(t, resp, err)

			require.Contains(t, resp.Data, "status")

			assert.Equal(t,
				map[string]any{
					"status":             AccountServerStatusSuspended,
					"last_status_change": time.Now(),
				},
				resp.Data["status"],
			)
		})
	})

	t.Run("disabling all behaviors suspends account server", func(_t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			nats := abstractnats.NewMock(_t)
			t := testBackendWithNats(_t, nats)

			id := AccountServerId("op1")
			SetupTestOperator(t, id.operatorId(), map[string]any{
				"create_system_account": true,
			})

			resp, err := WriteConfig(t, id, map[string]any{
				"servers":         []string{"nats://localhost:4222"},
				"sync_now":        false,
				"disable_lookups": true,
				"disable_updates": true,
				"disable_deletes": true,
			})
			RequireNoRespError(t, resp, err)

			resp, err = ReadConfigRaw(t, id)
			RequireNoRespError(t, resp, err)

			require.Contains(t, resp.Data, "status")

			assert.Equal(t,
				map[string]any{
					"status":             AccountServerStatusSuspended,
					"last_status_change": time.Now(),
				},
				resp.Data["status"],
			)
		})
	})

	t.Run("conn error", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			expectedErr := fmt.Errorf("a connection error happened")

			nats := abstractnats.NewMockError(_t, expectedErr)
			t := testBackendWithNats(_t, nats)

			id := AccountServerId("op1")
			SetupTestOperator(t, id.operatorId(), map[string]any{
				"create_system_account": true,
			})

			resp, err := WriteConfig(t, id, map[string]any{
				"servers":         []string{"nats://localhost:4222"},
				"sync_now":        false,
				"disable_lookups": true,
			})
			RequireNoRespError(t, resp, err)

			resp, err = ReadConfigRaw(t, id)
			RequireNoRespError(t, resp, err)

			require.Contains(t, resp.Data, "status")

			assert.Equal(t,
				map[string]any{
					"status":             AccountServerStatusError,
					"last_status_change": time.Now(),
					"error":              fmt.Sprintf("failed to create nats connection: %v", expectedErr.Error()),
				},
				resp.Data["status"],
			)
		})
	})
}
