package natsbackend

import (
	"context"
	"errors"
	"testing"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	complexOperatorClaimsSample = fromOperatorClaims(
		&jwt.Operator{
			AccountServerURL: "https://example.com/jwt/v1",
			GenericFields: jwt.GenericFields{
				Tags: jwt.TagList{
					"tag1",
					"tag2",
				},
				Version: 2,
			},
		},
	)
)

func TestBackend_Operator_Config(t *testing.T) {
	testCases := []struct {
		name     string
		data     map[string]any
		expected map[string]any
		err      error
	}{
		{
			name: "invalid jwt",
			data: map[string]any{
				"claims": fromOperatorClaims(
					&jwt.Operator{
						AccountServerURL: "invalid-url",
					},
				),
			},
			err: errors.New(`failed to encode operator jwt: account server url "invalid-url" requires a protocol`),
		},
		{
			name: "default behavior",
			data: map[string]any{},
			expected: map[string]any{
				"create_system_account": true,
				"system_account_name":   "SYS",
			},
		},
		{
			name: "no system account",
			data: map[string]any{
				"create_system_account": false,
				"system_account_name":   "custom_account",
			},
			expected: map[string]any{
				"create_system_account": false,
				"system_account_name":   "custom_account",
			},
		},
		{
			name: "custom system account name",
			data: map[string]any{
				"system_account_name": "custom_account",
			},
			expected: map[string]any{
				"create_system_account": true,
				"system_account_name":   "custom_account",
			},
		},
		{
			name: "managed system account",
			data: map[string]any{
				"create_system_account": true,
			},
			expected: map[string]any{
				"create_system_account": true,
				"system_account_name":   "SYS",
			},
		},
		{
			name: "default signing key",
			data: map[string]any{
				"default_signing_key": "sk1",
			},
			expected: map[string]any{
				"default_signing_key":   "sk1",
				"create_system_account": true,
				"system_account_name":   "SYS",
			},
		},
		{
			name: "generate system account with custom name",
			data: map[string]any{
				"create_system_account": true,
				"system_account_name":   "custom_account",
			},
			expected: map[string]any{
				"create_system_account": true,
				"system_account_name":   "custom_account",
			},
		},
		{
			name: "set basic claims",
			data: map[string]any{
				"claims": map[string]any{},
			},
			expected: map[string]any{
				"create_system_account": true,
				"system_account_name":   "SYS",
				"claims":                map[string]any{},
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
				"create_system_account": true,
				"system_account_name":   "SYS",
				"claims": map[string]any{
					"tags": []any{"tag1", "tag2"},
				},
			},
		},
		{
			name: "set complex claims",
			data: map[string]any{
				"claims": complexOperatorClaimsSample,
			},
			expected: map[string]any{
				"create_system_account": true,
				"system_account_name":   "SYS",
				"claims":                complexOperatorClaimsSample,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(_t *testing.T) {
			t := testBackend(_t)

			id := OperatorId("op1")
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      id.configPath(),
				Storage:   t,
				Data:      tc.data,
			}

			// clean up the config before exiting the test
			defer func() {
				req.Operation = logical.DeleteOperation
				req.Path = id.configPath()
				t.HandleRequest(context.Background(), req)
			}()
			// create config
			resp, err := t.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				if tc.err == nil {
					_t.Fatalf("err: %s; resp: %#v\n", err, resp)
				} else if err != nil && err.Error() == tc.err.Error() {
					return
				} else if err == nil && resp.Error().Error() == tc.err.Error() {
					return
				} else {
					_t.Fatalf("expected err message: %q, got %q, response error: %q", tc.err, err, resp.Error())
				}
			}

			if tc.err != nil {
				if resp == nil || !resp.IsError() {
					_t.Fatalf("expected err, got none")
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

			// ensure jwt exists
			resp, err = ReadJwtRaw(t, id)
			RequireNoRespError(t, resp, err)
			assert.NotNil(t, resp)

			// delete config
			resp, err = DeleteConfig(t, id, nil)
			RequireNoRespError(t, resp, err)

			// ensure nkey is deleted
			resp, err = ReadNkeyRaw(t, id)
			RequireNoRespError(t, resp, err)
			assert.Nil(t, resp)

			// ensure jwt is deleted
			resp, err = ReadJwtRaw(t, id)
			RequireNoRespError(t, resp, err)
			assert.Nil(t, resp)
		})
	}

	t.Run("clear existing claims", func(_t *testing.T) {
		t := testBackend(_t)

		opId := OperatorId("op1")
		SetupTestOperator(t, opId, map[string]any{
			"claims": map[string]any{
				"tags": []any{"test-tag"},
			},
		})

		WriteConfig(t, opId, map[string]any{
			"claims": nil,
		})

		resp, err := ReadConfig(t, opId)
		RequireNoRespError(t, resp, err)

		assert.NotContains(t, resp.Data, "claims")
	})

	t.Run("existence check", func(_t *testing.T) {
		t := testBackend(_t)

		id := OperatorId("op1")
		SetupTestOperator(t, id, nil)

		hasCheck, found, err := ExistenceCheckConfig(t, id)
		assert.NoError(t, err)
		assert.True(t, hasCheck, "existence check not found")
		assert.True(t, found, "item not found")
	})
}

func TestBackend_Operator_Claims(t *testing.T) {
}

func TestBackend_Operator_SystemAccount(t *testing.T) {
	t.Run("no system account", func(_t *testing.T) {
		t := testBackend(_t)

		opId := OperatorId("op1")
		SetupTestOperator(t, opId, map[string]any{
			"create_system_account": false,
		})

		sysId := opId.accountId(DefaultSysAccountName)
		resp, err := ReadConfig(t, sysId)
		RequireNoRespError(t, resp, err)
		require.Nil(t, resp)

		claims := ReadJwt[*jwt.OperatorClaims](t, opId)
		assert.Equal(t, "", claims.SystemAccount)
	})

	t.Run("create default system account", func(_t *testing.T) {
		t := testBackend(_t)

		opId := OperatorId("op1")
		SetupTestOperator(t, opId, map[string]any{
			"create_system_account": true,
		})

		sysId := opId.accountId(DefaultSysAccountName)

		// check sys account
		resp, err := ReadConfig(t, sysId)
		RequireNoRespError(t, resp, err)

		assert.True(t, resp.Data["status"].(map[string]any)["is_managed"].(bool))
		assert.True(t, resp.Data["status"].(map[string]any)["is_system_account"].(bool))
		assert.Equal(t, unmarshalToMap(DefaultSysAccountClaims), resp.Data["claims"])

		// check jwt
		opClaims := ReadJwt[*jwt.OperatorClaims](t, opId)
		sysPublicKey := ReadPublicKey(t, sysId)
		assert.Equal(t, sysPublicKey, opClaims.SystemAccount)
	})

	t.Run("system account created before operator", func(_t *testing.T) {
		t := testBackend(_t)

		opId := OperatorId("op1")
		resp := SetupTestOperator(t, opId, map[string]any{
			"create_system_account": false,
		})
		assert.Contains(t, resp.Warnings,
			`while reissuing jwt for operator "op1": system account "SYS" does not exist, so it was not added to the claims`)

		// check the jwt
		opClaims := ReadJwt[*jwt.OperatorClaims](t, opId)
		assert.Equal(t, "", opClaims.SystemAccount)

		// create sys account
		sysId := opId.accountId("custom_sys")
		resp, err := WriteConfig(t, sysId, nil)
		RequireNoRespError(t, resp, err)
		assert.Empty(t, resp.Warnings)

		// check sys account status
		resp, err = ReadConfig(t, sysId)
		RequireNoRespError(t, resp, err)

		assert.False(t, resp.Data["status"].(map[string]any)["is_managed"].(bool))
		assert.False(t, resp.Data["status"].(map[string]any)["is_system_account"].(bool))

		// update sys account name
		resp, err = UpdateConfig(t, opId, map[string]any{
			"system_account_name": "custom_sys",
		})
		RequireNoRespError(t, resp, err)
		assert.Contains(t, resp.Warnings, `this operation resulted in operator "op1" reissuing its jwt`)

		// check sys account status
		resp, err = ReadConfig(t, sysId)
		RequireNoRespError(t, resp, err)

		assert.False(t, resp.Data["status"].(map[string]any)["is_managed"].(bool))
		assert.True(t, resp.Data["status"].(map[string]any)["is_system_account"].(bool))

		// sys account is now assigned
		sysPublicKey := ReadPublicKey(t, sysId)
		opClaims = ReadJwt[*jwt.OperatorClaims](t, opId)
		assert.Equal(t, sysPublicKey, opClaims.SystemAccount)
	})

	t.Run("custom system account created after operator", func(_t *testing.T) {
		t := testBackend(_t)

		opId := OperatorId("op1")
		resp := SetupTestOperator(t, opId, map[string]any{
			"create_system_account": false,
			"system_account_name":   "custom_sys",
		})

		// first, the account is skipped because it doesn't exist
		assert.Contains(t, resp.Warnings, `while reissuing jwt for operator "op1": system account "custom_sys" does not exist, so it was not added to the claims`)

		// check the jwt
		opClaims := ReadJwt[*jwt.OperatorClaims](t, opId)
		assert.Equal(t, "", opClaims.SystemAccount)

		// create sys account
		sysId := opId.accountId("custom_sys")
		resp, err := WriteConfig(t, sysId, nil)
		RequireNoRespError(t, resp, err)
		assert.Contains(t, resp.Warnings, `this operation resulted in operator "op1" reissuing its jwt`)

		// check sys account status
		resp, err = ReadConfig(t, sysId)
		RequireNoRespError(t, resp, err)

		assert.False(t, resp.Data["status"].(map[string]any)["is_managed"].(bool))
		assert.True(t, resp.Data["status"].(map[string]any)["is_system_account"].(bool))

		// sys account is now assigned
		sysPublicKey := ReadPublicKey(t, sysId)
		opClaims = ReadJwt[*jwt.OperatorClaims](t, opId)
		assert.Equal(t, sysPublicKey, opClaims.SystemAccount)
	})

	t.Run("recreate managed system account", func(_t *testing.T) {
		t := testBackend(_t)

		opId := OperatorId("op1")
		resp := SetupTestOperator(t, opId, map[string]any{
			"create_system_account": true,
			"system_account_name":   "SYS",
		})
		assert.Empty(t, resp.Warnings)

		resp, err := UpdateConfig(t, opId, map[string]any{
			"system_account_name": "custom_sys",
		})
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Warnings, `this operation resulted in operator "op1" reissuing its jwt`)

		// old account is deleted
		resp, err = ReadConfig(t, opId.accountId("SYS"))
		RequireNoRespError(t, resp, err)
		assert.Nil(t, resp)

		// new account is created
		resp, err = ReadConfig(t, opId.accountId("custom_sys"))
		RequireNoRespError(t, resp, err)

		assert.True(t, resp.Data["status"].(map[string]any)["is_managed"].(bool))
		assert.True(t, resp.Data["status"].(map[string]any)["is_system_account"].(bool))
	})

	t.Run("move from custom to managed system account", func(_t *testing.T) {
		t := testBackend(_t)

		opId := OperatorId("op1")
		resp := SetupTestOperator(t, opId, map[string]any{
			"create_system_account": false,
			"system_account_name":   "SYS",
		})

		// create sys account
		resp, err := WriteConfig(t, opId.accountId("SYS"), nil)
		RequireNoRespError(t, resp, err)

		// check account status
		resp, err = ReadConfig(t, opId.accountId("SYS"))
		RequireNoRespError(t, resp, err)

		assert.False(t, resp.Data["status"].(map[string]any)["is_managed"].(bool))
		assert.True(t, resp.Data["status"].(map[string]any)["is_system_account"].(bool))

		// move to a managed system account
		resp, err = UpdateConfig(t, opId, map[string]any{
			"create_system_account": true,
			"system_account_name":   "managed_sys",
		})
		RequireNoRespError(t, resp, err)
		assert.Contains(t, resp.Warnings, `this operation resulted in operator "op1" reissuing its jwt`)

		// check sys account status
		resp, err = ReadConfig(t, opId.accountId("managed_sys"))
		RequireNoRespError(t, resp, err)

		assert.True(t, resp.Data["status"].(map[string]any)["is_managed"].(bool))
		assert.True(t, resp.Data["status"].(map[string]any)["is_system_account"].(bool))

		// check operator claim
		publicKey := ReadPublicKey(t, opId.accountId("managed_sys"))
		claims := ReadJwt[*jwt.OperatorClaims](t, opId)
		assert.Equal(t, publicKey, claims.SystemAccount)
	})

	t.Run("move from managed to custom system account", func(_t *testing.T) {
		t := testBackend(_t)

		opId := OperatorId("op1")
		resp := SetupTestOperator(t, opId, map[string]any{
			"create_system_account": true,
			"system_account_name":   "SYS",
		})

		// create sys account
		resp, err := WriteConfig(t, opId.accountId("custom_sys"), nil)
		RequireNoRespError(t, resp, err)

		// move to a custom system account
		resp, err = UpdateConfig(t, opId, map[string]any{
			"create_system_account": false,
			"system_account_name":   "custom_sys",
		})
		RequireNoRespError(t, resp, err)
		assert.Contains(t, resp.Warnings, `this operation resulted in operator "op1" reissuing its jwt`)

		// check sys account status
		resp, err = ReadConfig(t, opId.accountId("custom_sys"))
		RequireNoRespError(t, resp, err)

		assert.False(t, resp.Data["status"].(map[string]any)["is_managed"].(bool))
		assert.True(t, resp.Data["status"].(map[string]any)["is_system_account"].(bool))

		// managed sys should be deleted
		resp, err = ReadConfig(t, opId.accountId("SYS"))
		RequireNoRespError(t, resp, err)
		assert.Nil(t, resp)

		// check operator claim
		publicKey := ReadPublicKey(t, opId.accountId("custom_sys"))
		claims := ReadJwt[*jwt.OperatorClaims](t, opId)
		assert.Equal(t, publicKey, claims.SystemAccount)
	})

	t.Run("managed name clashes with existing account", func(_t *testing.T) {
		t := testBackend(_t)

		opId := OperatorId("op1")
		resp := SetupTestOperator(t, opId, map[string]any{
			"create_system_account": false,
			"system_account_name":   "SYS",
		})

		// create sys account
		resp, err := WriteConfig(t, opId.accountId("SYS"), nil)
		RequireNoRespError(t, resp, err)

		// try to create the system account
		resp, err = UpdateConfig(t, opId, map[string]any{
			"create_system_account": true,
		})
		assert.NoError(_t, err)
		assert.ErrorContains(_t, resp.Error(), "managed system account name \"SYS\" clashes with existing account")
	})

	t.Run("system account warnings", func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestOperator(t, accId.operatorId(), map[string]any{
			"system_account_name":   "acc1",
			"create_system_account": false,
		})

		resp, err := WriteConfig(t, accId, nil)
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Warnings, "this operation resulted in operator \"op1\" reissuing its jwt")

		resp, err = DeleteConfig(t, accId, nil)
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Warnings, "this operation resulted in operator \"op1\" reissuing its jwt")
	})
}

func TestBackend_Operator_Claims_Suspend(t *testing.T) {
	t.Run("suspend account server on claims change", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		defer nats.AssertNoLingering(_t)
		t := testBackendWithNats(_t, nats)

		opId := OperatorId("op1")
		SetupTestOperator(t, opId, nil)

		resp, err := WriteConfig(t, opId.accountServerId(), map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		WriteConfig(t, opId, map[string]any{
			"claims": map[string]any{
				"tags": []any{"test-tag"},
			},
		})

		resp, err = ReadConfig(t, opId.accountServerId())
		RequireNoRespError(t, resp, err)

		assert.Equal(t, true, resp.Data["suspend"])
	})

	t.Run("suspend account server on server account change", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		defer nats.AssertNoLingering(_t)
		t := testBackendWithNats(_t, nats)

		opId := OperatorId("op1")
		SetupTestOperator(t, opId, nil)

		resp, err := WriteConfig(t, opId.accountServerId(), map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		WriteConfig(t, opId, map[string]any{
			"system_account_name": "test_account",
		})

		resp, err = ReadConfig(t, opId.accountServerId())
		RequireNoRespError(t, resp, err)

		assert.Equal(t, true, resp.Data["suspend"])
	})

	t.Run("noop if claims are not changed", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		defer nats.AssertNoLingering(_t)
		t := testBackendWithNats(_t, nats)

		opId := OperatorId("op1")
		SetupTestOperator(t, opId, nil)

		resp, err := WriteConfig(t, opId.accountServerId(), map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		WriteConfig(t, opId, map[string]any{
			"default_signing_key": "sk1",
		})

		resp, err = ReadConfig(t, opId.accountServerId())
		RequireNoRespError(t, resp, err)

		assert.NotContains(t, resp.Data, "suspend")
	})
}

func TestBackend_Operator_List(_t *testing.T) {
	b := testBackend(_t)

	opId1 := OperatorId("op1")
	SetupTestOperator(b, opId1, nil)

	opId2 := OperatorId("op2")
	SetupTestOperator(b, opId2, nil)

	opId3 := OperatorId("op3")
	SetupTestOperator(b, opId3, nil)

	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      operatorsPathPrefix,
		Storage:   b,
		Data:      map[string]any{},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	RequireNoRespError(b, resp, err)

	assert.ElementsMatch(b, []string{"op1", "op2", "op3"}, resp.Data["keys"])

	req.Path = operatorJwtsPathPrefix
	resp, err = b.HandleRequest(context.Background(), req)
	RequireNoRespError(b, resp, err)

	assert.ElementsMatch(b, []string{"op1", "op2", "op3"}, resp.Data["keys"])

	req.Path = operatorKeysPathPrefix
	resp, err = b.HandleRequest(context.Background(), req)
	RequireNoRespError(b, resp, err)

	assert.ElementsMatch(b, []string{"op1", "op2", "op3"}, resp.Data["keys"])
}

// build a complex tree of objects and delete the operator
// all objects below it should also be deleted
func TestBackend_Operator_CascadingDelete(_t *testing.T) {
	t := testBackend(_t)

	opId := OperatorId("op1")
	opSkId := opId.signingKeyId("sk1")

	accId := opId.accountId("acc1")
	accImpId := accId.importId("imp1")
	accRevId := accId.revocationId("U123")
	accSkId := accId.signingKeyId("sk1")

	userId := accId.userId("user1")
	ephUserId := accId.ephemeralUserId("eph1")

	// operator
	SetupTestOperator(t, opId, nil)
	// operator account server
	WriteConfig(t, opId.accountServerId(), map[string]any{
		"servers": []string{"nats://localhost:4222"},
		"suspend": true,
	})
	// operator signing key
	WriteConfig(t, opSkId, nil)

	// account
	SetupTestAccount(t, accId, nil)
	// account import
	impAccKp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	impAccPubKey, err := impAccKp.PublicKey()
	require.NoError(t, err)
	WriteConfig(t, accImpId, map[string]any{
		"imports": []map[string]any{
			{
				"name":    "test-import",
				"subject": "foo",
				"account": impAccPubKey,
			},
		},
	})
	// account revocation
	WriteConfig(t, accRevId, nil)
	// account signing key
	WriteConfig(t, accSkId, nil)

	// user
	SetupTestUser(t, userId, nil)
	// ephemeral user
	SetupTestUser(t, ephUserId, nil)

	// delete operator
	DeleteConfig(t, opId, nil)

	// operator
	AssertConfigDeleted(t, opId)
	// operator account server
	resp, err := ReadConfig(t, opId.accountServerId())
	RequireNoRespError(t, resp, err)
	assert.Nil(t, resp)
	// operator signing key
	AssertConfigDeleted(t, accId)
	// operator key
	AssertNKeyDeleted(t, opId)
	// operator jwt
	AssertJwtDeleted(t, opId)

	// account
	AssertConfigDeleted(t, accId)
	// account import
	AssertConfigDeleted(t, accImpId)
	// account revocation
	AssertConfigDeleted(t, accRevId)
	// account signing key
	AssertConfigDeleted(t, accSkId)
	// account key
	AssertNKeyDeleted(t, accId)
	// account jwt
	AssertJwtDeleted(t, accId)

	// user
	AssertConfigDeleted(t, userId)
	// user key
	AssertNKeyDeleted(t, userId)
	// ephemeral user
	AssertConfigDeleted(t, ephUserId)
}
