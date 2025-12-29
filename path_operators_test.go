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
	complexOperatorClaimsSample = unmarshalToMap(fromOperatorClaims(
		&jwt.OperatorClaims{
			Operator: jwt.Operator{
				AccountServerURL: "https://example.com/jwt/v1",
				GenericFields: jwt.GenericFields{
					Tags: jwt.TagList{
						"tag1",
						"tag2",
					},
					Version: 2,
				},
			},
		},
	))
)

func TestBackend_Operator_Config(_t *testing.T) {
	b := testBackend(_t)

	testCases := []struct {
		name     string
		data     map[string]any
		expected map[string]any
		err      error
	}{
		{
			name: "invalid jwt",
			data: map[string]any{
				"claims": unmarshalToMap(fromOperatorClaims(
					&jwt.OperatorClaims{
						Operator: jwt.Operator{
							AccountServerURL: "invalid-url",
						},
					},
				)),
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
			name: "enerate system account with custom name",
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
		_t.Run(tc.name, func(t *testing.T) {
			id := OperatorId("op1")
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      id.configPath(),
				Storage:   b,
				Data:      tc.data,
			}

			// clean up the config before exiting the test
			defer func() {
				req.Operation = logical.DeleteOperation
				req.Path = id.configPath()
				b.HandleRequest(context.Background(), req)
			}()
			// create config
			resp, err := b.HandleRequest(context.Background(), req)
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
			checkFound, exists, err := ExistenceCheckConfig(b, id)
			assert.True(b, checkFound)
			assert.True(b, exists)

			resp, err = ReadConfigRaw(b, id)
			RequireNoRespError(b, resp, err)

			assert.EqualValues(b, tc.expected, resp.Data)

			// ensure nkey exists
			resp, err = ReadNkeyRaw(b, id)
			RequireNoRespError(b, resp, err)
			assert.NotNil(b, resp)

			// ensure jwt exists
			resp, err = ReadJwtRaw(b, id)
			RequireNoRespError(b, resp, err)
			assert.NotNil(b, resp)

			// delete config
			resp, err = DeleteConfig(b, id)
			RequireNoRespError(b, resp, err)

			// ensure nkey is deleted
			resp, err = ReadNkeyRaw(b, id)
			RequireNoRespError(b, resp, err)
			assert.Nil(b, resp)

			// ensure jwt is deleted
			resp, err = ReadJwtRaw(b, id)
			RequireNoRespError(b, resp, err)
			assert.Nil(b, resp)
		})
	}
}

func TestBackend_Operator_SystemAccount(t *testing.T) {
	t.Run("no system account", func(t *testing.T) {
		b := testBackend(t)

		opId := OperatorId("op1")
		SetupTestOperator(b, opId, map[string]any{
			"create_system_account": false,
			"system_account_name":   "",
		})

		sysId := opId.accountId(DefaultSysAccountName)
		resp, err := ReadConfigRaw(b, sysId)
		RequireNoRespError(b, resp, err)
		require.Nil(b, resp)

		claims := ReadJwt[*jwt.OperatorClaims](b, opId)
		assert.Equal(b, "", claims.SystemAccount)
	})

	t.Run("create default system account", func(t *testing.T) {
		b := testBackend(t)

		opId := OperatorId("op1")
		SetupTestOperator(b, opId, map[string]any{
			"create_system_account": true,
		})

		sysId := opId.accountId(DefaultSysAccountName)

		// check sys account
		sysConf := ReadConfig[accountEntry](b, sysId)
		assert.True(b, sysConf.Status.IsManaged)
		assert.True(b, sysConf.Status.IsSystemAccount)
		assert.Equal(b, unmarshalToMap(fromAccountClaims(DefaultSysAccountClaims)), unmarshalToMap(sysConf.RawClaims))

		// check jwt
		opClaims := ReadJwt[*jwt.OperatorClaims](b, opId)
		sysPublicKey := ReadPublicKey(b, sysId)
		assert.Equal(b, sysPublicKey, opClaims.SystemAccount)
	})

	t.Run("system account created before operator", func(t *testing.T) {
		b := testBackend(t)

		opId := OperatorId("op1")
		resp := SetupTestOperator(b, opId, map[string]any{
			"create_system_account": false,
		})
		assert.Contains(b, resp.Warnings,
			`while reissuing jwt for operator "op1": system account "SYS" does not exist, so it was not added to the claims`)

		// check the jwt
		opClaims := ReadJwt[*jwt.OperatorClaims](b, opId)
		assert.Equal(b, "", opClaims.SystemAccount)

		// create sys account
		sysId := opId.accountId("custom_sys")
		resp, err := WriteConfig(b, sysId, nil)
		RequireNoRespError(b, resp, err)
		assert.Empty(b, resp.Warnings)

		// check sys account status
		account := ReadConfig[*accountEntry](b, sysId)
		assert.False(b, account.Status.IsManaged)
		assert.False(b, account.Status.IsSystemAccount)

		// update sys account name
		resp, err = UpdateConfig(b, opId, map[string]any{
			"system_account_name": "custom_sys",
		})
		RequireNoRespError(b, resp, err)
		assert.Contains(b, resp.Warnings, `this operation resulted in operator "op1" reissuing its jwt`)

		// check sys account status
		account = ReadConfig[*accountEntry](b, sysId)
		assert.False(b, account.Status.IsManaged)
		assert.True(b, account.Status.IsSystemAccount)

		// sys account is now assigned
		sysPublicKey := ReadPublicKey(b, sysId)
		opClaims = ReadJwt[*jwt.OperatorClaims](b, opId)
		assert.Equal(b, sysPublicKey, opClaims.SystemAccount)
	})

	t.Run("custom system account created after operator", func(t *testing.T) {
		b := testBackend(t)

		opId := OperatorId("op1")
		resp := SetupTestOperator(b, opId, map[string]any{
			"create_system_account": false,
			"system_account_name":   "custom_sys",
		})

		// first, the account is skipped because it doesn't exist
		assert.Contains(b, resp.Warnings, `while reissuing jwt for operator "op1": system account "custom_sys" does not exist, so it was not added to the claims`)

		// check the jwt
		opClaims := ReadJwt[*jwt.OperatorClaims](b, opId)
		assert.Equal(b, "", opClaims.SystemAccount)

		// create sys account
		sysId := opId.accountId("custom_sys")
		resp, err := WriteConfig(b, sysId, nil)
		RequireNoRespError(b, resp, err)
		assert.Contains(b, resp.Warnings, `this operation resulted in operator "op1" reissuing its jwt`)

		// check sys account status
		account := ReadConfig[*accountEntry](b, sysId)
		assert.False(b, account.Status.IsManaged)
		assert.True(b, account.Status.IsSystemAccount)

		// sys account is now assigned
		sysPublicKey := ReadPublicKey(b, sysId)
		opClaims = ReadJwt[*jwt.OperatorClaims](b, opId)
		assert.Equal(b, sysPublicKey, opClaims.SystemAccount)
	})

	t.Run("recreate managed system account", func(t *testing.T) {
		b := testBackend(t)

		opId := OperatorId("op1")
		resp := SetupTestOperator(b, opId, map[string]any{
			"create_system_account": true,
			"system_account_name":   "SYS",
		})
		assert.Empty(b, resp.Warnings)

		resp, err := UpdateConfig(b, opId, map[string]any{
			"system_account_name": "custom_sys",
		})
		RequireNoRespError(b, resp, err)

		assert.Contains(b, resp.Warnings, `this operation resulted in operator "op1" reissuing its jwt`)

		// old account is deleted
		resp, err = ReadConfigRaw(b, opId.accountId("SYS"))
		RequireNoRespError(b, resp, err)
		assert.Nil(b, resp)

		// new account is created
		account := ReadConfig[*accountEntry](b, opId.accountId("custom_sys"))
		assert.True(b, account.Status.IsManaged)
		assert.True(b, account.Status.IsSystemAccount)
	})

	t.Run("move from custom to managed system account", func(t *testing.T) {
		b := testBackend(t)

		opId := OperatorId("op1")
		resp := SetupTestOperator(b, opId, map[string]any{
			"create_system_account": false,
			"system_account_name":   "SYS",
		})

		// create sys account
		resp, err := WriteConfig(b, opId.accountId("SYS"), nil)
		RequireNoRespError(b, resp, err)

		// check account status
		account := ReadConfig[*accountEntry](b, opId.accountId("SYS"))
		assert.False(b, account.Status.IsManaged)
		assert.True(b, account.Status.IsSystemAccount)

		// move to a managed system account
		resp, err = UpdateConfig(b, opId, map[string]any{
			"create_system_account": true,
			"system_account_name":   "managed_sys",
		})
		RequireNoRespError(b, resp, err)
		assert.Contains(b, resp.Warnings, `this operation resulted in operator "op1" reissuing its jwt`)

		// check sys account status
		account = ReadConfig[*accountEntry](b, opId.accountId("managed_sys"))
		assert.True(b, account.Status.IsManaged)
		assert.True(b, account.Status.IsSystemAccount)

		// check operator claim
		publicKey := ReadPublicKey(b, opId.accountId("managed_sys"))
		claims := ReadJwt[*jwt.OperatorClaims](b, opId)
		assert.Equal(b, publicKey, claims.SystemAccount)
	})

	t.Run("move from managed to custom system account", func(t *testing.T) {
		b := testBackend(t)

		opId := OperatorId("op1")
		resp := SetupTestOperator(b, opId, map[string]any{
			"create_system_account": true,
			"system_account_name":   "SYS",
		})

		// create sys account
		resp, err := WriteConfig(b, opId.accountId("custom_sys"), nil)
		RequireNoRespError(b, resp, err)

		// move to a custom system account
		resp, err = UpdateConfig(b, opId, map[string]any{
			"create_system_account": false,
			"system_account_name":   "custom_sys",
		})
		RequireNoRespError(b, resp, err)
		assert.Contains(b, resp.Warnings, `this operation resulted in operator "op1" reissuing its jwt`)

		// check sys account status
		account := ReadConfig[*accountEntry](b, opId.accountId("custom_sys"))
		assert.False(b, account.Status.IsManaged)
		assert.True(b, account.Status.IsSystemAccount)

		// managed sys should be deleted
		resp, err = ReadConfigRaw(b, opId.accountId("SYS"))
		RequireNoRespError(b, resp, err)
		assert.Nil(b, resp)

		// check operator claim
		publicKey := ReadPublicKey(b, opId.accountId("custom_sys"))
		claims := ReadJwt[*jwt.OperatorClaims](b, opId)
		assert.Equal(b, publicKey, claims.SystemAccount)
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

	assert.Equal(b, []string{"op1", "op2", "op3"}, resp.Data["keys"])

	req.Path = operatorJwtsPathPrefix
	resp, err = b.HandleRequest(context.Background(), req)
	RequireNoRespError(b, resp, err)

	assert.Equal(b, []string{"op1", "op2", "op3"}, resp.Data["keys"])

	req.Path = operatorKeysPathPrefix
	resp, err = b.HandleRequest(context.Background(), req)
	RequireNoRespError(b, resp, err)

	assert.Equal(b, []string{"op1", "op2", "op3"}, resp.Data["keys"])
}

// build a complex tree of objects and delete the operator
// all objects below it should also be deleted
func TestBackend_Cascading_Delete(_t *testing.T) {
	t := testBackendWithNats(_t, abstractnats.NewMock(_t))

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
	// operator sync config
	CreateSyncConfig(t, opId, map[string]any{
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
	DeleteConfig(t, opId)

	// operator
	AssertConfigDeleted(t, opId)
	// operator sync config
	resp, err := ReadSyncConfigRaw(t, opId)
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
