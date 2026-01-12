package natsbackend

import (
	"context"
	"errors"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
)

var (
	complexAccountClaimsSample = fromAccountClaims(
		&jwt.Account{
			GenericFields: jwt.GenericFields{
				Tags: jwt.TagList{
					"tag1",
					"tag2",
				},
			},
		},
	)
)

func TestBackend_Account_Config(t *testing.T) {
	testCases := []struct {
		name     string
		data     map[string]any
		expected map[string]any
		err      error
	}{
		{
			name: "invalid jwt",
			data: map[string]any{
				"claims": fromAccountClaims(
					&jwt.Account{
						Imports: []*jwt.Import{
							nil,
						},
					},
				),
			},
			err: errors.New(`failed to encode account jwt: null import is not allowed`),
		},
		{
			name: "default behavior",
			data: map[string]any{},
			expected: map[string]any{
				"status": map[string]any{
					"is_managed":        false,
					"is_system_account": false,
				},
			},
		},
		{
			name: "default signing key",
			data: map[string]any{
				"default_signing_key": "sk1",
			},
			expected: map[string]any{
				"default_signing_key": "sk1",
				"status": map[string]any{
					"is_managed":        false,
					"is_system_account": false,
				},
			},
		},
		{
			name: "set basic claims",
			data: map[string]any{
				"claims": map[string]any{},
			},
			expected: map[string]any{
				"claims": map[string]any{},
				"status": map[string]any{
					"is_managed":        false,
					"is_system_account": false,
				},
			},
		},
		{
			name: "set old-style claims",
			data: map[string]any{
				"claims": map[string]any{
					"nats": map[string]any{
						"tags": []string{"tag1", "tag2"},
					},
				},
			},
			expected: map[string]any{
				"claims": map[string]any{
					"nats": map[string]any{
						"tags": []any{"tag1", "tag2"},
					},
				},
				"status": map[string]any{
					"is_managed":        false,
					"is_system_account": false,
				},
			},
		},
		{
			name: "set complex claims",
			data: map[string]any{
				"claims": complexAccountClaimsSample,
			},
			expected: map[string]any{
				"claims": complexAccountClaimsSample,
				"status": map[string]any{
					"is_managed":        false,
					"is_system_account": false,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(_t *testing.T) {
			t := testBackend(_t)
			id := AccountId("op1", "acc1")

			SetupTestOperator(t, id.operatorId(), nil)
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

			// ensure jwt exists
			resp, err = ReadJwtRaw(t, id)
			RequireNoRespError(t, resp, err)
			assert.NotNil(t, resp)

			// delete config
			resp, err = DeleteConfig(t, id)
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
}

func TestBackend_Account_NonExistentOperator(_t *testing.T) {
	t := testBackend(_t)

	id := AccountId("op1", "acc1")
	resp, err := WriteConfig(t, id, nil)
	assert.NoError(t, err)
	assert.ErrorContains(t, resp.Error(), "operator \"op1\" does not exist")
}

func TestBackend_Account_List(_t *testing.T) {
	t := testBackend(_t)

	opId := OperatorId("op1")
	SetupTestOperator(t, opId, map[string]any{
		"create_system_account": false,
	})

	accId1 := opId.accountId("acc1")
	SetupTestAccount(t, accId1, nil)

	accId2 := opId.accountId("acc2")
	SetupTestAccount(t, accId2, nil)

	accId3 := opId.accountId("acc3")
	SetupTestAccount(t, accId3, nil)

	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      opId.accountsConfigPrefix(),
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	assert.Equal(t, []string{"acc1", "acc2", "acc3"}, resp.Data["keys"])

	// jwts
	req.Path = opId.accountsJwtPrefix()
	resp, err = t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	assert.Equal(t, []string{"acc1", "acc2", "acc3"}, resp.Data["keys"])

	// keys
	req.Path = opId.accountsNkeyPrefix()
	resp, err = t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	assert.Equal(t, []string{"acc1", "acc2", "acc3"}, resp.Data["keys"])
}

func TestBackend_Account_SigningKeys(t *testing.T) {
	t.Run("operator default signing key", func(_t *testing.T) {
		t := testBackend(_t)

		id := AccountId("op1", "acc1")
		SetupTestOperator(t, id.operatorId(), map[string]any{
			"default_signing_key": "sk1",
		})

		resp, err := WriteConfig(t, id.operatorId().signingKeyId("sk1"), nil)
		RequireNoRespError(t, resp, err)

		resp, err = WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		skPublicKey := ReadPublicKey(t, id.operatorId().signingKeyId("sk1"))

		accountClaims := ReadJwt[*jwt.AccountClaims](t, id)
		assert.Equal(t, skPublicKey, accountClaims.Issuer)
	})
	t.Run("account signing key overrides operator default", func(_t *testing.T) {
		t := testBackend(_t)

		id := AccountId("op1", "acc1")
		SetupTestOperator(t, id.operatorId(), map[string]any{
			"default_signing_key": "sk1",
		})

		resp, err := WriteConfig(t, id.operatorId().signingKeyId("sk1"), nil)
		RequireNoRespError(t, resp, err)

		resp, err = WriteConfig(t, id.operatorId().signingKeyId("sk2"), nil)
		RequireNoRespError(t, resp, err)

		resp, err = WriteConfig(t, id, map[string]any{
			"signing_key": "sk2",
		})
		RequireNoRespError(t, resp, err)

		skPublicKey := ReadPublicKey(t, id.operatorId().signingKeyId("sk2"))

		accountClaims := ReadJwt[*jwt.AccountClaims](t, id)
		assert.Equal(t, skPublicKey, accountClaims.Issuer)
	})
	t.Run("non-existent signing key defaults to operator identity key", func(_t *testing.T) {
		t := testBackend(_t)

		id := AccountId("op1", "acc1")
		SetupTestOperator(t, id.operatorId(), nil)

		resp, err := WriteConfig(t, id, map[string]any{
			"signing_key": "sk1",
		})
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Warnings, "could not use signing key \"sk1\" (from account definition) as it does not exist; defaulting to operator identity key")

		opPublicKey := ReadPublicKey(t, id.operatorId())

		accountClaims := ReadJwt[*jwt.AccountClaims](t, id)
		assert.Equal(t, opPublicKey, accountClaims.Issuer)
	})
	t.Run("non-existent signing key defaults to operator default key", func(_t *testing.T) {
		t := testBackend(_t)

		id := AccountId("op1", "acc1")
		SetupTestOperator(t, id.operatorId(), map[string]any{
			"default_signing_key": "sk1",
		})

		resp, err := WriteConfig(t, id.operatorId().signingKeyId("sk1"), nil)
		RequireNoRespError(t, resp, err)

		resp, err = WriteConfig(t, id, map[string]any{
			"signing_key": "sk2",
		})
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Warnings, "could not use signing key \"sk2\" (from account definition) as it does not exist; defaulting to \"sk1\" (from operator default)")

		opPublicKey := ReadPublicKey(t, id.operatorId().signingKeyId("sk1"))

		accountClaims := ReadJwt[*jwt.AccountClaims](t, id)
		assert.Equal(t, opPublicKey, accountClaims.Issuer)
	})
}
