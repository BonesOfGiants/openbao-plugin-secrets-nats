package natsbackend

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackend_OperatorSigningKey_Config(t *testing.T) {
	t.Run("basic", func(_t *testing.T) {
		t := testBackend(_t)

		id := OperatorSigningKeyId("op1", "s1")
		SetupTestOperator(t, id.operatorId(), nil)

		// create the signing key
		resp, err := WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		pubKey := ReadPublicKey(t, id)

		// operator jwt should contain the signing key
		opJwt := ReadOperatorJwt(t, id.operatorId())
		assert.Contains(t, opJwt.SigningKeys, pubKey)

		// delete signing key
		DeleteConfig(t, id)

		// operator jwt should not contain the signing key
		opJwt = ReadOperatorJwt(t, id.operatorId())
		assert.NotContains(t, opJwt.SigningKeys, pubKey)
	})
	t.Run("reissue jwts when signing key is created", func(_t *testing.T) {
		t := testBackend(_t)

		id := OperatorSigningKeyId("op1", "s1")
		SetupTestOperator(t, id.operatorId(), nil)

		// create account with signing key
		SetupTestAccount(t, id.operatorId().accountId("acc1"), map[string]any{
			"signing_key": "sk1",
		})

		// create the signing key
		resp, err := WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		pubKey := ReadPublicKey(t, id)

		// operator jwt should contain the signing key
		opJwt := ReadOperatorJwt(t, id.operatorId())
		assert.Contains(t, opJwt.SigningKeys, pubKey)

		// delete signing key
		DeleteConfig(t, id)

		// operator jwt should not contain the signing key
		opJwt = ReadOperatorJwt(t, id.operatorId())
		assert.NotContains(t, opJwt.SigningKeys, pubKey)
	})
}

func TestBackend_AccountSigningKey_Config(t *testing.T) {
	b := testBackend(t)

	testCases := []struct {
		name        string
		scoped      bool
		description string
		template    *jwt.UserPermissionLimits
		err         error
	}{
		{
			name:   "basic",
			scoped: false,
		},
		{
			name:   "basic-scoped",
			scoped: true,
		},
		{
			name:        "custom scope params",
			scoped:      true,
			description: "test-description",
			template: &jwt.UserPermissionLimits{
				Limits: jwt.Limits{
					UserLimits: jwt.UserLimits{
						Src: jwt.CIDRList{"192.0.2.0/24"},
					},
					NatsLimits: jwt.NatsLimits{
						Subs:    10,
						Payload: 10,
						Data:    10,
					},
				},
				ProxyRequired: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id := AccountSigningKeyId("op1", "acc1", "s1")
			SetupTestAccount(b, id.accountId(), nil)
			defer DeleteConfig(b, id.accountId())

			var templateMapping map[string]any
			if tc.template != nil {
				res, err := json.Marshal(tc.template)
				require.NoError(b, err)
				err = json.Unmarshal(res, &templateMapping)
				require.NoError(b, err)
			} else {
				templateMapping = nil
			}

			// create the signing key
			resp, err := WriteConfig(b, id, map[string]any{
				"scoped":              tc.scoped,
				"description":         tc.description,
				"permission_template": templateMapping,
			})
			RequireNoRespError(b, resp, err)

			pubKey := ReadPublicKey(b, id)

			accJwt := ReadAccountJwt(b, id.accountId())
			assert.Contains(b, accJwt.SigningKeys, pubKey)

			scope := accJwt.SigningKeys[pubKey]

			if tc.scoped {
				assert.IsType(b, &jwt.UserScope{}, scope)
				userScope := scope.(*jwt.UserScope)

				// jwt has some special handling for default permissions
				var template jwt.UserPermissionLimits
				if tc.template == nil {
					template = jwt.NewUserScope().Template
				} else {
					template = *tc.template
				}

				assert.Equal(b, jwt.UserScopeType, userScope.Kind)
				assert.Equal(b, id.name, userScope.Role)
				assert.Equal(b, tc.description, userScope.Description)
				assert.Equal(b, template, userScope.Template)
			} else {
				assert.Nil(b, scope)
			}

			// delete signing key
			DeleteConfig(b, id)

			// jwt should not contain signing key
			accJwt = ReadAccountJwt(b, id.accountId())
			assert.NotContains(b, accJwt.SigningKeys, pubKey)
		})
	}
}

func TestBackend_OperatorSigningKey_List(_t *testing.T) {
	t := testBackend(_t)

	opId := OperatorId("op1")
	SetupTestOperator(t, opId, nil)

	sk1Id := opId.signingKeyId("sk1")
	resp, err := WriteConfig(t, sk1Id, nil)
	RequireNoRespError(t, resp, err)

	sk2Id := opId.signingKeyId("sk2")
	resp, err = WriteConfig(t, sk2Id, nil)
	RequireNoRespError(t, resp, err)

	sk3Id := opId.signingKeyId("sk3")
	resp, err = WriteConfig(t, sk3Id, nil)
	RequireNoRespError(t, resp, err)

	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      opId.signingKeyPrefix(),
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err = t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	assert.Equal(t, []string{"sk1", "sk2", "sk3"}, resp.Data["keys"])
}

func TestBackend_AccountSigningKey_List(_t *testing.T) {
	t := testBackend(_t)

	accId := AccountId("op1", "acc1")
	SetupTestAccount(t, accId, nil)

	sk1Id := accId.signingKeyId("sk1")
	resp, err := WriteConfig(t, sk1Id, nil)
	RequireNoRespError(t, resp, err)

	sk2Id := accId.signingKeyId("sk2")
	resp, err = WriteConfig(t, sk2Id, nil)
	RequireNoRespError(t, resp, err)

	sk3Id := accId.signingKeyId("sk3")
	resp, err = WriteConfig(t, sk3Id, nil)
	RequireNoRespError(t, resp, err)

	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      accId.signingKeyPrefix(),
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err = t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	assert.Equal(t, []string{"sk1", "sk2", "sk3"}, resp.Data["keys"])
}
