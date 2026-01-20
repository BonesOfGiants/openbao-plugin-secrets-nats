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
		DeleteConfig(t, id, nil)

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
		DeleteConfig(t, id, nil)

		// operator jwt should not contain the signing key
		opJwt = ReadOperatorJwt(t, id.operatorId())
		assert.NotContains(t, opJwt.SigningKeys, pubKey)
	})

	t.Run("existence check", func(_t *testing.T) {
		t := testBackend(_t)

		id := OperatorSigningKeyId("op1", "sk1")
		SetupTestOperator(t, id.operatorId(), nil)

		resp, err := WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		hasCheck, found, err := ExistenceCheckConfig(t, id)
		assert.NoError(t, err)
		assert.True(t, hasCheck, "existence check not found")
		assert.True(t, found, "item not found")
	})

	t.Run("list", func(_t *testing.T) {
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

		assert.ElementsMatch(t, []string{"sk1", "sk2", "sk3"}, resp.Data["keys"])
	})
}

func TestBackend_AccountSigningKey_Config(t *testing.T) {
	testCases := []struct {
		name               string
		scoped             bool
		description        string
		permissionTemplate *jwt.UserPermissionLimits
		err                error
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
			permissionTemplate: &jwt.UserPermissionLimits{
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
		t.Run(tc.name, func(_t *testing.T) {
			t := testBackend(_t)
			id := AccountSigningKeyId("op1", "acc1", "s1")
			SetupTestAccount(t, id.accountId(), nil)
			defer DeleteConfig(t, id.accountId(), nil)

			var template map[string]any
			if tc.permissionTemplate != nil {
				res, err := json.Marshal(tc.permissionTemplate)
				require.NoError(t, err)
				err = json.Unmarshal(res, &template)
				require.NoError(t, err)
			} else {
				template = nil
			}

			// create the signing key
			resp, err := WriteConfig(t, id, map[string]any{
				"scoped":              tc.scoped,
				"description":         tc.description,
				"permission_template": template,
			})
			RequireNoRespError(t, resp, err)

			pubKey := ReadPublicKey(t, id)

			accJwt := ReadAccountJwt(t, id.accountId())
			assert.Contains(t, accJwt.SigningKeys, pubKey)

			scope := accJwt.SigningKeys[pubKey]

			if tc.scoped {
				assert.IsType(t, &jwt.UserScope{}, scope)
				userScope := scope.(*jwt.UserScope)

				// jwt has some special handling for default permissions
				var template jwt.UserPermissionLimits
				if tc.permissionTemplate == nil {
					template = jwt.NewUserScope().Template
				} else {
					template = *tc.permissionTemplate
				}

				assert.Equal(t, jwt.UserScopeType, userScope.Kind)
				assert.Equal(t, id.name, userScope.Role)
				assert.Equal(t, tc.description, userScope.Description)
				assert.Equal(t, template, userScope.Template)
			} else {
				assert.Nil(t, scope)
			}

			// delete signing key
			DeleteConfig(t, id, nil)

			// jwt should not contain signing key
			accJwt = ReadAccountJwt(t, id.accountId())
			assert.NotContains(t, accJwt.SigningKeys, pubKey)
		})
	}

	t.Run("existence check", func(_t *testing.T) {
		t := testBackend(_t)

		id := AccountSigningKeyId("op1", "acc1", "sk1")
		SetupTestAccount(t, id.accountId(), nil)

		resp, err := WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		hasCheck, found, err := ExistenceCheckConfig(t, id)
		assert.NoError(t, err)
		assert.True(t, hasCheck, "existence check not found")
		assert.True(t, found, "item not found")
	})

	t.Run("list", func(_t *testing.T) {
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

		assert.ElementsMatch(t, []string{"sk1", "sk2", "sk3"}, resp.Data["keys"])
	})
}

func TestBackend_OperatorSigningKey_Defaults(t *testing.T) {
	t.Run("deleting/creating sk resigns accounts with operator key", func(_t *testing.T) {
		t := testBackend(_t)

		id := OperatorSigningKeyId("op1", "sk1")
		SetupTestOperator(t, id.operatorId(), nil)

		resp, err := WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		accId := id.operatorId().accountId("acc1")
		SetupTestAccount(t, accId, map[string]any{
			"signing_key": id.name,
		})

		// delete signing key
		resp, err = DeleteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Warnings, "reissued jwt for account \"acc1\" as it was signed with signing key \"sk1\"")
		assert.Contains(t, resp.Warnings, "while reissuing jwt for account \"acc1\": could not use signing key \"sk1\" (from account definition) as it does not exist; defaulting to operator identity key")

		// recreate signing key
		resp, err = WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Warnings, "reissued jwt for account \"acc1\" as it wants to be signed with signing key \"sk1\"")
	})

	t.Run("modifying default sk resigns accounts with default sk", func(_t *testing.T) {
		t := testBackend(_t)

		opId := OperatorId("op1")
		id := opId.signingKeyId("sk1")
		id2 := opId.signingKeyId("sk2")

		SetupTestOperator(t, opId, nil)

		// create signing key
		resp, err := WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		accId := opId.accountId("acc1")
		resp, err = WriteConfig(t, accId, nil)
		RequireNoRespError(t, resp, err)

		// add default signing key
		resp, err = WriteConfig(t, opId, map[string]any{
			"default_signing_key": id.name,
		})
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Warnings, "reissued jwt for account \"acc1\" as it is signed with the default key")

		// modify default signing key
		resp, err = WriteConfig(t, opId, map[string]any{
			"default_signing_key": id2.name,
		})
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Warnings, "reissued jwt for account \"acc1\" as it is signed with the default key")

		// remove default signing key
		resp, err = WriteConfig(t, opId, map[string]any{
			"default_signing_key": "",
		})
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Warnings, "reissued jwt for account \"acc1\" as it is signed with the default key")
	})
}
