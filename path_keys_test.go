package natsbackend

import (
	"encoding/json"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackend_Operator_SigningKey(t *testing.T) {
	b := testBackend(t)

	id := OperatorSigningKeyId("op1", "s1")
	SetupTestOperator(b, id.operatorId(), nil)

	// create the signing key
	resp, err := WriteConfig(b, id, nil)
	RequireNoRespError(b, resp, err)

	pubKey := ReadPublicKey(b, id)

	// operator jwt should contain the signing key
	opJwt := ReadOperatorJwt(b, id.operatorId())
	assert.Contains(b, opJwt.SigningKeys, pubKey)

	// delete signing key
	DeleteConfig(b, id)

	// operator jwt should not contain the signing key
	opJwt = ReadOperatorJwt(b, id.operatorId())
	assert.NotContains(b, opJwt.SigningKeys, pubKey)
}

func TestBackend_Account_SigningKey(t *testing.T) {
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
