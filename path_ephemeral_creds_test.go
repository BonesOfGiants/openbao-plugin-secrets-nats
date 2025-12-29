package natsbackend

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackend_EphemeralUser_Creds(t *testing.T) {
	t.Run("complex claims template", func(t *testing.T) {
		// run in a synctest bubble to accurately assess ttl/expires
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			claims := &jwt.UserClaims{
				ClaimsData: jwt.ClaimsData{
					// overwritten
					IssuedAt: 1766703476,
					Subject:  "test-subject",
					Issuer:   "test-subject",
					Name:     "test-name",

					// preserved
					Expires:   1766703476,
					Audience:  "test-audience",
					NotBefore: 1766703476,
				},
				User: jwt.User{
					IssuerAccount: "test-account", // overwritten
					UserPermissionLimits: jwt.UserPermissionLimits{
						Permissions: jwt.Permissions{
							Pub: jwt.Permission{
								Allow: jwt.StringList{"allowed"},
								Deny:  jwt.StringList{"denied"},
							},
							Sub: jwt.Permission{
								Allow: jwt.StringList{"allowed"},
								Deny:  jwt.StringList{"denied"},
							},
							Resp: &jwt.ResponsePermission{
								MaxMsgs: 10,
								Expires: 10,
							},
						},
						Limits: jwt.Limits{
							UserLimits: jwt.UserLimits{
								Src: jwt.CIDRList{
									"192.0.2.0/24",
								},
								Times: []jwt.TimeRange{
									{
										Start: "10:00:00",
										End:   "12:00:00",
									},
								},
								Locale: "America/New_York",
							},
							NatsLimits: jwt.NatsLimits{
								Subs:    0,
								Data:    0,
								Payload: 0,
							},
						},
						BearerToken:   true,
						ProxyRequired: true,
						AllowedConnectionTypes: jwt.StringList{
							jwt.ConnectionTypeLeafnode,
						},
					},
					GenericFields: jwt.GenericFields{
						Tags:    jwt.TagList{"test-tag"},
						Type:    "test-type",
						Version: 0,
					},
				},
			}

			id := EphemeralUserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"claims": unmarshalToMap(fromUserClaims(claims)),
			})

			sessionName := "test"
			resp, err := ReadEphemeralCreds(t, id, sessionName, nil)
			RequireNoRespError(t, resp, err)

			creds, ok := resp.Data["creds"]
			require.True(t, ok)

			userJwt, ok := resp.Data["jwt"]
			require.True(t, ok)

			seed, ok := resp.Data["seed"]
			require.True(t, ok)

			kpFromSeed, err := nkeys.FromSeed([]byte(seed.(string)))
			require.NoError(t, err)
			seedPrivateKey, err := kpFromSeed.PrivateKey()
			require.NoError(t, err)
			seedPublicKey, err := kpFromSeed.PublicKey()
			require.NoError(t, err)

			credsKeyPair, err := jwt.ParseDecoratedUserNKey([]byte(creds.(string)))
			require.NoError(t, err)
			claimBytes, err := jwt.ParseDecoratedJWT([]byte(creds.(string)))
			require.NoError(t, err)

			// the nkey should match the user nkey
			credsPublicKey, err := credsKeyPair.PublicKey()
			require.NoError(t, err)
			credsPrivateKey, err := credsKeyPair.PrivateKey()
			require.NoError(t, err)

			rawClaims, err := jwt.Decode(claimBytes)
			require.NoError(t, err)

			userClaims, ok := rawClaims.(*jwt.UserClaims)
			require.True(t, ok)

			// check that the jwt and creds jwt are the same
			assert.Equal(t, userJwt, string(claimBytes))

			// check nkey match
			assert.Equal(t, seedPrivateKey, credsPrivateKey)
			assert.Equal(t, seedPublicKey, credsPublicKey)

			// custom claim data
			assert.Equal(t, claims.ClaimsData.Audience, userClaims.ClaimsData.Audience)
			assert.Equal(t, claims.ClaimsData.NotBefore, userClaims.ClaimsData.NotBefore)

			// fixed claim data
			accountPublicKey := ReadPublicKey(t, id.accountId())
			assert.Equal(t, accountPublicKey, userClaims.ClaimsData.Issuer)
			assert.Equal(t, credsPublicKey, userClaims.ClaimsData.Subject)
			assert.Equal(t, sessionName, userClaims.ClaimsData.Name)
			assert.Equal(t, jwt.ClaimType(jwt.UserClaim), userClaims.User.GenericFields.Type)
			assert.Equal(t, libVersion, userClaims.User.GenericFields.Version)
			assert.Equal(t, "", userClaims.User.IssuerAccount)

			// user config
			assert.Equal(t, claims.User.UserPermissionLimits, userClaims.User.UserPermissionLimits)

			// test system sets a 24hr default lease ttl
			expectedExpires := time.Now().Add(24 * time.Hour)
			assert.Equal(t, expectedExpires.Unix(), userClaims.ClaimsData.Expires)

			// new creds should have a different seed
			resp, err = ReadEphemeralCreds(t, id, "test", nil)
			RequireNoRespError(t, resp, err)
			newSeed, ok := resp.Data["seed"]
			require.True(t, ok)
			assert.NotEqual(t, seed, newSeed)

			// delete user
			resp, err = DeleteConfig(t, id)
			RequireNoRespError(t, resp, err)

			// creds should be nil
			resp, err = ReadEphemeralCreds(t, id, "test", nil)
			RequireNoRespError(t, resp, err)
			assert.Nil(t, resp)
		})
	})

	t.Run("default signing key", func(_t *testing.T) {
		t := testBackend(_t)

		id := EphemeralUserId("op1", "acc1", "user1")

		SetupTestAccount(t, id.accountId(), nil)

		resp, err := WriteConfig(t, id.accountId().signingKeyId("sk1"), nil)
		RequireNoRespError(t, resp, err)

		SetupTestUser(t, id, map[string]any{
			"default_signing_key": "sk1",
		})

		resp, err = ReadEphemeralCreds(t, id, "test", nil)
		RequireNoRespError(t, resp, err)

		userJwt := resp.Data["jwt"]

		claims, err := jwt.DecodeUserClaims(userJwt.(string))
		require.NoError(t, err)

		accPubKey := ReadPublicKey(t, id.accountId())
		skPubKey := ReadPublicKey(t, id.accountId().signingKeyId("sk1"))

		assert.Equal(t, accPubKey, claims.IssuerAccount)
		assert.Equal(t, skPubKey, claims.Issuer)
	})
}
