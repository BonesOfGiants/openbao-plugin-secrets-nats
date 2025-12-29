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

func TestBackend_User_Creds(ts *testing.T) {
	b := testBackend(ts)

	// run in a synctest bubble to accurately assess ttl/expires
	synctest.Test(ts, func(t *testing.T) {
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

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(b, id, map[string]any{
			"claims": unmarshalToMap(fromUserClaims(claims)),
		})

		resp, err := ReadNkeyRaw(b, id)
		RequireNoRespError(b, resp, err)

		userPublicKey, ok := resp.Data["public_key"]
		require.True(b, ok)
		userPrivateKey, ok := resp.Data["private_key"]
		require.True(b, ok)

		resp, err = ReadCreds(b, id, nil)
		RequireNoRespError(b, resp, err)

		creds, ok := resp.Data["creds"]
		require.True(b, ok)

		userJwt, ok := resp.Data["jwt"]
		require.True(b, ok)

		seed, ok := resp.Data["seed"]
		require.True(b, ok)

		kpFromSeed, err := nkeys.FromSeed([]byte(seed.(string)))
		require.NoError(b, err)
		seedPrivateKey, err := kpFromSeed.PrivateKey()
		seedPublicKey, err := kpFromSeed.PublicKey()

		credsKeyPair, err := jwt.ParseDecoratedUserNKey([]byte(creds.(string)))
		require.NoError(b, err)
		claimBytes, err := jwt.ParseDecoratedJWT([]byte(creds.(string)))
		require.NoError(b, err)

		rawClaims, err := jwt.Decode(claimBytes)
		require.NoError(b, err)

		userClaims, ok := rawClaims.(*jwt.UserClaims)
		require.True(b, ok)

		// the nkey should match the user nkey
		credsPublicKey, err := credsKeyPair.PublicKey()
		require.NoError(b, err)
		credsPrivateKey, err := credsKeyPair.PrivateKey()
		require.NoError(b, err)

		// user id key
		assert.Equal(b, userPrivateKey, string(credsPrivateKey))
		assert.Equal(b, userPublicKey, credsPublicKey)
		assert.Equal(b, userPrivateKey, string(seedPrivateKey))
		assert.Equal(b, userPublicKey, seedPublicKey)

		// check that the jwt and creds jwt are the same
		assert.Equal(b, userJwt, string(claimBytes))

		// custom claim data
		assert.Equal(b, claims.ClaimsData.Audience, userClaims.ClaimsData.Audience)
		assert.Equal(b, claims.ClaimsData.NotBefore, userClaims.ClaimsData.NotBefore)

		// fixed claim data
		accountPublicKey := ReadPublicKey(b, id.accountId())
		assert.Equal(b, accountPublicKey, userClaims.ClaimsData.Issuer)
		assert.Equal(b, userPublicKey, userClaims.ClaimsData.Subject)
		assert.Equal(b, id.user, userClaims.ClaimsData.Name)
		assert.Equal(b, jwt.ClaimType(jwt.UserClaim), userClaims.User.GenericFields.Type)
		assert.Equal(b, libVersion, userClaims.User.GenericFields.Version)
		assert.Equal(b, "", userClaims.User.IssuerAccount)

		// user config
		assert.Equal(b, claims.User.UserPermissionLimits, userClaims.User.UserPermissionLimits)

		// test system sets a 24hr default lease ttl
		expectedExpires := time.Now().Add(24 * time.Hour)
		assert.Equal(b, expectedExpires.Unix(), userClaims.ClaimsData.Expires)

		// delete user
		resp, err = DeleteConfig(b, id)
		RequireNoRespError(b, resp, err)

		// creds should be nil
		resp, err = ReadCreds(b, id, nil)
		RequireNoRespError(b, resp, err)
		assert.Nil(b, resp)
	})
}
