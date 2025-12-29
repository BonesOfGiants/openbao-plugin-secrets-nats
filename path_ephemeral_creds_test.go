package natsbackend

import (
	"encoding/json"
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

			claims := `
			{
				"aud": "test-audience",
				"exp": 1766703476,
				"iat": 1766703476,
				"iss": "test-subject",
				"name": "test-name",
				"nats": {
					"allowed_connection_types": [
						"LEAFNODE"
					],
					"bearer_token": true,
					"issuer_account": "test-account",
					"proxy_required": true,
					"pub": {
						"allow": [
							"allowed"
						],
						"deny": [
							"denied"
						]
					},
					"resp": {
						"max": 10,
						"ttl": 10
					},
					"src": [
						"192.0.2.0/24"
					],
					"subs": 0,
					"data": 0,
					"payload": 0,
					"sub": {
						"allow": [
							"allowed"
						],
						"deny": [
							"denied"
						]
					},
					"tags": [
						"test-tag"
					],
					"times": [
						{
							"end": "12:00:00",
							"start": "10:00:00"
						}
					],
					"times_location": "America/New_York",
					"type": "test-type"
				},
				"nbf": 1766703476,
				"sub": "test-subject"
			}`

			var parsedClaims jwt.UserClaims
			err := json.Unmarshal([]byte(claims), &parsedClaims)

			id := EphemeralUserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"claims": unmarshalToMap([]byte(claims)),
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
			assert.Equal(t, parsedClaims.ClaimsData.Audience, userClaims.ClaimsData.Audience)
			assert.Equal(t, parsedClaims.ClaimsData.NotBefore, userClaims.ClaimsData.NotBefore)

			// fixed claim data
			accountPublicKey := ReadPublicKey(t, id.accountId())
			assert.Equal(t, accountPublicKey, userClaims.ClaimsData.Issuer)
			assert.Equal(t, credsPublicKey, userClaims.ClaimsData.Subject)
			assert.Equal(t, sessionName, userClaims.ClaimsData.Name)
			assert.Equal(t, jwt.ClaimType(jwt.UserClaim), userClaims.User.GenericFields.Type)
			assert.Equal(t, libVersion, userClaims.User.GenericFields.Version)
			assert.Equal(t, "", userClaims.User.IssuerAccount)

			// user config
			assert.Equal(t, parsedClaims.User.UserPermissionLimits, userClaims.User.UserPermissionLimits)

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
