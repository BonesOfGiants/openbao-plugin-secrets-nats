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

func TestBackend_User_Creds(ts *testing.T) {
	b := testBackend(ts)

	// run in a synctest bubble to accurately assess ttl/expires
	synctest.Test(ts, func(t *testing.T) {
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

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(b, id, map[string]any{
			"claims": unmarshalToMap([]byte(claims)),
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
		assert.Equal(b, parsedClaims.ClaimsData.Audience, userClaims.ClaimsData.Audience)
		assert.Equal(b, parsedClaims.ClaimsData.NotBefore, userClaims.ClaimsData.NotBefore)

		// fixed claim data
		accountPublicKey := ReadPublicKey(b, id.accountId())
		assert.Equal(b, accountPublicKey, userClaims.ClaimsData.Issuer)
		assert.Equal(b, userPublicKey, userClaims.ClaimsData.Subject)
		assert.Equal(b, id.user, userClaims.ClaimsData.Name)
		assert.Equal(b, jwt.ClaimType(jwt.UserClaim), userClaims.User.GenericFields.Type)
		assert.Equal(b, libVersion, userClaims.User.GenericFields.Version)
		assert.Equal(b, "", userClaims.User.IssuerAccount)

		// user config
		assert.Equal(b, parsedClaims.User.UserPermissionLimits, userClaims.User.UserPermissionLimits)

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
