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

func TestBackend_EphemeralCreds_Read(t *testing.T) {
	t.Run("old-style template", func(t *testing.T) {
		// run in a synctest bubble to accurately assess ttl/expires
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			claims := `
			{
				"nats": {
					"tags": [
						"test-tag"
					]
				}
			}`

			var parsedClaims jwt.UserClaims
			err := json.Unmarshal([]byte(claims), &parsedClaims)

			id := EphemeralUserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"claims": unmarshalToMap(json.RawMessage(claims)),
			})

			sessionName := "test"
			resp, err := ReadEphemeralCreds(t, id, sessionName, nil)
			RequireNoRespError(t, resp, err)

			creds, ok := resp.Data["creds"]
			require.True(t, ok)

			claimBytes, err := jwt.ParseDecoratedJWT([]byte(creds.(string)))
			require.NoError(t, err)

			rawClaims, err := jwt.Decode(claimBytes)
			require.NoError(t, err)

			userClaims, ok := rawClaims.(*jwt.UserClaims)
			require.True(t, ok)

			// user config
			assert.Equal(t, parsedClaims.User.Tags, userClaims.User.Tags)
		})
	})

	t.Run("complex claims template", func(t *testing.T) {
		// run in a synctest bubble to accurately assess ttl/expires
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			claims := `
			{
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
			}`

			var parsedClaims jwt.User
			err := json.Unmarshal([]byte(claims), &parsedClaims)

			id := EphemeralUserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"claims": unmarshalToMap(json.RawMessage(claims)),
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

			// fixed claim data
			accountPublicKey := ReadPublicKey(t, id.accountId())
			assert.Equal(t, accountPublicKey, userClaims.ClaimsData.Issuer)
			assert.Equal(t, credsPublicKey, userClaims.ClaimsData.Subject)
			assert.Equal(t, sessionName, userClaims.ClaimsData.Name)
			assert.Equal(t, jwt.ClaimType(jwt.UserClaim), userClaims.User.GenericFields.Type)
			assert.Equal(t, libVersion, userClaims.User.GenericFields.Version)
			assert.Equal(t, "", userClaims.User.IssuerAccount)

			// user config
			assert.Equal(t, parsedClaims.UserPermissionLimits, userClaims.User.UserPermissionLimits)

			// test system sets a 24hr default lease ttl
			expectedExpires := time.Now().Add(24 * time.Hour).Unix()
			assert.Equal(t, expectedExpires, userClaims.ClaimsData.Expires)

			// new creds should have a different seed
			resp, err = ReadEphemeralCreds(t, id, "test", nil)
			RequireNoRespError(t, resp, err)
			newSeed, ok := resp.Data["seed"]
			require.True(t, ok)
			assert.NotEqual(t, seed, newSeed)

			// delete user
			resp, err = DeleteConfig(t, id, nil)
			RequireNoRespError(t, resp, err)

			// creds should be nil
			resp, err = ReadEphemeralCreds(t, id, "test", nil)
			RequireNoRespError(t, resp, err)
			assert.Nil(t, resp)
		})
	})
}

func TestBackend_EphemeralCreds_Ttl(t *testing.T) {
	t.Run("default creds ttl", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			id := EphemeralUserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"creds_default_ttl": "10m",
			})

			resp, err := ReadEphemeralCreds(t, id, "test", nil)
			RequireNoRespError(t, resp, err)

			userJwt := resp.Data["jwt"]
			expiresAt := resp.Data["expires_at"]

			claims, err := jwt.DecodeUserClaims(userJwt.(string))
			require.NoError(t, err)

			expectedExpiry := time.Now().Add(10 * time.Minute).Unix()
			assert.Equal(t, expectedExpiry, claims.Expires)
			assert.Equal(t, expectedExpiry, expiresAt)
		})
	})

	t.Run("max creds ttl", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			id := EphemeralUserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"creds_default_ttl": "60m",
				"creds_max_ttl":     "10m",
			})

			resp, err := ReadEphemeralCreds(t, id, "test", nil)
			RequireNoRespError(t, resp, err)

			userJwt := resp.Data["jwt"]
			expiresAt := resp.Data["expires_at"]

			claims, err := jwt.DecodeUserClaims(userJwt.(string))
			require.NoError(t, err)

			expectedExpiry := time.Now().Add(10 * time.Minute).Unix()
			assert.Equal(t, expectedExpiry, claims.Expires)
			assert.Equal(t, expectedExpiry, expiresAt)
		})
	})

	t.Run("ttl parameter overrides default", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			id := EphemeralUserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"creds_default_ttl": "60m",
			})

			resp, err := ReadEphemeralCreds(t, id, "test", map[string]any{
				"ttl": "10m",
			})
			RequireNoRespError(t, resp, err)

			userJwt := resp.Data["jwt"]
			expiresAt := resp.Data["expires_at"]

			claims, err := jwt.DecodeUserClaims(userJwt.(string))
			require.NoError(t, err)

			expectedExpiry := time.Now().Add(10 * time.Minute).Unix()
			assert.Equal(t, expectedExpiry, claims.Expires)
			assert.Equal(t, expectedExpiry, expiresAt)
		})
	})

	t.Run("zero ttl uses system default", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			id := EphemeralUserId("op1", "acc1", "user1")
			SetupTestUser(t, id, nil)

			resp, err := ReadEphemeralCreds(t, id, "test", map[string]any{
				"ttl": 0,
			})
			RequireNoRespError(t, resp, err)

			userJwt := resp.Data["jwt"]
			expiresAt := resp.Data["expires_at"]

			claims, err := jwt.DecodeUserClaims(userJwt.(string))
			require.NoError(t, err)

			expectedExpiry := time.Now().Add(t.Backend.System().MaxLeaseTTL()).Unix()
			assert.Equal(t, expectedExpiry, claims.Expires)
			assert.Equal(t, expectedExpiry, expiresAt)
		})
	})

	t.Run("max ttl overrides ttl parameter", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			id := EphemeralUserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"creds_max_ttl": "10m",
			})

			resp, err := ReadEphemeralCreds(t, id, "test", map[string]any{
				"ttl": "60m",
			})
			RequireNoRespError(t, resp, err)

			userJwt := resp.Data["jwt"]
			expiresAt := resp.Data["expires_at"]

			claims, err := jwt.DecodeUserClaims(userJwt.(string))
			require.NoError(t, err)

			expectedExpiry := time.Now().Add(10 * time.Minute).Unix()
			assert.Equal(t, expectedExpiry, claims.Expires)
			assert.Equal(t, expectedExpiry, expiresAt)
		})
	})
}

func TestBackend_EphemeralCreds_SigningKeys(t *testing.T) {
	t.Run("account identity key", func(_t *testing.T) {
		t := testBackend(_t)

		id := EphemeralUserId("op1", "acc1", "user1")
		SetupTestUser(t, id, nil)

		resp, err := ReadEphemeralCreds(t, id, "s1", nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		accountKey := ReadPublicKey(t, id.accountId())
		assert.Equal(t, accountKey, userClaims.Issuer)
	})
	t.Run("account default", func(_t *testing.T) {
		t := testBackend(_t)

		id := EphemeralUserId("op1", "acc1", "user1")
		SetupTestAccount(t, id.accountId(), map[string]any{
			"default_signing_key": "sk1",
		})
		resp, err := WriteConfig(t, id.accountId().signingKeyId("sk1"), nil)
		RequireNoRespError(t, resp, err)

		SetupTestUser(t, id, nil)

		resp, err = ReadEphemeralCreds(t, id, "s1", nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		accountKey := ReadPublicKey(t, id.accountId().signingKeyId("sk1"))
		assert.Equal(t, accountKey, userClaims.Issuer)
	})
	t.Run("user default overrides account default", func(_t *testing.T) {
		t := testBackend(_t)

		id := EphemeralUserId("op1", "acc1", "user1")
		SetupTestAccount(t, id.accountId(), map[string]any{
			"default_signing_key": "sk1",
		})
		resp, err := WriteConfig(t, id.accountId().signingKeyId("sk1"), nil)
		RequireNoRespError(t, resp, err)
		resp, err = WriteConfig(t, id.accountId().signingKeyId("sk2"), nil)
		RequireNoRespError(t, resp, err)

		SetupTestUser(t, id, map[string]any{
			"default_signing_key": "sk2",
		})

		resp, err = ReadEphemeralCreds(t, id, "s1", nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		accountKey := ReadPublicKey(t, id.accountId().signingKeyId("sk2"))
		assert.Equal(t, accountKey, userClaims.Issuer)
	})
	t.Run("creds overrides user default", func(_t *testing.T) {
		t := testBackend(_t)

		id := EphemeralUserId("op1", "acc1", "user1")
		SetupTestAccount(t, id.accountId(), nil)
		resp, err := WriteConfig(t, id.accountId().signingKeyId("sk1"), nil)
		RequireNoRespError(t, resp, err)
		resp, err = WriteConfig(t, id.accountId().signingKeyId("sk2"), nil)
		RequireNoRespError(t, resp, err)

		SetupTestUser(t, id, map[string]any{
			"default_signing_key": "sk1",
		})

		resp, err = ReadEphemeralCreds(t, id, "s1", map[string]any{
			"signing_key": "sk2",
		})
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		accountKey := ReadPublicKey(t, id.accountId().signingKeyId("sk2"))
		assert.Equal(t, accountKey, userClaims.Issuer)
	})
	t.Run("non-existent direct fails", func(_t *testing.T) {
		t := testBackend(_t)

		id := EphemeralUserId("op1", "acc1", "user1")
		SetupTestUser(t, id, nil)

		resp, err := ReadEphemeralCreds(t, id, "s1", map[string]any{
			"signing_key": "sk1",
		})
		require.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "failed to generate user creds: invalid signing key \"sk1\" specified")
	})
	t.Run("non-existent user default fails", func(_t *testing.T) {
		t := testBackend(_t)

		id := EphemeralUserId("op1", "acc1", "user1")
		SetupTestUser(t, id, map[string]any{
			"default_signing_key": "sk1",
		})

		resp, err := ReadEphemeralCreds(t, id, "s1", nil)
		require.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "failed to generate user creds: invalid signing key \"sk1\" specified")
	})
	t.Run("non-existent account default fails", func(_t *testing.T) {
		t := testBackend(_t)

		id := EphemeralUserId("op1", "acc1", "user1")
		SetupTestAccount(t, id.accountId(), map[string]any{
			"default_signing_key": "sk1",
		})
		SetupTestUser(t, id, nil)

		resp, err := ReadEphemeralCreds(t, id, "s1", nil)
		require.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "failed to generate user creds: invalid signing key \"sk1\" specified")
	})
}

func TestBackend_EphemeralCreds_Tags(t *testing.T) {
	t.Run("simple merge", func(_t *testing.T) {
		t := testBackend(_t)

		id := EphemeralUserId("op1", "acc1", "user1")
		SetupTestUser(t, id, map[string]any{
			"claims": fromUserClaims(
				&jwt.User{
					UserPermissionLimits: jwt.UserPermissionLimits{
						Permissions: jwt.Permissions{
							Pub: jwt.Permission{
								Allow: []string{"test-subject"},
							},
						},
					},
					GenericFields: jwt.GenericFields{
						Tags: jwt.TagList{"k1:v1"},
					},
				},
			),
		})

		resp, err := ReadEphemeralCreds(t, id, "s1", map[string]any{
			"tags": []string{"k2:v2"},
		})
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.Equal(t, jwt.TagList{"k1:v1", "k2:v2"}, userClaims.Tags)
	})
	t.Run("simple deduplicate", func(_t *testing.T) {
		t := testBackend(_t)

		id := EphemeralUserId("op1", "acc1", "user1")
		SetupTestUser(t, id, map[string]any{
			"claims": fromUserClaims(
				&jwt.User{
					UserPermissionLimits: jwt.UserPermissionLimits{
						Permissions: jwt.Permissions{
							Pub: jwt.Permission{
								Allow: []string{"test-subject"},
							},
						},
					},
					GenericFields: jwt.GenericFields{
						Tags: jwt.TagList{"k1:v1"},
					},
				},
			),
		})

		resp, err := ReadEphemeralCreds(t, id, "s1", map[string]any{
			"tags": []string{"k1:v1"},
		})
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.Equal(t, jwt.TagList{"k1:v1"}, userClaims.Tags)
	})
	t.Run("deduplicate in claims", func(_t *testing.T) {
		t := testBackend(_t)

		id := EphemeralUserId("op1", "acc1", "user1")
		SetupTestUser(t, id, map[string]any{
			"claims": fromUserClaims(
				&jwt.User{
					UserPermissionLimits: jwt.UserPermissionLimits{
						Permissions: jwt.Permissions{
							Pub: jwt.Permission{
								Allow: []string{"test-subject"},
							},
						},
					},
					GenericFields: jwt.GenericFields{
						Tags: jwt.TagList{"k1:v1", "k1:v1"},
					},
				},
			),
		})

		resp, err := ReadEphemeralCreds(t, id, "s1", nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.Equal(t, jwt.TagList{"k1:v1"}, userClaims.Tags)
	})
}
