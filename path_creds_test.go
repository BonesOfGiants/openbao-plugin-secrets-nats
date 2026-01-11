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

func TestBackend_Creds_Read(t *testing.T) {
	t.Run("complete claims", func(t *testing.T) {
		// run in a synctest bubble to accurately assess ttl/expires
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			claims := `
			{
				"aud": "test-audience",
				"exp": 1766703476,
				"iat": 1766703476,
				"iss": "test-subject",
				"nbf": 1766703476,
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
				"sub": "test-subject"
			}`

			var expected jwt.UserClaims
			err := json.Unmarshal([]byte(claims), &expected)
			require.NoError(t, err)

			id := UserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"claims": unmarshalToMap(json.RawMessage(claims)),
			})

			resp, err := ReadNkeyRaw(t, id)
			RequireNoRespError(t, resp, err)

			userPublicKey, ok := resp.Data["public_key"]
			require.True(t, ok)
			userPrivateKey, ok := resp.Data["private_key"]
			require.True(t, ok)

			resp, err = ReadCreds(t, id, nil)
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
			seedPublicKey, err := kpFromSeed.PublicKey()

			credsKeyPair, err := jwt.ParseDecoratedUserNKey([]byte(creds.(string)))
			require.NoError(t, err)
			claimBytes, err := jwt.ParseDecoratedJWT([]byte(creds.(string)))
			require.NoError(t, err)

			userClaims, err := jwt.DecodeUserClaims(claimBytes)
			require.NoError(t, err)

			// the nkey should match the user nkey
			credsPublicKey, err := credsKeyPair.PublicKey()
			require.NoError(t, err)
			credsPrivateKey, err := credsKeyPair.PrivateKey()
			require.NoError(t, err)

			// user id key
			assert.Equal(t, userPrivateKey, string(credsPrivateKey))
			assert.Equal(t, userPublicKey, credsPublicKey)
			assert.Equal(t, userPrivateKey, string(seedPrivateKey))
			assert.Equal(t, userPublicKey, seedPublicKey)

			// check that the jwt and creds jwt are the same
			assert.Equal(t, userJwt, string(claimBytes))

			// custom claim data
			assert.Equal(t, expected.ClaimsData.Audience, userClaims.ClaimsData.Audience)
			assert.Equal(t, expected.ClaimsData.NotBefore, userClaims.ClaimsData.NotBefore)

			// fixed claim data
			accountPublicKey := ReadPublicKey(t, id.accountId())
			assert.Equal(t, accountPublicKey, userClaims.ClaimsData.Issuer)
			assert.Equal(t, userPublicKey, userClaims.ClaimsData.Subject)
			assert.Equal(t, id.user, userClaims.ClaimsData.Name)
			assert.Equal(t, jwt.ClaimType(jwt.UserClaim), userClaims.User.GenericFields.Type)
			assert.Equal(t, libVersion, userClaims.User.GenericFields.Version)
			assert.Equal(t, "", userClaims.User.IssuerAccount)

			// user config
			assert.Equal(t, expected.User.UserPermissionLimits, userClaims.User.UserPermissionLimits)

			// test system sets a 24hr default lease ttl
			expectedExpires := time.Now().Add(24 * time.Hour)
			assert.Equal(t, expectedExpires.Unix(), userClaims.ClaimsData.Expires)

			// delete user
			resp, err = DeleteConfig(t, id)
			RequireNoRespError(t, resp, err)

			// creds should be nil
			resp, err = ReadCreds(t, id, nil)
			RequireNoRespError(t, resp, err)
			assert.Nil(t, resp)
		})
	})

	t.Run("custom nbf", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, nil)

		time := time.Now().Unix()
		resp, err := ReadCreds(t, id, map[string]any{
			"not_before": time,
		})
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.EqualValues(t, time, userClaims.NotBefore)
	})
}

func TestBackend_Creds_DefaultPermissions(t *testing.T) {
	t.Run("default permissions", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, nil)

		resp, err := ReadCreds(t, id, nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.EqualValues(t, -1, userClaims.Limits.Subs)
		assert.EqualValues(t, -1, userClaims.Limits.Data)
		assert.EqualValues(t, -1, userClaims.Limits.Payload)
	})
	t.Run("zeroes are respected", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, map[string]any{
			"claims": map[string]any{
				"nats": map[string]any{
					"subs":    0,
					"data":    0,
					"payload": 0,
				},
			},
		})

		resp, err := ReadCreds(t, id, nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.EqualValues(t, 0, userClaims.Limits.Subs)
		assert.EqualValues(t, 0, userClaims.Limits.Data)
		assert.EqualValues(t, 0, userClaims.Limits.Payload)
	})
	t.Run("partial defaults", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, map[string]any{
			"claims": map[string]any{
				"nats": map[string]any{
					"subs": 0,
				},
			},
		})

		resp, err := ReadCreds(t, id, nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.EqualValues(t, 0, userClaims.Limits.Subs)
		assert.EqualValues(t, -1, userClaims.Limits.Data)
		assert.EqualValues(t, -1, userClaims.Limits.Payload)
	})
	t.Run("src is respected", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, map[string]any{
			"claims": map[string]any{
				"nats": map[string]any{
					"src": []string{"192.0.2.0/24"},
				},
			},
		})

		resp, err := ReadCreds(t, id, nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.Equal(t, jwt.CIDRList{"192.0.2.0/24"}, userClaims.Limits.Src)
		assert.EqualValues(t, -1, userClaims.Limits.Subs)
		assert.EqualValues(t, -1, userClaims.Limits.Data)
		assert.EqualValues(t, -1, userClaims.Limits.Payload)
	})
	t.Run("scoped override", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestAccount(t, id.accountId(), nil)

		resp, err := WriteConfig(t, id.accountId().signingKeyId("sk1"), map[string]any{
			"scoped": true,
		})
		RequireNoRespError(t, resp, err)

		SetupTestUser(t, id, map[string]any{
			"default_signing_key": "sk1",
			"claims": map[string]any{
				"nats": map[string]any{
					"subs":    10,
					"data":    -1,
					"payload": 142,
				},
			},
		})

		resp, err = ReadCreds(t, id, nil)
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Warnings, "ignoring limits in user claims due to scope")

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.Zero(t, userClaims.UserPermissionLimits)
	})
}

func TestBackend_Creds_Ttl(t *testing.T) {
	t.Run("default creds ttl", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			id := UserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"creds_default_ttl": "10m",
			})

			resp, err := ReadCreds(t, id, nil)
			RequireNoRespError(t, resp, err)

			userJwt := resp.Data["jwt"]
			expiresAt := resp.Data["expires_at"]

			expectedExpiry := time.Now().Add(10 * time.Minute)

			claims, err := jwt.DecodeUserClaims(userJwt.(string))
			require.NoError(t, err)

			assert.Equal(t, expectedExpiry.Unix(), claims.Expires)
			assert.Equal(t, expectedExpiry.Unix(), expiresAt)
		})
	})

	t.Run("max creds ttl", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			id := UserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"creds_default_ttl": "60m",
				"creds_max_ttl":     "10m",
			})

			resp, err := ReadCreds(t, id, nil)
			RequireNoRespError(t, resp, err)

			userJwt := resp.Data["jwt"]
			expiresAt := resp.Data["expires_at"]

			expectedExpiry := time.Now().Add(10 * time.Minute)

			claims, err := jwt.DecodeUserClaims(userJwt.(string))
			require.NoError(t, err)

			assert.Equal(t, expectedExpiry.Unix(), claims.Expires)
			assert.Equal(t, expectedExpiry.Unix(), expiresAt)
		})
	})

	t.Run("ttl parameter overrides default", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			id := UserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"creds_default_ttl": "60m",
			})

			resp, err := ReadCreds(t, id, map[string]any{
				"ttl": "10m",
			})
			RequireNoRespError(t, resp, err)

			userJwt := resp.Data["jwt"]
			expiresAt := resp.Data["expires_at"]

			expectedExpiry := time.Now().Add(10 * time.Minute)

			claims, err := jwt.DecodeUserClaims(userJwt.(string))
			require.NoError(t, err)

			assert.Equal(t, expectedExpiry.Unix(), claims.Expires)
			assert.Equal(t, expectedExpiry.Unix(), expiresAt)
		})
	})

	t.Run("max ttl overrides ttl parameter", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			id := UserId("op1", "acc1", "user1")
			SetupTestUser(t, id, map[string]any{
				"creds_max_ttl": "10m",
			})

			resp, err := ReadCreds(t, id, map[string]any{
				"ttl": "60m",
			})
			RequireNoRespError(t, resp, err)

			userJwt := resp.Data["jwt"]
			expiresAt := resp.Data["expires_at"]

			expectedExpiry := time.Now().Add(10 * time.Minute)

			claims, err := jwt.DecodeUserClaims(userJwt.(string))
			require.NoError(t, err)

			assert.Equal(t, expectedExpiry.Unix(), claims.Expires)
			assert.Equal(t, expectedExpiry.Unix(), expiresAt)
		})
	})
}

func TestBackend_Creds_SigningKeys(t *testing.T) {
	t.Run("account identity key", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, nil)

		resp, err := ReadCreds(t, id, nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		accountKey := ReadPublicKey(t, id.accountId())
		assert.Equal(t, accountKey, userClaims.Issuer)
	})
	t.Run("account default", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestAccount(t, id.accountId(), map[string]any{
			"default_signing_key": "sk1",
		})
		resp, err := WriteConfig(t, id.accountId().signingKeyId("sk1"), nil)
		RequireNoRespError(t, resp, err)

		SetupTestUser(t, id, nil)

		resp, err = ReadCreds(t, id, nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		accountKey := ReadPublicKey(t, id.accountId().signingKeyId("sk1"))
		assert.Equal(t, accountKey, userClaims.Issuer)
	})
	t.Run("user default overrides account default", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
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

		resp, err = ReadCreds(t, id, nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		accountKey := ReadPublicKey(t, id.accountId().signingKeyId("sk2"))
		assert.Equal(t, accountKey, userClaims.Issuer)
	})
	t.Run("creds overrides user default", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestAccount(t, id.accountId(), nil)
		resp, err := WriteConfig(t, id.accountId().signingKeyId("sk1"), nil)
		RequireNoRespError(t, resp, err)
		resp, err = WriteConfig(t, id.accountId().signingKeyId("sk2"), nil)
		RequireNoRespError(t, resp, err)

		SetupTestUser(t, id, map[string]any{
			"default_signing_key": "sk1",
		})

		resp, err = ReadCreds(t, id, map[string]any{
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

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, nil)

		resp, err := ReadCreds(t, id, map[string]any{
			"signing_key": "sk1",
		})
		require.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "failed to generate user creds: invalid signing key \"sk1\" specified")
	})
	t.Run("non-existent user default fails", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, map[string]any{
			"default_signing_key": "sk1",
		})

		resp, err := ReadCreds(t, id, nil)
		require.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "failed to generate user creds: invalid signing key \"sk1\" specified")
	})
	t.Run("non-existent account default fails", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestAccount(t, id.accountId(), map[string]any{
			"default_signing_key": "sk1",
		})
		SetupTestUser(t, id, nil)

		resp, err := ReadCreds(t, id, nil)
		require.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "failed to generate user creds: invalid signing key \"sk1\" specified")
	})
}

func TestBackend_Creds_Tags(t *testing.T) {
	t.Run("simple merge", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, map[string]any{
			"claims": unmarshalToMap(fromUserClaims(
				&jwt.UserClaims{
					User: jwt.User{
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
				},
			)),
		})

		resp, err := ReadCreds(t, id, map[string]any{
			"tags": []string{"k2:v2"},
		})
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.Equal(t, jwt.TagList{"k1:v1", "k2:v2"}, userClaims.Tags)
	})
	t.Run("simple deduplicate", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, map[string]any{
			"claims": unmarshalToMap(fromUserClaims(
				&jwt.UserClaims{
					User: jwt.User{
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
				},
			)),
		})

		resp, err := ReadCreds(t, id, map[string]any{
			"tags": []string{"k1:v1"},
		})
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.Equal(t, jwt.TagList{"k1:v1"}, userClaims.Tags)
	})
	t.Run("deduplicate in claims", func(_t *testing.T) {
		t := testBackend(_t)

		id := UserId("op1", "acc1", "user1")
		SetupTestUser(t, id, map[string]any{
			"claims": unmarshalToMap(fromUserClaims(
				&jwt.UserClaims{
					User: jwt.User{
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
				},
			)),
		})

		resp, err := ReadCreds(t, id, nil)
		RequireNoRespError(t, resp, err)

		userClaims, err := jwt.DecodeUserClaims(resp.Data["jwt"].(string))
		require.NoError(t, err)

		assert.Equal(t, jwt.TagList{"k1:v1"}, userClaims.Tags)
	})
}
