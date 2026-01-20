package natsbackend

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createUserSubject(t testContext) string {
	t.Helper()

	nkey, err := nkeys.CreateUser()
	require.NoError(t, err)

	sub, err := nkey.PublicKey()
	require.NoError(t, err)

	return sub
}

func TestBackend_Revocation_Config(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			t := testBackend(_t)

			accId := AccountId("op1", "acc1")
			SetupTestAccount(t, accId, nil)

			sub := createUserSubject(t)

			WriteConfig(t, accId.revocationId(sub), nil)

			resp, err := ReadConfig(t, accId.revocationId(sub))
			RequireNoRespError(t, resp, err)

			assert.EqualValues(t, time.Now().Unix(), resp.Data["creation_time"])
			assert.EqualValues(t, 0*time.Second, resp.Data["ttl"])

			// the account jwt should contain the revoke with the proper time
			accJwt := ReadAccountJwt(t, accId)
			entry, ok := accJwt.Account.Revocations[sub]
			assert.True(t, ok, "revocations do not contain user id")
			assert.Equal(t, time.Now().Unix(), entry)

			DeleteConfig(t, accId.revocationId(sub), nil)

			// the revocation should be removed from the jwt
			accJwt = ReadAccountJwt(t, accId)
			assert.NotContains(t, accJwt.Account.Revocations, sub)
		})
	})

	t.Run("invalid subject", func(_t *testing.T) {
		t := testBackend(_t)

		id := AccountRevocationId("op1", "acc1", "bad-subject")
		resp, err := WriteConfig(t, id, nil)
		assert.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "subject must be a valid user public key")
	})

	t.Run("non-existent account", func(_t *testing.T) {
		t := testBackend(_t)

		sub := createUserSubject(t)

		id := AccountRevocationId("op1", "acc1", sub)
		resp, err := WriteConfig(t, id, nil)
		assert.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "account \"acc1\" does not exist")
	})

	t.Run("list", func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		sub1 := createUserSubject(t)
		sub2 := createUserSubject(t)
		sub3 := createUserSubject(t)

		resp, err := WriteConfig(t, accId.revocationId(sub1), nil)
		RequireNoRespError(t, resp, err)
		resp, err = WriteConfig(t, accId.revocationId(sub2), nil)
		RequireNoRespError(t, resp, err)
		resp, err = WriteConfig(t, accId.revocationId(sub3), nil)
		RequireNoRespError(t, resp, err)

		resp, err = ListPath(t, accId.revocationPrefix())
		RequireNoRespError(t, resp, err)

		assert.ElementsMatch(t, []string{sub1, sub2, sub3}, resp.Data["keys"])

		resp, err = DeleteConfig(t, accId.revocationId(sub1), nil)
		RequireNoRespError(t, resp, err)
		resp, err = DeleteConfig(t, accId.revocationId(sub2), nil)
		RequireNoRespError(t, resp, err)
		resp, err = DeleteConfig(t, accId.revocationId(sub3), nil)
		RequireNoRespError(t, resp, err)

		resp, err = ListPath(t, accId.revocationPrefix())
		RequireNoRespError(t, resp, err)

		assert.NotContains(t, resp.Data, "keys")
	})

	t.Run("existence check", func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		sub := createUserSubject(t)

		resp, err := WriteConfig(t, accId.revocationId(sub), nil)
		RequireNoRespError(t, resp, err)

		hasCheck, found, err := ExistenceCheckConfig(t, accId.revocationId(sub))
		assert.NoError(t, err)
		assert.True(t, hasCheck, "existence check not found")
		assert.True(t, found, "item not found")
	})
}

func TestBackend_Revocation_AutoDelete(t *testing.T) {
	synctest.Test(t, func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		sub := createUserSubject(t)

		WriteConfig(t, accId.revocationId(sub), map[string]any{
			"ttl": "10s",
		})

		resp, err := ReadConfig(t, accId.revocationId(sub))
		RequireNoRespError(t, resp, err)

		assert.EqualValues(t, time.Now().Unix(), resp.Data["creation_time"])
		assert.EqualValues(t, 10, resp.Data["ttl"])

		// the account jwt should contain the revoke with the proper time
		accJwt := ReadAccountJwt(t, accId)
		assert.Contains(t, accJwt.Account.Revocations, sub)
		assert.Equal(t, time.Now().Unix(), accJwt.Account.Revocations[sub])

		TickPeriodic(t)

		// the account jwt should still contain the revoke since the ttl has not passed
		accJwt = ReadAccountJwt(t, accId)
		assert.Contains(t, accJwt.Account.Revocations, sub)

		// let some time pass...
		time.Sleep(minRollbackAge * 2)

		TickPeriodic(t)

		// the revocation should be removed from the jwt
		accJwt = ReadAccountJwt(t, accId)
		assert.NotContains(t, accJwt.Account.Revocations, sub)
	})
}

func TestBackend_Revocation_Sync(t *testing.T) {
	t.Run("sync on revocation create", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		defer nats.AssertNoLingering(_t)
		t := testBackendWithNats(_t, nats)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		resp, err := WriteConfig(t, accId.operatorId().accountServerId(), map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		var receivedJwt string
		ExpectUpdateSync(t, nats, &receivedJwt)

		sub := createUserSubject(t)
		WriteConfig(t, accId.revocationId(sub), map[string]any{
			"ttl": "10s",
		})

		claims, err := jwt.DecodeAccountClaims(receivedJwt)
		require.NoError(t, err)

		assert.Contains(t, claims.Revocations, sub)
	})
	t.Run("sync on revocation delete", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		defer nats.AssertNoLingering(_t)
		t := testBackendWithNats(_t, nats)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		resp, err := WriteConfig(t, accId.operatorId().accountServerId(), map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"suspend":         true,
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		sub := createUserSubject(t)
		WriteConfig(t, accId.revocationId(sub), map[string]any{
			"ttl": "10s",
		})

		resp, err = WriteConfig(t, accId.operatorId().accountServerId(), map[string]any{
			"suspend":  false,
			"sync_now": false,
		})
		RequireNoRespError(t, resp, err)

		var receivedJwt string
		ExpectUpdateSync(t, nats, &receivedJwt)

		resp, err = DeleteConfig(t, accId.revocationId(sub), nil)
		RequireNoRespError(t, resp, err)

		claims, err := jwt.DecodeAccountClaims(receivedJwt)
		require.NoError(t, err)

		assert.NotContains(t, claims.Revocations, sub)
	})
	t.Run("sync on revocation expire", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			nats := abstractnats.NewMock(_t)
			defer nats.AssertNoLingering(_t)
			t := testBackendWithNats(_t, nats)

			accId := AccountId("op1", "acc1")
			SetupTestAccount(t, accId, nil)

			resp, err := WriteConfig(t, accId.operatorId().accountServerId(), map[string]any{
				"servers":         []string{"nats://localhost:4222"},
				"suspend":         true,
				"sync_now":        false,
				"disable_lookups": true,
			})
			RequireNoRespError(t, resp, err)

			sub := createUserSubject(t)
			WriteConfig(t, accId.revocationId(sub), map[string]any{
				"ttl": "10s",
			})

			resp, err = WriteConfig(t, accId.operatorId().accountServerId(), map[string]any{
				"suspend":  false,
				"sync_now": false,
			})
			RequireNoRespError(t, resp, err)

			var receivedJwt string
			ExpectUpdateSync(t, nats, &receivedJwt)

			// let some time pass...
			time.Sleep(minRollbackAge * 2)

			TickPeriodic(t)

			claims, err := jwt.DecodeAccountClaims(receivedJwt)
			require.NoError(t, err)

			// the update should not contain the user id
			assert.NotContains(t, claims.Revocations, sub)
		})
	})
}
