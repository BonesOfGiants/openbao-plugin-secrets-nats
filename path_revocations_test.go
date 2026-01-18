package natsbackend

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackend_Revocation_Config(t *testing.T) {
	synctest.Test(t, func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		WriteConfig(t, accId.revocationId("U123"), nil)

		revConfig := ReadConfig[accountRevocationEntry](t, accId.revocationId("U123"))

		assert.Equal(t, time.Now(), revConfig.CreationTime)
		assert.Equal(t, 0*time.Second, revConfig.Ttl)

		// the account jwt should contain the revoke with the proper time
		accJwt := ReadAccountJwt(t, accId)
		entry, ok := accJwt.Account.Revocations["U123"]
		assert.True(t, ok, "revocations do not contain user id")
		assert.Equal(t, time.Now().Unix(), entry)

		DeleteConfig(t, accId.revocationId("U123"))

		// the revocation should be removed from the jwt
		accJwt = ReadAccountJwt(t, accId)
		assert.NotContains(t, accJwt.Account.Revocations, "U123")
	})
}

func TestBackend_Revocation_NonExistentAccount(_t *testing.T) {
	t := testBackend(_t)

	id := AccountRevocationId("op1", "acc1", "U123")
	resp, err := WriteConfig(t, id, nil)
	assert.NoError(t, err)
	assert.ErrorContains(t, resp.Error(), "account \"acc1\" does not exist")
}

func TestBackend_Revocation_List(_t *testing.T) {
	t := testBackend(_t)

	accId := AccountId("op1", "acc1")
	SetupTestAccount(t, accId, nil)

	WriteConfig(t, accId.revocationId("U123"), nil)
	WriteConfig(t, accId.revocationId("U234"), nil)
	WriteConfig(t, accId.revocationId("U345"), nil)

	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      accId.revocationPrefix(),
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	assert.Equal(t, []string{"U123", "U234", "U345"}, resp.Data["keys"])

	DeleteConfig(t, accId.revocationId("U123"))
	DeleteConfig(t, accId.revocationId("U234"))
	DeleteConfig(t, accId.revocationId("U345"))

	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      accId.revocationPrefix(),
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err = t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	assert.NotContains(t, resp.Data, "keys")
}

func TestBackend_Revocation_AutoDelete(t *testing.T) {
	synctest.Test(t, func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		WriteConfig(t, accId.revocationId("U123"), map[string]any{
			"ttl": "10s",
		})

		resp, err := ReadConfigRaw(t, accId.revocationId("U123"))
		RequireNoRespError(t, resp, err)

		assert.Equal(t, time.Now(), resp.Data["creation_time"])
		assert.Equal(t, 10, resp.Data["ttl"])

		// the account jwt should contain the revoke with the proper time
		accJwt := ReadAccountJwt(t, accId)
		assert.Contains(t, accJwt.Account.Revocations, "U123")
		assert.Equal(t, time.Now().Unix(), accJwt.Account.Revocations["U123"])

		TickPeriodic(t)

		// the account jwt should still contain the revoke since the ttl has not passed
		accJwt = ReadAccountJwt(t, accId)
		assert.Contains(t, accJwt.Account.Revocations, "U123")

		// let some time pass...
		time.Sleep(minRollbackAge * 2)

		TickPeriodic(t)

		// the revocation should be removed from the jwt
		accJwt = ReadAccountJwt(t, accId)
		assert.NotContains(t, accJwt.Account.Revocations, "U123")
	})
}

func TestBackend_Revocation_Sync(t *testing.T) {
	t.Run("sync on revocation create", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		defer nats.AssertNoLingering(_t)
		t := testBackendWithNats(_t, nats)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		resp, err := WriteAccountServer(t, accId.operatorId(), map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		var receivedJwt string
		ExpectUpdateSync(t, nats, &receivedJwt)

		userId := "U123"
		WriteConfig(t, accId.revocationId(userId), map[string]any{
			"ttl": "10s",
		})

		claims, err := jwt.DecodeAccountClaims(receivedJwt)
		require.NoError(t, err)

		assert.Contains(t, claims.Revocations, userId)
	})
	t.Run("sync on revocation delete", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		defer nats.AssertNoLingering(_t)
		t := testBackendWithNats(_t, nats)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		resp, err := WriteAccountServer(t, accId.operatorId(), map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"suspend":         true,
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		userId := "U123"
		WriteConfig(t, accId.revocationId(userId), map[string]any{
			"ttl": "10s",
		})

		resp, err = WriteAccountServer(t, accId.operatorId(), map[string]any{
			"suspend":  false,
			"sync_now": false,
		})
		RequireNoRespError(t, resp, err)

		var receivedJwt string
		ExpectUpdateSync(t, nats, &receivedJwt)

		resp, err = DeleteConfig(t, accId.revocationId(userId))
		RequireNoRespError(t, resp, err)

		claims, err := jwt.DecodeAccountClaims(receivedJwt)
		require.NoError(t, err)

		assert.NotContains(t, claims.Revocations, userId)
	})
	t.Run("sync on revocation expire", func(t *testing.T) {
		synctest.Test(t, func(_t *testing.T) {
			nats := abstractnats.NewMock(_t)
			defer nats.AssertNoLingering(_t)
			t := testBackendWithNats(_t, nats)

			accId := AccountId("op1", "acc1")
			SetupTestAccount(t, accId, nil)

			resp, err := WriteAccountServer(t, accId.operatorId(), map[string]any{
				"servers":         []string{"nats://localhost:4222"},
				"suspend":         true,
				"sync_now":        false,
				"disable_lookups": true,
			})
			RequireNoRespError(t, resp, err)

			userId := "U123"
			WriteConfig(t, accId.revocationId(userId), map[string]any{
				"ttl": "10s",
			})

			resp, err = WriteAccountServer(t, accId.operatorId(), map[string]any{
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
			assert.NotContains(t, claims.Revocations, userId)
		})
	})
}
