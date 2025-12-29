package natsbackend

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
)

func TestBackend_Revocation_Config(t *testing.T) {
	synctest.Test(t, func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, map[string]any{
			"claims": map[string]any{
				"nats": map[string]any{
					"limits": map[string]any{
						"imports": -1,
						"exports": -1,
					},
				},
			},
		})

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

func TestBackend_Revocation_List(_t *testing.T) {
	t := testBackend(_t)

	accId := AccountId("op1", "acc1")
	SetupTestAccount(t, accId, map[string]any{
		"claims": map[string]any{
			"nats": map[string]any{
				"limits": map[string]any{
					"imports": -1,
					"exports": -1,
				},
			},
		},
	})

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
		SetupTestAccount(t, accId, map[string]any{
			"claims": map[string]any{
				"nats": map[string]any{
					"limits": map[string]any{
						"imports": -1,
						"exports": -1,
					},
				},
			},
		})

		WriteConfig(t, accId.revocationId("U123"), map[string]any{
			"ttl": "10s",
		})

		revConfig := ReadConfig[accountRevocationEntry](t, accId.revocationId("U123"))

		assert.Equal(t, time.Now(), revConfig.CreationTime)
		assert.Equal(t, 10*time.Second, revConfig.Ttl)

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
