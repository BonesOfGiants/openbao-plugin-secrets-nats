package natsbackend

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ServerConfigGenerator(t *testing.T) {
	t.Run("json format", func(t *testing.T) {
		b := testBackend(t)
		opId := OperatorId("op1")
		SetupTestOperator(b, opId, nil)

		config := ReadServerConfigJson(b, opId, map[string]any{
			"format": "json",
		})

		assert.Equal(b, map[string]any{
			"operator":       ReadJwtString(b, opId),
			"system_account": ReadPublicKey(b, opId.accountId(DefaultSysAccountName)),
		}, config)
	})

	t.Run("nats format", func(t *testing.T) {
		b := testBackend(t)
		opId := OperatorId("op1")
		SetupTestOperator(b, opId, nil)

		config := ReadServerConfig(b, opId, map[string]any{
			"format": "nats",
		})

		assert.Contains(b, config, fmt.Sprintf("operator: %s\n", ReadJwtString(b, opId)))
		assert.Contains(b, config, fmt.Sprintf("system_account: %s\n", ReadPublicKey(b, opId.accountId(DefaultSysAccountName))))
	})

	t.Run("json with preload", func(t *testing.T) {
		b := testBackend(t)
		opId := OperatorId("op1")
		SetupTestOperator(b, opId, nil)

		SetupTestAccount(b, opId.accountId("acc1"), nil)
		SetupTestAccount(b, opId.accountId("acc2"), nil)
		SetupTestAccount(b, opId.accountId("acc3"), nil)

		config := ReadServerConfigJson(b, opId, map[string]any{
			"format":                   "json",
			"include_resolver_preload": true,
		})

		sysKey := ReadPublicKey(b, opId.accountId(DefaultSysAccountName))
		sysJwt := ReadJwtString(b, opId.accountId(DefaultSysAccountName))
		acc1Key := ReadPublicKey(b, opId.accountId("acc1"))
		acc1Jwt := ReadJwtString(b, opId.accountId("acc1"))
		acc2Key := ReadPublicKey(b, opId.accountId("acc2"))
		acc2Jwt := ReadJwtString(b, opId.accountId("acc2"))
		acc3Key := ReadPublicKey(b, opId.accountId("acc3"))
		acc3Jwt := ReadJwtString(b, opId.accountId("acc3"))

		assert.Equal(b, map[string]any{
			"operator":       ReadJwtString(b, opId),
			"system_account": sysKey,
			"resolver_preload": map[string]any{
				sysKey:  sysJwt,
				acc1Key: acc1Jwt,
				acc2Key: acc2Jwt,
				acc3Key: acc3Jwt,
			},
		}, config)
	})

	t.Run("nats with preload", func(t *testing.T) {
		b := testBackend(t)
		opId := OperatorId("op1")
		SetupTestOperator(b, opId, nil)

		SetupTestAccount(b, opId.accountId("acc1"), nil)
		SetupTestAccount(b, opId.accountId("acc2"), nil)
		SetupTestAccount(b, opId.accountId("acc3"), nil)

		config := ReadServerConfig(b, opId, map[string]any{
			"format":                   "nats",
			"include_resolver_preload": true,
		})

		sysKey := ReadPublicKey(b, opId.accountId(DefaultSysAccountName))
		sysJwt := ReadJwtString(b, opId.accountId(DefaultSysAccountName))
		acc1Key := ReadPublicKey(b, opId.accountId("acc1"))
		acc1Jwt := ReadJwtString(b, opId.accountId("acc1"))
		acc2Key := ReadPublicKey(b, opId.accountId("acc2"))
		acc2Jwt := ReadJwtString(b, opId.accountId("acc2"))
		acc3Key := ReadPublicKey(b, opId.accountId("acc3"))
		acc3Jwt := ReadJwtString(b, opId.accountId("acc3"))

		assert.Contains(b, config, fmt.Sprintf("operator: %s\n", ReadJwtString(b, opId)))
		assert.Contains(b, config, fmt.Sprintf("system_account: %s\n", ReadPublicKey(b, opId.accountId(DefaultSysAccountName))))

		blockRe := regexp.MustCompile(`resolver_preload\s*:?\s*\{([^}]*)\}`)
		m := blockRe.FindStringSubmatch(config)
		if len(m) < 2 {
			t.Fatal("resolver_preload block not found")
		}

		block := m[1]
		pairs := map[string]string{
			sysKey:  sysJwt,
			acc1Key: acc1Jwt,
			acc2Key: acc2Jwt,
			acc3Key: acc3Jwt,
		}

		for k, v := range pairs {
			assert.Contains(b, block, k+": "+v)
		}
	})
}
