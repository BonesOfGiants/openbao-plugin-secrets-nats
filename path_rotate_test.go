package natsbackend

import (
	"context"
	"testing"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackend_Operator_Rotation(t *testing.T) {
	t.Run("signing key does not exist", func(t *testing.T) {
		b := testBackend(t)

		id := OperatorId("op1")

		resp, err := RotateKey(b, id, nil)
		require.NoError(b, err)
		assert.ErrorContains(b, resp.Error(), "operator \"op1\" does not exist")
	})

	t.Run("basic rotate", func(t *testing.T) {
		b := testBackend(t)

		opId := OperatorId("op1")
		SetupTestOperator(b, opId, nil)

		oldNkey := ReadPublicKey(b, opId)

		opJwt := ReadOperatorJwt(b, opId)
		assert.Equal(b, oldNkey, opJwt.Issuer)
		assert.Equal(b, oldNkey, opJwt.Subject)

		resp, err := RotateKey(b, opId, nil)
		RequireNoRespError(b, resp, err)

		newNkey := ReadPublicKey(b, opId)
		assert.NotEqual(b, oldNkey, newNkey)

		opJwt = ReadOperatorJwt(b, opId)
		assert.Equal(b, newNkey, opJwt.Issuer)
		assert.Equal(b, newNkey, opJwt.Subject)
	})

	t.Run("rotation should reissue account jwts", func(t *testing.T) {
		b := testBackend(t)

		opId := OperatorId("op1")
		SetupTestOperator(b, opId, nil)

		accId := opId.accountId("acc1")
		SetupTestAccount(b, accId, nil)

		nkey := ReadPublicKey(b, opId)
		accJwt := ReadAccountJwt(b, accId)
		assert.Equal(b, nkey, accJwt.Issuer)

		resp, err := RotateKey(b, opId, nil)
		RequireNoRespError(b, resp, err)

		nkey = ReadPublicKey(b, opId)
		accJwt = ReadAccountJwt(b, accId)
		assert.Equal(b, nkey, accJwt.Issuer)
	})
}

func TestBackend_Operator_SigningKey_Rotation(t *testing.T) {
	t.Run("signing key does not exist", func(t *testing.T) {
		b := testBackend(t)

		id := OperatorSigningKeyId("op1", "sk1")

		resp, err := RotateKey(b, id, nil)
		require.NoError(b, err)
		assert.ErrorContains(b, resp.Error(), "signing key \"sk1\" does not exist")
	})

	t.Run("basic rotate", func(t *testing.T) {
		b := testBackend(t)

		opId := OperatorId("op1")
		SetupTestOperator(b, opId, nil)

		skId := opId.signingKeyId("sk1")
		resp, err := WriteConfig(b, skId, nil)
		RequireNoRespError(b, resp, err)

		oldNkey := ReadPublicKey(b, skId)

		opJwt := ReadOperatorJwt(b, opId)
		assert.Contains(b, opJwt.SigningKeys, oldNkey)

		resp, err = RotateKey(b, skId, nil)
		RequireNoRespError(b, resp, err)

		newNkey := ReadPublicKey(b, skId)
		assert.NotEqual(b, oldNkey, newNkey)

		opJwt = ReadOperatorJwt(b, opId)
		assert.NotContains(b, opJwt.SigningKeys, oldNkey)
		assert.Contains(b, opJwt.SigningKeys, newNkey)
	})

	t.Run("rotation should reissue account jwts", func(t *testing.T) {
		b := testBackend(t)

		opId := OperatorId("op1")
		SetupTestOperator(b, opId, nil)

		// create the signing key
		skId := opId.signingKeyId("sk1")
		resp, err := WriteConfig(b, skId, nil)
		RequireNoRespError(b, resp, err)

		accId := opId.accountId("acc1")
		SetupTestAccount(b, accId, map[string]any{
			"signing_key": skId.name,
		})

		nkey := ReadPublicKey(b, skId)
		accJwt := ReadAccountJwt(b, accId)
		assert.Equal(b, nkey, accJwt.Issuer)

		resp, err = RotateKey(b, skId, nil)
		RequireNoRespError(b, resp, err)

		nkey = ReadPublicKey(b, skId)
		accJwt = ReadAccountJwt(b, accId)
		assert.Equal(b, nkey, accJwt.Issuer)
	})
}

func TestBackend_Operator_Rotation_Suspend(t *testing.T) {
	t.Run("suspend account server on identity key rotate", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		defer nats.AssertNoLingering(_t)
		t := testBackendWithNats(_t, nats)

		opId := OperatorId("op1")
		SetupTestOperator(t, opId, nil)

		resp, err := WriteConfig(t, opId.accountServerId(), map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		resp, err = RotateKey(t, opId, nil)
		RequireNoRespError(t, resp, err)

		resp, err = ReadConfig(t, opId.accountServerId())
		RequireNoRespError(t, resp, err)

		assert.Equal(t, true, resp.Data["suspend"])
	})
	t.Run("suspend account server on signing key rotate", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		defer nats.AssertNoLingering(_t)
		t := testBackendWithNats(_t, nats)

		id := OperatorSigningKeyId("op1", "sk1")
		SetupTestOperator(t, id.operatorId(), nil)

		// create the signing key
		resp, err := WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		resp, err = WriteConfig(t, id.operatorId().accountServerId(), map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		resp, err = RotateKey(t, id, nil)
		RequireNoRespError(t, resp, err)

		resp, err = ReadConfig(t, id.operatorId().accountServerId())
		RequireNoRespError(t, resp, err)

		assert.Equal(t, true, resp.Data["suspend"])
	})
}

func TestBackend_Account_Rotation(_t *testing.T) {
	t := testBackend(_t)

	accId := AccountId("op1", "acc1")
	SetupTestAccount(t, accId, nil)

	oldNkey := ReadPublicKey(t, accId)

	opJwt := ReadAccountJwt(t, accId)
	assert.Equal(t, oldNkey, opJwt.Subject)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      accId.rotatePath(),
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	newNkey := ReadPublicKey(t, accId)
	assert.NotEqual(t, oldNkey, newNkey)

	opJwt = ReadAccountJwt(t, accId)
	assert.Equal(t, newNkey, opJwt.Subject)
}

func TestBackend_Account_SigningKey_Rotation(t *testing.T) {
	t.Run("signing key does not exist", func(_t *testing.T) {
		t := testBackend(_t)

		id := AccountSigningKeyId("op1", "acc1", "sk1")

		resp, err := RotateKey(t, id, nil)
		require.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "signing key \"sk1\" does not exist")
	})

	t.Run("unscoped", func(_t *testing.T) {
		t := testBackend(_t)

		id := AccountSigningKeyId("op1", "acc1", "s1")
		SetupTestAccount(t, id.accountId(), nil)

		// create the signing key
		resp, err := WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		oldNkey := ReadPublicKey(t, id)

		accJwt := ReadAccountJwt(t, id.accountId())
		assert.Contains(t, accJwt.SigningKeys, oldNkey)

		resp, err = RotateKey(t, id, nil)
		RequireNoRespError(t, resp, err)

		newNkey := ReadPublicKey(t, id)
		assert.NotEqual(t, oldNkey, newNkey)

		accJwt = ReadAccountJwt(t, id.accountId())
		assert.NotContains(t, accJwt.SigningKeys, oldNkey)
		assert.Contains(t, accJwt.SigningKeys, newNkey)
	})

	t.Run("scoped", func(_t *testing.T) {
		t := testBackend(_t)

		id := AccountSigningKeyId("op1", "acc1", "s1")
		SetupTestAccount(t, id.accountId(), map[string]any{
			"scoped": true,
		})

		// create the signing key
		resp, err := WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		oldNkey := ReadPublicKey(t, id)

		accJwt := ReadAccountJwt(t, id.accountId())
		assert.Contains(t, accJwt.SigningKeys, oldNkey)

		resp, err = RotateKey(t, id, nil)
		RequireNoRespError(t, resp, err)

		newNkey := ReadPublicKey(t, id)
		assert.NotEqual(t, oldNkey, newNkey)

		accJwt = ReadAccountJwt(t, id.accountId())
		assert.NotContains(t, accJwt.SigningKeys, oldNkey)
		assert.Contains(t, accJwt.SigningKeys, newNkey)
	})
}

func TestBackend_Account_Rotation_Sync(t *testing.T) {
	t.Run("sync on identity key rotate", func(_t *testing.T) {
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

		opPublicKey := ReadPublicKey(t, accId.operatorId())
		accPublicKey := ReadPublicKey(t, accId)
		ExpectDeleteSync(t, nats, opPublicKey, accPublicKey)

		resp, err = RotateKey(t, accId, nil)
		RequireNoRespError(t, resp, err)

		accJwt := ReadJwtString(t, accId)
		assert.Equal(t, accJwt, receivedJwt)
	})

	t.Run("sync on signing key rotate", func(_t *testing.T) {
		nats := abstractnats.NewMock(_t)
		defer nats.AssertNoLingering(_t)
		t := testBackendWithNats(_t, nats)

		id := AccountSigningKeyId("op1", "acc1", "sk1")
		SetupTestAccount(t, id.accountId(), nil)

		// create the signing key
		resp, err := WriteConfig(t, id, nil)
		RequireNoRespError(t, resp, err)

		oldSkPublicKey := ReadPublicKey(t, id)

		resp, err = WriteConfig(t, id.operatorId().accountServerId(), map[string]any{
			"servers":         []string{"nats://localhost:4222"},
			"sync_now":        false,
			"disable_lookups": true,
		})
		RequireNoRespError(t, resp, err)

		var receivedJwt string
		ExpectUpdateSync(t, nats, &receivedJwt)

		resp, err = RotateKey(t, id, nil)
		RequireNoRespError(t, resp, err)

		receivedClaims, err := jwt.DecodeAccountClaims(receivedJwt)
		require.NoError(t, err)

		skPublicKey := ReadPublicKey(t, id)
		assert.Contains(t, receivedClaims.SigningKeys, skPublicKey)
		assert.NotContains(t, receivedClaims.SigningKeys, oldSkPublicKey)
	})
}

func TestBackend_User_Rotation(t *testing.T) {
	t.Run("user does not exist", func(_t *testing.T) {
		t := testBackend(_t)

		userId := UserId("op1", "acc1", "user1")

		resp, err := RotateKey(t, userId, nil)
		require.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "user \"user1\" does not exist")
	})

	t.Run("default behavior", func(_t *testing.T) {
		t := testBackend(_t)

		userId := UserId("op1", "acc1", "user1")
		SetupTestUser(t, userId, nil)

		oldNkey := ReadPublicKey(t, userId)

		resp, err := ReadCreds(t, userId, nil)
		RequireNoRespError(t, resp, err)

		rawJwt, ok := resp.Data["jwt"]
		assert.True(t, ok)

		claims, err := jwt.DecodeUserClaims(rawJwt.(string))
		require.NoError(t, err)
		assert.Equal(t, oldNkey, claims.Subject)

		// rotate the user
		resp, err = RotateKey(t, userId, nil)
		RequireNoRespError(t, resp, err)

		newNkey := ReadPublicKey(t, userId)
		assert.NotEqual(t, oldNkey, newNkey)
		resp, err = ReadCreds(t, userId, nil)
		RequireNoRespError(t, resp, err)
		rawJwt, ok = resp.Data["jwt"]
		assert.True(t, ok)
		claims, err = jwt.DecodeUserClaims(rawJwt.(string))

		assert.Equal(t, newNkey, claims.Subject)

		// check account that it was revoked
		accJwt := ReadAccountJwt(t, userId.accountId())
		assert.Contains(t, accJwt.Revocations, oldNkey)
	})

	t.Run("no revoke", func(_t *testing.T) {
		t := testBackend(_t)

		userId := UserId("op1", "acc1", "user1")
		SetupTestUser(t, userId, nil)

		oldNkey := ReadPublicKey(t, userId)

		resp, err := ReadCreds(t, userId, nil)
		RequireNoRespError(t, resp, err)

		rawJwt, ok := resp.Data["jwt"]
		assert.True(t, ok)

		claims, err := jwt.DecodeUserClaims(rawJwt.(string))
		require.NoError(t, err)
		assert.Equal(t, oldNkey, claims.Subject)

		RotateKey(t, userId, map[string]any{
			"revoke": false,
		})

		newNkey := ReadPublicKey(t, userId)
		assert.NotEqual(t, oldNkey, newNkey)

		resp, err = ReadCreds(t, userId, nil)
		RequireNoRespError(t, resp, err)

		rawJwt, ok = resp.Data["jwt"]
		assert.True(t, ok)

		claims, err = jwt.DecodeUserClaims(rawJwt.(string))
		assert.Equal(t, newNkey, claims.Subject)

		// check account that it was not revoked
		accJwt := ReadAccountJwt(t, userId.accountId())
		assert.NotContains(t, accJwt.Revocations, oldNkey)
	})
}
