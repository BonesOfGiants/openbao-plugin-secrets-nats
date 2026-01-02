package natsbackend

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/accountsync"
	"github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
todo: list of things that still need tests:
- operator jwt change resulting in sync being suspended
- managed name clashes with existing account
- account config
- ephemeral user config
- user config
- all the variations of things that cause account syncing
	- [ ] operator rotate
	- [ ] operator signing key rotate
	- [x] account import create/update/delete
	- [x] revocation create/update/delete
	- [ ] user delete resulting in revocation
	- [ ] account config
	- [ ] account rotate
	- [ ] account signing key rotate
- operator signing key delete resulting in accounts being resigned using the id key
- key list tests + change the alias lists to use the proper fn call
- walrollback behavior with deleted accounts
- ttl of eph/creds, including default, max, and ttl passed into creds endpoint directly
*/

func testFactory(ctx context.Context, conf *logical.BackendConfig, n abstractnats.MockNatsConnection) (logical.Backend, error) {
	b := Backend()
	if n != nil {
		b.NewSyncConnection = n.NewMockConnection
	} else {
		b.NewSyncConnection = func(_ []string, _ ...nats.Option) (abstractnats.NatsConnection, error) {
			return nil, errors.New(`must pass a nats mock to create nats connections in unit tests`)
		}
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type testContext struct {
	testing.TB
	logical.Backend
	logical.Storage
}

func testBackend(tb testing.TB) testContext {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.System = logical.TestSystemView()
	config.StorageView = &logical.InmemStorage{}

	b, err := testFactory(context.Background(), config, nil)
	if err != nil {
		tb.Fatal(err)
	}

	return testContext{
		TB:      tb,
		Backend: b,
		Storage: config.StorageView,
	}
}

func testBackendWithNats(tb testing.TB, n abstractnats.MockNatsConnection) testContext {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.System = logical.TestSystemView()
	config.StorageView = &logical.InmemStorage{}

	b, err := testFactory(context.Background(), config, n)
	if err != nil {
		tb.Fatal(err)
	}

	return testContext{
		TB:      tb,
		Backend: b,
		Storage: config.StorageView,
	}
}

func TickPeriodic(t testContext) error {
	_, err := t.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RollbackOperation,
		Storage:   t,
	})

	return err
}

func RequireNoRespError(t testContext, resp *logical.Response, err error) {
	t.Helper()

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s; resp: %#v\n", err, resp)
	}
}

func unmarshalToMap(i json.RawMessage) map[string]any {
	var out map[string]any
	err := json.Unmarshal(i, &out)
	if err != nil {
		panic(err)
	}
	return out
}

func SetupTestOperator(t testContext, id operatorId, data map[string]any) *logical.Response {
	t.Helper()

	if data == nil {
		data = map[string]any{}
	}

	// create operator
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      id.configPath(),
		Storage:   t,
		Data:      data,
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	return resp
}

func SetupTestAccount(t testContext, id accountId, data map[string]any) *logical.Response {
	t.Helper()

	if data == nil {
		data = map[string]any{}
	}

	// create operator
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      id.operatorId().configPath(),
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	// create account
	req.Path = id.configPath()
	req.Data = data
	resp, err = t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	return resp
}

func SetupTestUser(t testContext, id userPather, data map[string]any) {
	t.Helper()

	if data == nil {
		data = map[string]any{}
	}

	// create operator
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      id.operatorId().configPath(),
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	// create account
	req.Path = id.accountId().configPath()
	resp, err = t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	// create user
	req.Path = id.configPath()
	req.Data = data
	resp, err = t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)
}

func ReadJwt[T jwt.Claims](t testContext, id jwtPather) T {
	t.Helper()

	req := &logical.Request{
		Path:      id.jwtPath(),
		Operation: logical.ReadOperation,
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	jwtRaw, ok := resp.Data["jwt"]
	require.True(t, ok)
	require.IsType(t, "", jwtRaw)

	rawClaims, err := jwt.Decode(jwtRaw.(string))
	require.NoError(t, err)

	claims, ok := rawClaims.(T)
	require.True(t, ok)

	return claims
}

func ReadOperatorJwt(t testContext, id operatorId) *jwt.OperatorClaims {
	t.Helper()

	return ReadJwt[*jwt.OperatorClaims](t, id)
}

func ReadAccountJwt(t testContext, id accountId) *jwt.AccountClaims {
	t.Helper()

	return ReadJwt[*jwt.AccountClaims](t, id)
}

func ReadJwtString(t testContext, id jwtPather) string {
	t.Helper()

	req := &logical.Request{
		Path:      id.jwtPath(),
		Operation: logical.ReadOperation,
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	jwtRaw, ok := resp.Data["jwt"]
	require.True(t, ok)
	require.IsType(t, "", jwtRaw)

	return jwtRaw.(string)
}

func ReadJwtRaw(t testContext, id jwtPather) (*logical.Response, error) {
	t.Helper()

	return t.HandleRequest(context.Background(), &logical.Request{
		Path:      id.jwtPath(),
		Operation: logical.ReadOperation,
		Storage:   t,
		Data:      map[string]any{},
	})
}

func ReadNkeyRaw(t testContext, id nkeyPather) (*logical.Response, error) {
	t.Helper()

	return t.HandleRequest(context.Background(), &logical.Request{
		Path:      id.nkeyPath(),
		Operation: logical.ReadOperation,
		Storage:   t,
		Data:      map[string]any{},
	})
}

func ReadPublicKey(t testContext, id nkeyPather) string {
	t.Helper()

	// check the jwt
	req := &logical.Request{
		Path:      id.nkeyPath(),
		Operation: logical.ReadOperation,
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	publicKey, ok := resp.Data["public_key"]
	require.True(t, ok)

	return publicKey.(string)
}

func UpdateConfig(t testContext, id configPather, data map[string]any) (*logical.Response, error) {
	if data == nil {
		data = map[string]any{}
	}

	return t.HandleRequest(context.Background(), &logical.Request{
		Path:      id.configPath(),
		Operation: logical.UpdateOperation,
		Storage:   t,
		Data:      data,
	})
}

func WriteConfig(t testContext, id configPather, data map[string]any) (*logical.Response, error) {
	t.Helper()

	if data == nil {
		data = map[string]any{}
	}

	return t.HandleRequest(context.Background(), &logical.Request{
		Path:      id.configPath(),
		Operation: logical.CreateOperation,
		Storage:   t,
		Data:      data,
	})
}

func WriteSyncConfig(t testContext, id operatorId, data map[string]any) (*logical.Response, error) {
	t.Helper()

	if data == nil {
		data = map[string]any{}
	}

	return t.HandleRequest(context.Background(), &logical.Request{
		Path:      id.syncConfigPath(),
		Operation: logical.CreateOperation,
		Storage:   t,
		Data:      data,
	})
}

func ReadSyncConfigRaw(t testContext, id operatorId) (*logical.Response, error) {
	t.Helper()

	return t.HandleRequest(context.Background(), &logical.Request{
		Path:      id.syncConfigPath(),
		Operation: logical.ReadOperation,
		Storage:   t,
		Data:      map[string]any{},
	})
}

func DeleteSyncConfig(t testContext, id operatorId) (*logical.Response, error) {
	t.Helper()

	return t.HandleRequest(context.Background(), &logical.Request{
		Path:      id.syncConfigPath(),
		Operation: logical.DeleteOperation,
		Storage:   t,
		Data:      map[string]any{},
	})
}

func ReadConfig[T configPather](t testContext, id configPather) T {
	t.Helper()

	// check the jwt
	req := &logical.Request{
		Path:      id.configPath(),
		Operation: logical.ReadOperation,
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	var out T
	j, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	err = json.Unmarshal(j, &out)
	require.NoError(t, err)

	switch v := any(out).(type) {
	case operatorEntry:
		_id := id.(operatorId)
		v.op = _id.op
	case accountEntry:
		_id := id.(accountId)
		v.op = _id.op
		v.acc = _id.acc
	case userEntry:
		_id := id.(userId)
		v.op = _id.op
		v.acc = _id.acc
		v.user = _id.user
	}

	return out
}

func ExistenceCheckConfig(t testContext, id configPather) (bool, bool, error) {
	t.Helper()

	return t.HandleExistenceCheck(context.Background(), &logical.Request{
		Path:      id.configPath(),
		Operation: logical.CreateOperation,
		Storage:   t,
		Data:      map[string]any{},
	})
}

func ReadConfigRaw(t testContext, id configPather) (*logical.Response, error) {
	t.Helper()

	return t.HandleRequest(context.Background(), &logical.Request{
		Path:      id.configPath(),
		Operation: logical.ReadOperation,
		Storage:   t,
		Data:      map[string]any{},
	})
}

func DeleteConfig(t testContext, id configPather) (*logical.Response, error) {
	t.Helper()

	return t.HandleRequest(context.Background(), &logical.Request{
		Path:      id.configPath(),
		Operation: logical.DeleteOperation,
		Storage:   t,
		Data:      map[string]any{},
	})
}

func AssertConfigDeleted(t testContext, id configPather) {
	t.Helper()

	resp, err := ReadConfigRaw(t, id)
	RequireNoRespError(t, resp, err)
	assert.Nilf(t, resp, "Expected %q not to exist", id.configPath())
}

func AssertJwtDeleted(t testContext, id jwtPather) {
	t.Helper()

	resp, err := ReadJwtRaw(t, id)
	RequireNoRespError(t, resp, err)
	assert.Nilf(t, resp, "Expected %q not to exist", id.jwtPath())
}

func AssertNKeyDeleted(t testContext, id nkeyPather) {
	t.Helper()

	resp, err := ReadNkeyRaw(t, id)
	RequireNoRespError(t, resp, err)
	assert.Nilf(t, resp, "Expected %q not to exist", id.nkeyPath())
}

func ReadCreds(t testContext, id credsPather, data map[string]any) (*logical.Response, error) {
	t.Helper()

	if data == nil {
		data = map[string]any{}
	}

	return t.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      id.credsPath(),
		Storage:   t,
		Data:      data,
	})
}

func ReadEphemeralCreds(t testContext, id ephemeralUserId, session string, data map[string]any) (*logical.Response, error) {
	t.Helper()

	if data == nil {
		data = map[string]any{}
	}

	return t.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      id.ephemeralCredsPath(session),
		Storage:   t,
		Data:      data,
	})
}

func RotateKey(t testContext, id rotatePather, data map[string]any) (*logical.Response, error) {
	t.Helper()

	if data == nil {
		data = map[string]any{}
	}

	return t.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      id.rotatePath(),
		Storage:   t,
		Data:      data,
	})
}

func ExpectUpdateSync(t testContext, m abstractnats.MockNatsConnection, outJwt *string) {
	t.Helper()

	sub := m.ExpectInboxSubscription()
	m.ExpectPublish(accountsync.SysClaimsUpdateSubject, func(_ abstractnats.MockNatsConnection, subj, reply string, data []byte) error {
		t.Helper()

		assert.Equal(t, sub.Subject(), reply, "reply inbox does not match")
		*outJwt = string(data)

		msg := &accountsync.ServerAPIClaimUpdateResponse{}

		msgBytes, err := json.Marshal(msg)
		require.NoError(t, err)

		sub.Reply("", msgBytes)

		return nil
	})
}

func ExpectDeleteSync(t testContext, m abstractnats.MockNatsConnection, operatorKey, accountKey string) {
	t.Helper()

	sub := m.ExpectInboxSubscription()
	m.ExpectPublish(accountsync.SysClaimsDeleteSubject, func(_ abstractnats.MockNatsConnection, subj, reply string, data []byte) error {
		t.Helper()

		assert.Equal(t, sub.Subject(), reply, "reply inbox does not match")

		claims, err := jwt.DecodeGeneric(string(data))
		require.NoError(t, err)

		assert.Equal(t, operatorKey, claims.Issuer)
		assert.Equal(t, operatorKey, claims.Subject)
		assert.Contains(t, claims.Data["accounts"], accountKey)

		msg := &accountsync.ServerAPIClaimUpdateResponse{}

		msgBytes, err := json.Marshal(msg)
		require.NoError(t, err)

		sub.Reply("", msgBytes)

		return nil
	})
}

func ReadServerConfig(t testContext, id operatorId, data map[string]any) string {
	t.Helper()

	if data == nil {
		data = map[string]any{}
	}

	resp, err := t.HandleRequest(context.Background(), &logical.Request{
		Path:      id.generateServerConfigPath(),
		Operation: logical.ReadOperation,
		Storage:   t,
		Data:      data,
	})
	RequireNoRespError(t, resp, err)

	conf, ok := resp.Data["config"]
	require.True(t, ok)
	require.IsType(t, "", conf)

	return conf.(string)
}

func ReadServerConfigJson(t testContext, id operatorId, data map[string]any) map[string]any {
	t.Helper()

	if data == nil {
		data = map[string]any{}
	}

	data["format"] = "json"

	config := ReadServerConfig(t, id, data)

	var parsedConf map[string]any
	err := json.Unmarshal([]byte(config), &parsedConf)
	require.NoError(t, err)

	return parsedConf
}
