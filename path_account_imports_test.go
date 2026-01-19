package natsbackend

import (
	"context"
	"errors"
	"testing"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackend_AccountImport_Config(t *testing.T) {
	testCases := []struct {
		name     string
		data     map[string]any
		expected map[string]any
		err      error
	}{
		{
			name: "require at least one import",
			data: map[string]any{},
			err:  errors.New(`must define at least one import`),
		},
		{
			name: "validation error",
			data: map[string]any{
				"imports": []map[string]any{
					{
						"name": "test-import",
					},
				},
			},
			err: errors.New(`validation error: invalid import type: "unknown"; account to import from is not specified; subject cannot be empty`),
		},
		{
			name: "basic",
			data: map[string]any{
				"imports": []map[string]any{
					{
						"name":    "test-import",
						"subject": "foo.bar",
						"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
						"type":    "stream",
					},
				},
			},
			expected: map[string]any{
				"imports": []map[string]any{
					{
						"name":    "test-import",
						"subject": "foo.bar",
						"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
						"type":    "stream",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(_t *testing.T) {
			t := testBackend(_t)

			accId := AccountId("op1", "acc1")
			SetupTestAccount(t, accId, nil)

			// create imports
			impId := accId.importId("imp1")
			resp, err := WriteConfig(t, impId, tc.data)
			if err != nil || (resp != nil && resp.IsError()) {
				if tc.err == nil {
					t.Fatalf("err: %s; resp: %#v\n", err, resp)
				} else if err != nil && err.Error() == tc.err.Error() {
					return
				} else if err == nil && resp.Error().Error() == tc.err.Error() {
					return
				} else {
					t.Fatalf("expected err message: %q, got %q, response error: %q", tc.err, err, resp.Error())
				}
			} else if tc.err != nil {
				if resp == nil || !resp.IsError() {
					t.Fatalf("expected err, got none")
				}
			}

			// read config
			resp, err = ReadConfigRaw(t, impId)
			RequireNoRespError(t, resp, err)

			assert.EqualValues(t, tc.expected, resp.Data)

			// read jwt
			claims := ReadJwt[*jwt.AccountClaims](t, accId)

			for i, imp := range claims.Imports {
				comp := tc.expected["imports"].([]map[string]any)[i]
				if comp["name"] != nil {
					assert.Equal(t, comp["name"], imp.Name)
				} else {
					assert.Zero(t, imp.Name)
				}
				if comp["subject"] != nil {
					assert.Equal(t, comp["subject"], string(imp.Subject))
				} else {
					assert.Zero(t, imp.Subject)
				}
				if comp["account"] != nil {
					assert.Equal(t, comp["account"], imp.Account)
				} else {
					assert.Zero(t, imp.Account)
				}
				if comp["token"] != nil {
					assert.Equal(t, comp["token"], imp.Token)
				} else {
					assert.Zero(t, imp.Token)
				}
				if comp["local_subject"] != nil {
					assert.Equal(t, comp["local_subject"], imp.LocalSubject)
				} else {
					assert.Zero(t, imp.LocalSubject)
				}
				if comp["type"] != nil {
					assert.Equal(t, comp["type"], imp.Type.String())
				} else {
					assert.Zero(t, imp.Type)
				}
				if comp["share"] != nil {
					assert.Equal(t, comp["share"], imp.Share)
				} else {
					assert.Zero(t, imp.Share)
				}
				if comp["allow_trace"] != nil {
					assert.Equal(t, comp["allow_trace"], imp.AllowTrace)
				} else {
					assert.Zero(t, imp.AllowTrace)
				}
			}

			// delete config
			resp, err = DeleteConfig(t, impId, nil)
			RequireNoRespError(t, resp, err)

			// read config
			resp, err = ReadConfigRaw(t, impId)
			RequireNoRespError(t, resp, err)
			assert.Nil(t, resp)
		})
	}

	t.Run("overwrite imports", func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		// create import with some claims
		impId := accId.importId("imp1")
		resp, err := WriteConfig(t, impId, map[string]any{
			"imports": []any{
				map[string]any{
					"name":    "test-import",
					"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
					"type":    "stream",
					"subject": "foo.bar",
				},
			},
		})
		RequireNoRespError(t, resp, err)

		// attempt to make a "partial" update
		resp, err = WriteConfig(t, impId, map[string]any{
			"imports": []any{
				map[string]any{
					"type": "service",
				},
			},
		})
		require.NoError(t, err)

		// validation error because the import was overwritten
		// and the required fields were lost
		assert.ErrorContains(t, resp.Error(), "validation error")
	})
}

func TestBackend_AccountImport_NonExistentAccount(_t *testing.T) {
	t := testBackend(_t)

	id := AccountImportId("op1", "acc1", "imp1")
	resp, err := WriteConfig(t, id, nil)
	assert.NoError(t, err)
	assert.ErrorContains(t, resp.Error(), "account \"acc1\" does not exist")
}

func TestBackend_AccountImport_RootParameters(t *testing.T) {
	t.Run("basic usage", func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		expected := map[string]any{
			"name":    "test-import",
			"subject": "foo.bar",
			"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
			"type":    "stream",
		}
		impId := accId.importId("imp1")
		resp, err := WriteConfig(t, impId, expected)
		RequireNoRespError(t, resp, err)

		resp, err = ReadConfigRaw(t, impId)
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Data, "imports")
		imports := resp.Data["imports"].([]map[string]any)
		assert.Len(t, imports, 1)

		assert.Equal(t, expected, imports[0])
	})
	t.Run("partial update", func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)
		impId := accId.importId("imp1")
		resp, err := WriteConfig(t, impId, map[string]any{
			"name":    "test-import",
			"subject": "foo.bar",
			"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
			"type":    "stream",
		})
		RequireNoRespError(t, resp, err)

		// attempt partial update
		resp, err = WriteConfig(t, impId, map[string]any{
			"type": "service",
		})
		RequireNoRespError(t, resp, err)

		resp, err = ReadConfigRaw(t, impId)
		RequireNoRespError(t, resp, err)

		assert.Contains(t, resp.Data, "imports")
		imports := resp.Data["imports"].([]map[string]any)
		assert.Len(t, imports, 1)

		assert.Equal(t, map[string]any{
			"name":    "test-import",
			"subject": "foo.bar",
			"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
			"type":    "service",
		}, imports[0])
	})
	t.Run("may not specify both root and imports", func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)
		impId := accId.importId("imp1")
		resp, err := WriteConfig(t, impId, map[string]any{
			"name":    "test-import",
			"subject": "foo.bar",
			"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
			"type":    "stream",
			"imports": []any{
				map[string]any{
					"name":    "test-import",
					"subject": "foo.bar",
					"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
					"type":    "stream",
				},
			},
		})
		require.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "may not specify imports array along with root-level import parameters")
	})
	t.Run("may not specify root on import with more than one claim", func(_t *testing.T) {
		t := testBackend(_t)

		accId := AccountId("op1", "acc1")
		SetupTestAccount(t, accId, nil)

		impId := accId.importId("imp1")
		resp, err := WriteConfig(t, impId, map[string]any{
			"imports": []any{
				map[string]any{
					"name":    "test-import",
					"subject": "foo.bar",
					"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
					"type":    "stream",
				},
				map[string]any{
					"name":    "test-import-2",
					"subject": "foo.bar.baz",
					"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
					"type":    "stream",
				},
			},
		})
		RequireNoRespError(t, resp, err)

		resp, err = WriteConfig(t, impId, map[string]any{
			"type": "service",
		})
		assert.NoError(t, err)
		assert.ErrorContains(t, resp.Error(), "cannot specify root-level parameters on an account import with more than one import claim")
	})
}

func TestBackend_AccountImport_List(ts *testing.T) {
	t := testBackend(ts)

	accId := AccountId("op1", "acc1")
	SetupTestAccount(t, accId, map[string]any{
		"claims": map[string]any{
			"limits": map[string]any{
				"imports": -1,
				"exports": -1,
			},
		},
	})

	data := map[string]any{
		"imports": []map[string]any{
			{
				"name":    "test-import",
				"subject": "foo.bar",
				"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
				"type":    "stream",
			},
		},
	}

	WriteConfig(t, accId.importId("imp1"), data)
	WriteConfig(t, accId.importId("imp2"), data)
	WriteConfig(t, accId.importId("imp3"), data)

	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      accId.importPrefix(),
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	assert.Equal(t, []string{"imp1", "imp2", "imp3"}, resp.Data["keys"])

	DeleteConfig(t, accId.importId("imp1"), nil)
	DeleteConfig(t, accId.importId("imp2"), nil)
	DeleteConfig(t, accId.importId("imp3"), nil)

	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      accId.importPrefix(),
		Storage:   t,
		Data:      map[string]any{},
	}
	resp, err = t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	assert.NotContains(t, resp.Data, "keys")
}

func TestBackend_AccountImport_Sync(t *testing.T) {
	t.Run("sync on account import create", func(_t *testing.T) {
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

		expected := map[string]any{
			"name":    "test-import",
			"subject": "foo.bar",
			"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
			"type":    "stream",
		}
		WriteConfig(t, accId.importId("test-import"), expected)

		claims, err := jwt.DecodeAccountClaims(receivedJwt)
		require.NoError(t, err)

		assert.Len(t, claims.Imports, 1)

		imp := claims.Imports[0]
		assert.True(t, imp.IsStream(), "import is not stream")
		assert.Equal(t, expected["name"], imp.Name)
		assert.Equal(t, expected["subject"], string(imp.Subject))
		assert.Equal(t, expected["account"], imp.Account)
	})
	t.Run("sync on account import delete", func(_t *testing.T) {
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

		expected := map[string]any{
			"name":    "test-import",
			"subject": "foo.bar",
			"account": "ABDEAD7OENMDZ6NF6NYQX4RUWE77YAM7DDEYSHTCWDLR3MWAJWKGHJC3",
			"type":    "stream",
		}
		WriteConfig(t, accId.importId("test-import"), expected)

		resp, err = WriteConfig(t, accId.operatorId().accountServerId(), map[string]any{
			"suspend":  false,
			"sync_now": false,
		})
		RequireNoRespError(t, resp, err)

		var receivedJwt string
		ExpectUpdateSync(t, nats, &receivedJwt)

		resp, err = DeleteConfig(t, accId.importId("test-import"), nil)
		RequireNoRespError(t, resp, err)

		claims, err := jwt.DecodeAccountClaims(receivedJwt)
		require.NoError(t, err)

		assert.Len(t, claims.Imports, 0)
	})
}
