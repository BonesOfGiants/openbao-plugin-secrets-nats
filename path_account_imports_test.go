package natsbackend

import (
	"context"
	"errors"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
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
			err: errors.New(`failed to encode account jwt: invalid import type: "unknown", account to import from is not specified, subject cannot be empty`),
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
		t.Run(tc.name, func(t *testing.T) {
			b := testBackend(t)

			accId := AccountId("op1", "acc1")
			resp := SetupTestAccount(b, accId, map[string]any{
				"claims": map[string]any{
					"nats": map[string]any{
						"limits": map[string]any{
							"imports": -1,
							"exports": -1,
						},
					},
				},
			})

			// create imports
			impId := accId.importId("imp1")
			resp, err := WriteConfig(b, impId, tc.data)
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
			resp, err = ReadConfigRaw(b, impId)
			RequireNoRespError(b, resp, err)

			assert.EqualValues(b, tc.expected, resp.Data)

			// read jwt
			claims := ReadJwt[*jwt.AccountClaims](b, accId)

			for i, imp := range claims.Imports {
				comp := tc.expected["imports"].([]map[string]any)[i]
				if comp["name"] != nil {
					assert.Equal(b, comp["name"], imp.Name)
				} else {
					assert.Zero(b, imp.Name)
				}
				if comp["subject"] != nil {
					assert.Equal(b, comp["subject"], string(imp.Subject))
				} else {
					assert.Zero(b, imp.Subject)
				}
				if comp["account"] != nil {
					assert.Equal(b, comp["account"], imp.Account)
				} else {
					assert.Zero(b, imp.Account)
				}
				if comp["token"] != nil {
					assert.Equal(b, comp["token"], imp.Token)
				} else {
					assert.Zero(b, imp.Token)
				}
				if comp["to"] != nil {
					assert.Equal(b, comp["to"], imp.To)
				} else {
					assert.Zero(b, imp.To)
				}
				if comp["local_subject"] != nil {
					assert.Equal(b, comp["local_subject"], imp.LocalSubject)
				} else {
					assert.Zero(b, imp.LocalSubject)
				}
				if comp["type"] != nil {
					assert.Equal(b, comp["type"], imp.Type.String())
				} else {
					assert.Zero(b, imp.Type)
				}
				if comp["share"] != nil {
					assert.Equal(b, comp["share"], imp.Share)
				} else {
					assert.Zero(b, imp.Share)
				}
				if comp["allow_trace"] != nil {
					assert.Equal(b, comp["allow_trace"], imp.AllowTrace)
				} else {
					assert.Zero(b, imp.AllowTrace)
				}
			}

			// delete config
			resp, err = DeleteConfig(b, impId)
			RequireNoRespError(b, resp, err)

			// read config
			resp, err = ReadConfigRaw(b, impId)
			RequireNoRespError(b, resp, err)
			assert.Nil(b, resp)
		})
	}
}

func TestBackend_AccountImport_List(ts *testing.T) {
	t := testBackend(ts)

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

	DeleteConfig(t, accId.importId("imp1"))
	DeleteConfig(t, accId.importId("imp2"))
	DeleteConfig(t, accId.importId("imp3"))

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
