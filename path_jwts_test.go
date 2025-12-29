package natsbackend

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
)

// from nats jwt package
const libVersion = 2

func TestBackend_Operator_Jwt(_t *testing.T) {
	t := testBackend(_t)

	testClaims := &jwt.OperatorClaims{
		ClaimsData: jwt.ClaimsData{
			// overwritten
			Expires:  1766703476,
			IssuedAt: 1766703476,
			Subject:  "test-subject",
			Issuer:   "test-subject",
			Name:     "test-name",

			// preserved
			Audience:  "test-audience",
			NotBefore: 1766703476,
		},
		Operator: jwt.Operator{
			SigningKeys:           []string{"OAFBH2TC62XAENUKN4HBJZEVXYFS2JK4FE2IPRNXF6RUK26FCKR2ZQ5Q"},
			AccountServerURL:      "http://localhost:8000",
			OperatorServiceURLs:   []string{"nats://localhost:4222"},
			AssertServerVersion:   "1.0.0",
			StrictSigningKeyUsage: true,
			SystemAccount:         "ABLODEHOP6OHO7MYC5JO2HL4AC66VN5OOQSEBP6TNF7FGH4JSPAZ7K6L",
			GenericFields: jwt.GenericFields{
				Tags: jwt.TagList{
					"test-tag",
				},
				Type:    "test-type", // overwritten
				Version: 0,
			},
		},
	}

	id := OperatorId("op1")
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      id.configPath(),
		Storage:   t,
		Data: map[string]any{
			"create_system_account": false, // system account would be overwritten
			"claims":                unmarshalToMap(fromOperatorClaims(testClaims)),
		},
	}
	resp, err := t.HandleRequest(context.Background(), req)
	RequireNoRespError(t, resp, err)

	publicKey := ReadPublicKey(t, id)
	opClaims := ReadJwt[*jwt.OperatorClaims](t, id)

	// custom claim data
	assert.Equal(t, testClaims.ClaimsData.Audience, opClaims.ClaimsData.Audience)
	assert.Equal(t, testClaims.ClaimsData.NotBefore, opClaims.ClaimsData.NotBefore)

	// fixed claim data
	assert.Equal(t, publicKey, opClaims.ClaimsData.Issuer)
	assert.Equal(t, publicKey, opClaims.ClaimsData.Subject)
	assert.Equal(t, id.op, opClaims.ClaimsData.Name)
	assert.Equal(t, int64(0), opClaims.ClaimsData.Expires)
	assert.Equal(t, jwt.ClaimType(jwt.OperatorClaim), opClaims.Operator.GenericFields.Type)
	assert.Equal(t, libVersion, opClaims.Operator.GenericFields.Version)

	// operator config
	assert.Equal(t, testClaims.Operator.SigningKeys, opClaims.Operator.SigningKeys)
	assert.Equal(t, testClaims.Operator.AccountServerURL, opClaims.Operator.AccountServerURL)
	assert.Equal(t, testClaims.Operator.OperatorServiceURLs, opClaims.Operator.OperatorServiceURLs)
	assert.Equal(t, testClaims.Operator.AssertServerVersion, opClaims.Operator.AssertServerVersion)
	assert.Equal(t, testClaims.Operator.StrictSigningKeyUsage, opClaims.Operator.StrictSigningKeyUsage)
	assert.Equal(t, testClaims.Operator.SystemAccount, opClaims.Operator.SystemAccount)
	assert.Equal(t, testClaims.Operator.GenericFields.Tags, opClaims.Operator.GenericFields.Tags)
}

func TestBackend_Account_Jwt(t *testing.T) {
	b := testBackend(t)

	claims := &jwt.AccountClaims{
		ClaimsData: jwt.ClaimsData{
			// overwritten
			Expires:  1766703476,
			IssuedAt: 1766703476,
			Subject:  "test-subject",
			Issuer:   "test-subject",
			Name:     "test-name",

			// preserved
			Audience:  "test-audience",
			NotBefore: 1766703476,
		},
		Account: jwt.Account{
			Imports: jwt.Imports{
				{
					Name:         "test-import",
					Subject:      "foo.bar",
					Account:      "ABGQ4SUQNZSOIKMZLX5GR3FNSFK67CD646SLCYJEVIUEWMGI4WERJ6WG",
					LocalSubject: "foo.bar",
					Type:         jwt.Stream,
					AllowTrace:   true,
					// Token: "", // not supported
				},
				{
					Name:    "test-import-2",
					Subject: "foo.bar.baz",
					Account: "ABGQ4SUQNZSOIKMZLX5GR3FNSFK67CD646SLCYJEVIUEWMGI4WERJ6WG",
					Type:    jwt.Service,
					Share:   true,
					// Token: "", // not supported
				},
			},
			Exports: jwt.Exports{
				{
					Name:    "test-export",
					Subject: "foo.bar.*",
					Type:    jwt.Service,
					// TokenReq: true, // not supported
					Revocations: jwt.RevocationList{
						"UCEWUEWVTNKDKQQ3UUCQUDHTD3ELAE2WW3KTGCCK6APNTXJVUVP2XRMA": 1766703476,
					},
					ResponseType:      jwt.ResponseTypeSingleton,
					ResponseThreshold: 10 * time.Second,
					Latency: &jwt.ServiceLatency{
						Sampling: 10,
						Results:  "foo.bar",
					},
					AccountTokenPosition: 3,
					Advertise:            true,
					AllowTrace:           true,
					Info: jwt.Info{
						Description: "test-description",
						InfoURL:     "http://localhost:8000",
					},
				},
			},
			Limits: jwt.OperatorLimits{
				NatsLimits: jwt.NatsLimits{
					Subs:    10,
					Data:    10,
					Payload: 10,
				},
				AccountLimits: jwt.AccountLimits{
					Imports:         10,
					Exports:         10,
					WildcardExports: true,
					DisallowBearer:  true,
					Conn:            10,
					LeafNodeConn:    10,
				},
				JetStreamLimits: jwt.JetStreamLimits{
					MemoryStorage:        10,
					DiskStorage:          10,
					Streams:              10,
					Consumer:             10,
					MaxAckPending:        10,
					MemoryMaxStreamBytes: 10,
					DiskMaxStreamBytes:   10,
					MaxBytesRequired:     true,
				},
				// tiered limits are mutually exclusive
				// JetStreamTieredLimits: jwt.JetStreamTieredLimits{},
			},
			SigningKeys: jwt.SigningKeys{}, // handled below
			Revocations: jwt.RevocationList{
				"UCEWUEWVTNKDKQQ3UUCQUDHTD3ELAE2WW3KTGCCK6APNTXJVUVP2XRMA": 1766703476,
			},
			DefaultPermissions: jwt.Permissions{
				Pub: jwt.Permission{
					Allow: jwt.StringList{"allowed"},
					Deny:  jwt.StringList{"denied"},
				},
				Sub: jwt.Permission{
					Allow: jwt.StringList{"allowed"},
					Deny:  jwt.StringList{"denied"},
				},
				Resp: &jwt.ResponsePermission{
					MaxMsgs: 10,
					Expires: 10 * time.Second,
				},
			},
			Mappings: jwt.Mapping{
				"foo.bar": []jwt.WeightedMapping{
					{
						Subject: "foo.bar",
						Weight:  10,
						Cluster: "test-cluster",
					},
				},
			},
			Authorization: jwt.ExternalAuthorization{
				AuthUsers:       jwt.StringList{"UCEWUEWVTNKDKQQ3UUCQUDHTD3ELAE2WW3KTGCCK6APNTXJVUVP2XRMA"},
				AllowedAccounts: jwt.StringList{"ABGQ4SUQNZSOIKMZLX5GR3FNSFK67CD646SLCYJEVIUEWMGI4WERJ6WG"},
				// XKey:            "",
			},
			Trace: &jwt.MsgTrace{
				Destination: "foo.bar",
				Sampling:    10,
			},
			ClusterTraffic: jwt.ClusterTrafficOwner,
			Info: jwt.Info{
				Description: "",
				InfoURL:     "",
			},
			GenericFields: jwt.GenericFields{
				Tags:    jwt.TagList{"test-tag"},
				Type:    "test-type",
				Version: 0,
			},
		},
	}
	claims.Account.SigningKeys.Add("AD7NGPOM42ASLFM3BLMU3DEPVJ23CZUQEZSCLCIK7CE6W4UOQJCKWV44")

	id := AccountId("op1", "acc1")
	SetupTestAccount(b, id, map[string]any{
		"claims": unmarshalToMap(fromAccountClaims(claims)),
	})

	opIdKey := ReadPublicKey(b, id.operatorId())
	accIdKey := ReadPublicKey(b, id)
	accClaims := ReadJwt[*jwt.AccountClaims](b, id)

	// custom claim data
	assert.Equal(b, claims.ClaimsData.Audience, accClaims.ClaimsData.Audience)
	assert.Equal(b, claims.ClaimsData.NotBefore, accClaims.ClaimsData.NotBefore)

	// fixed claim data
	assert.Equal(b, opIdKey, accClaims.ClaimsData.Issuer)
	assert.Equal(b, accIdKey, accClaims.ClaimsData.Subject)
	assert.Equal(b, id.acc, accClaims.ClaimsData.Name)
	assert.Equal(b, int64(0), accClaims.ClaimsData.Expires)
	assert.Equal(b, jwt.ClaimType(jwt.AccountClaim), accClaims.Account.GenericFields.Type)
	assert.Equal(b, libVersion, accClaims.Account.GenericFields.Version)

	// account config
	assert.Equal(b, claims.Account.Imports, accClaims.Account.Imports)
	assert.Equal(b, claims.Account.Exports, accClaims.Account.Exports)
	assert.Equal(b, claims.Account.Limits, accClaims.Account.Limits)
	assert.Equal(b, claims.Account.SigningKeys, accClaims.Account.SigningKeys)
	assert.Equal(b, claims.Account.Revocations, accClaims.Account.Revocations)
	assert.Equal(b, claims.Account.DefaultPermissions, accClaims.Account.DefaultPermissions)
	assert.Equal(b, claims.Account.Mappings, accClaims.Account.Mappings)
	assert.Equal(b, claims.Account.Authorization, accClaims.Account.Authorization)
	assert.Equal(b, claims.Account.Trace, accClaims.Account.Trace)
	assert.Equal(b, claims.Account.ClusterTraffic, accClaims.Account.ClusterTraffic)
	assert.Equal(b, claims.Account.Info.Description, accClaims.Account.Info.Description)
	assert.Equal(b, claims.Account.Info.InfoURL, accClaims.Account.Info.InfoURL)
	assert.Equal(b, claims.Account.GenericFields.Tags, accClaims.Account.GenericFields.Tags)

	// delete account
	DeleteConfig(b, id)

	// jwt should also be deleted
	resp, err := ReadJwtRaw(b, id)
	RequireNoRespError(b, resp, err)
	assert.Nil(b, resp)
}
