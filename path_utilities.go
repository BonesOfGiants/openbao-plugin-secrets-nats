package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type ServerConfigFormat int

const (
	ServerConfigFormatJson ServerConfigFormat = iota
	ServerConfigFormatNats                    = iota
)

func pathUtilities(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: operatorGenerateServerConfigPathPrefix + operatorRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"include_resolver_preload": {
					Type:        framework.TypeBool,
					Description: "Whether to include a `resolver_preload` map in the generated config. This is only supported for NATS and MEMORY resolvers. The map will contain the current public key and JWT of all accounts under the operator.",
					Required:    false,
				},
				"format": {
					Type: framework.TypeString,
					AllowedValues: []any{
						"nats", "json",
					},
					Default: "json",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathGenerateServerConfig,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"config": {
									Type:        framework.TypeString,
									Description: "The rendered configuration file.",
									Required:    true,
								},
							},
						}},
					},
				},
			},
			HelpSynopsis: `Utility to generate a valid NATS server configuration for an account.`,
		},
	}
}

func (b *backend) pathGenerateServerConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	opId := OperatorIdField(d)

	includePreload := false
	if includePreloadRaw, ok := d.GetOk("include_resolver_preload"); ok {
		includePreload = includePreloadRaw.(bool)
	}

	format := ServerConfigFormatJson
	if formatRaw, ok := d.GetOk("format"); ok {
		formatStr := formatRaw.(string)

		switch formatStr {
		case "json":
			format = ServerConfigFormatJson
		case "nats":
			format = ServerConfigFormatNats
		default:
			return logical.ErrorResponse("unsupported format %q", formatStr), nil
		}
	}

	operator, err := b.Operator(ctx, req.Storage, opId)
	if err != nil {
		return nil, err
	}
	if operator == nil {
		return logical.ErrorResponse("operator %q does not exist", opId.op), nil
	}

	opJwt, err := b.Jwt(ctx, req.Storage, opId)
	if err != nil {
		return nil, err
	}
	if opJwt == nil {
		return nil, fmt.Errorf("operator jwt does not exist")
	}

	sysAccountName := operator.SysAccountName

	var sysPublicKey = ""
	sysAccountKey, err := b.Nkey(ctx, req.Storage, opId.accountId(sysAccountName))
	if err != nil {
		return nil, err
	}
	if sysAccountKey != nil {
		pubKey, err := sysAccountKey.publicKey()
		if err != nil {
			return nil, err
		}
		sysPublicKey = pubKey
	}

	type kv struct {
		key   string
		value string
	}
	preload := []kv{}
	if includePreload {
		for acc, err := range listPaged(ctx, req.Storage, opId.accountsJwtPrefix(), DefaultPagingSize) {
			if err != nil {
				return nil, err
			}

			accId := opId.accountId(acc)
			jwt, err := b.Jwt(ctx, req.Storage, accId)
			if err != nil {
				return nil, err
			}
			if jwt == nil {
				return nil, fmt.Errorf("failed to find account %q jwt", acc)
			}

			nkey, err := b.Nkey(ctx, req.Storage, accId)
			if err != nil {
				return nil, err
			}
			if nkey == nil {
				return nil, fmt.Errorf("failed to find account %q identity key", acc)
			}

			publicKey, err := nkey.publicKey()
			if err != nil {
				return nil, fmt.Errorf("failed to decode account %q public key", acc)
			}

			preload = append(preload, kv{
				key:   publicKey,
				value: jwt.Token,
			})
		}
	}
	slices.SortFunc(preload, func(a kv, b kv) int {
		return strings.Compare(a.key, b.key)
	})

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	switch format {
	case ServerConfigFormatJson:
		data := map[string]any{
			"operator": opJwt.Token,
		}
		if sysPublicKey != "" {
			data["system_account"] = sysPublicKey
		}

		if len(preload) > 0 {
			preloadMap := make(map[string]any, len(preload))
			for _, kv := range preload {
				preloadMap[kv.key] = kv.value
			}
			data["resolver_preload"] = preloadMap
		}

		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		resp.Data = map[string]any{
			"config": string(jsonData),
		}
	case ServerConfigFormatNats:
		builder := strings.Builder{}

		builder.WriteString("operator: ")
		builder.WriteString(opJwt.Token)
		builder.WriteRune('\n')

		if sysPublicKey != "" {
			builder.WriteString("system_account: ")
			builder.WriteString(sysPublicKey)
			builder.WriteRune('\n')
		}

		if len(preload) > 0 {
			builder.WriteRune('\n')
			builder.WriteString("resolver_preload: {")
			for _, v := range preload {
				builder.WriteString("  ")
				builder.WriteString(v.key)
				builder.WriteString(": ")
				builder.WriteString(v.value)
				builder.WriteRune('\n')
			}
			builder.WriteString("}")
			builder.WriteRune('\n')
		}

		resp.Data = map[string]any{
			"config": builder.String(),
		}
	default:
		b.Logger().Error("unexpected format value", "format", format, "raw", d.Get("format"))
	}

	return resp, nil
}
