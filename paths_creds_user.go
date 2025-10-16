package natsbackend

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/user/v1alpha1"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"

	"encoding/json"
)

// UserCredsParameters now includes template parameters
type UserCredsParameters struct {
	Operator   string            `json:"operator"`
	Account    string            `json:"account"`
	User       string            `json:"user"`
	Parameters map[string]string `json:"parameters,omitempty"` // Template substitution parameters
}

// UserCredsData for response
type UserCredsData struct {
	Operator   string            `json:"operator"`
	Account    string            `json:"account"`
	User       string            `json:"user"`
	Creds      string            `json:"creds"`
	Parameters map[string]string `json:"parameters,omitempty"`
	ExpiresAt  int64             `json:"expiresAt,omitempty"` // Unix timestamp when JWT expires
}

func pathUserCreds(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/" + framework.GenericNameRegex("user") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"account": {
					Type:        framework.TypeString,
					Description: "account identifier",
					Required:    false,
				},
				"user": {
					Type:        framework.TypeString,
					Description: "user identifier",
					Required:    false,
				},
				"parameters": {
					Type:        framework.TypeString,
					Description: "Template parameters for substitution (e.g., beholder_id, etc.)",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadUserCreds,
				},
			},
			HelpSynopsis:    `Generates fresh user credentials on-demand.`,
			HelpDescription: `Reads the user template and generates a fresh JWT with current timestamp and provided parameters, then returns complete NATS credentials.`,
		},
		{
			Pattern: "creds/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"account": {
					Type:        framework.TypeString,
					Description: "account identifier",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListUserCreds,
				},
			},
			HelpSynopsis:    "List available user credential templates",
			HelpDescription: "List all users that have credential templates configured",
		},
	}
}

func (b *NatsBackend) pathReadUserCreds(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	// Extract path parameters directly from data.Raw
	params := UserCredsParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
		User:     data.Get("user").(string),
	}

	// Parse parameters string from query parameter
	if parametersStr := data.Get("parameters"); parametersStr != nil {
		if paramStr, ok := parametersStr.(string); ok && paramStr != "" {
			params.Parameters = make(map[string]string)

			// Try to parse as JSON first
			err := json.Unmarshal([]byte(paramStr), &params.Parameters)
			if err != nil {
				// If JSON parsing fails, try key=value format
				err = parseKeyValueString(paramStr, params.Parameters)
				if err != nil {
					log.Error().Err(err).Str("parametersStr", paramStr).Msg("Failed to parse parameters")
					return logical.ErrorResponse("Invalid parameters format. Use key=value,key2=value2 or JSON"), logical.ErrInvalidRequest
				}
			}

			log.Debug().Interface("parsedParameters", params.Parameters).Msg("Parsed parameters")
		}
	}

	// Generate fresh credentials on-demand
	userCreds, err := generateUserCreds(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("GeneratingCredsFailedError: %s", err.Error())), err
	}

	if userCreds == nil {
		return logical.ErrorResponse("UserTemplateNotFoundError"), nil
	}

	return createResponseUserCredsData(userCreds)
}

func parseKeyValueString(input string, result map[string]string) error {
	if input == "" {
		return nil
	}

	pairs := strings.SplitSeq(input, ",")
	for pair := range pairs {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid key=value pair: %s", pair)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return fmt.Errorf("empty key in pair: %s", pair)
		}
		result[key] = value
	}
	return nil
}

func (b *NatsBackend) pathListUserCreds(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params UserCredsParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	entries, err := listUserCreds(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListCredsFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func generateUserCreds(ctx context.Context, storage logical.Storage, params UserCredsParameters) (*UserCredsData, error) {
	log.Info().
		Str("operator", params.Operator).
		Str("account", params.Account).
		Str("user", params.User).
		Interface("parameters", params.Parameters).
		Msg("generating fresh user credentials")

	// 1. Read the user issue template
	issue, err := readUserIssue(ctx, storage, IssueUserParameters{
		Operator: params.Operator,
		Account:  params.Account,
		User:     params.User,
	})
	if err != nil {
		return nil, fmt.Errorf("could not read user template: %s", err)
	}
	if issue == nil {
		return nil, logical.ErrUnsupportedPath
	}

	if params.Parameters == nil {
		params.Parameters = make(map[string]string, 3)
	}

	params.Parameters["name()"] = params.User
	params.Parameters["account()"] = params.Account
	params.Parameters["operator()"] = params.Operator

	// 2. Apply template parameters to claims
	processedClaims, err := applyTemplateParameters(issue.ClaimsTemplate, params.Parameters)
	if err != nil {
		return nil, fmt.Errorf("could not apply template parameters: %s", err)
	}

	// 3. Generate fresh JWT
	jwtToken, expiresAt, err := generateUserJWT(ctx, storage, *issue, processedClaims)
	if err != nil {
		return nil, fmt.Errorf("could not generate JWT: %s", err)
	}

	// 4. Get user nkey for creds file
	userNkey, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: params.Operator,
		Account:  params.Account,
		User:     params.User,
	})
	if err != nil {
		return nil, fmt.Errorf("could not read user nkey: %s", err)
	}
	if userNkey == nil {
		return nil, logical.ErrUnsupportedPath
	}

	// 5. Create creds file
	userKeyPair, err := nkeys.FromSeed(userNkey.Seed)
	if err != nil {
		return nil, fmt.Errorf("could not create keypair from seed: %s", err)
	}
	seed, err := userKeyPair.Seed()
	if err != nil {
		return nil, fmt.Errorf("could not get seed: %s", err)
	}

	creds, err := jwt.FormatUserConfig(jwtToken, seed)
	if err != nil {
		return nil, fmt.Errorf("could not format user creds: %s", err)
	}

	return &UserCredsData{
		Operator:   params.Operator,
		Account:    params.Account,
		User:       params.User,
		Creds:      string(creds),
		Parameters: params.Parameters,
		ExpiresAt:  expiresAt,
	}, nil
}

// applyTemplateParameters replaces placeholders in claims template with actual values
func applyTemplateParameters(template v1alpha1.UserClaims, parameters map[string]string) (v1alpha1.UserClaims, error) {
	// Convert template to JSON for string replacement
	templateBytes, err := json.Marshal(template)
	if err != nil {
		return template, fmt.Errorf("could not marshal template: %s", err)
	}

	templateStr := string(templateBytes)

	// Find all template variables in the format {{variable}}
	requiredVars := findTemplateVariables(templateStr)

	// Check if all required variables are provided
	if len(requiredVars) > 0 {
		var missingVars []string
		for _, variable := range requiredVars {
			if _, exists := parameters[variable]; !exists {
				missingVars = append(missingVars, variable)
			}
		}

		if len(missingVars) > 0 {
			return template, fmt.Errorf("missing required template parameters: %v", missingVars)
		}
	}

	// Replace all {{key}} placeholders with values
	for key, value := range parameters {
		placeholder := fmt.Sprintf("{{%s}}", key)
		templateStr = strings.ReplaceAll(templateStr, placeholder, value)
	}

	// Convert back to claims
	var processedClaims v1alpha1.UserClaims
	err = json.Unmarshal([]byte(templateStr), &processedClaims)
	if err != nil {
		return template, fmt.Errorf("could not unmarshal processed template: %s", err)
	}

	return processedClaims, nil
}

func findTemplateVariables(templateStr string) []string {
	var variables []string
	variableMap := make(map[string]bool) // To avoid duplicates

	// Simple regex-like approach using string parsing
	for i := 0; i < len(templateStr)-1; i++ {
		if templateStr[i] == '{' && templateStr[i+1] == '{' {
			// Find the closing }}
			start := i + 2
			end := -1
			for j := start; j < len(templateStr)-1; j++ {
				if templateStr[j] == '}' && templateStr[j+1] == '}' {
					end = j
					break
				}
			}

			if end != -1 {
				variable := templateStr[start:end]
				variable = strings.TrimSpace(variable)
				if variable != "" && !variableMap[variable] {
					variables = append(variables, variable)
					variableMap[variable] = true
				}
				i = end + 1 // Skip past the closing }}
			}
		}
	}

	return variables
}

// generateUserJWT creates a fresh JWT from the template
func generateUserJWT(ctx context.Context, storage logical.Storage, issue IssueUserStorage, claims v1alpha1.UserClaims) (string, int64, error) {
	// Get signing key (account or signing key)
	useSigningKey := issue.UseSigningKey
	var seed []byte

	accountNkey, err := readAccountNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return "", 0, fmt.Errorf("could not read account nkey: %s", err)
	}
	if accountNkey == nil {
		return "", 0, fmt.Errorf("account nkey does not exist: %s", issue.Account)
	}

	accountKeyPair, err := nkeys.FromSeed(accountNkey.Seed)
	if err != nil {
		return "", 0, err
	}
	accountPublicKey, err := accountKeyPair.PublicKey()
	if err != nil {
		return "", 0, err
	}

	if useSigningKey == "" {
		seed = accountNkey.Seed
	} else {
		signingNkey, err := readAccountSigningNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			Signing:  useSigningKey,
		})
		if err != nil {
			return "", 0, fmt.Errorf("could not read signing nkey: %s", err)
		}
		if signingNkey == nil {
			return "", 0, fmt.Errorf("account signing nkey does not exist: %s", useSigningKey)
		}
		seed = signingNkey.Seed
	}

	signingKeyPair, err := nkeys.FromSeed(seed)
	if err != nil {
		return "", 0, err
	}
	signingPublicKey, err := signingKeyPair.PublicKey()
	if err != nil {
		return "", 0, err
	}

	// Get user public key for subject
	userNkey, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	})
	if err != nil {
		return "", 0, fmt.Errorf("could not read user nkey: %s", err)
	}
	if userNkey == nil {
		return "", 0, fmt.Errorf("user nkey does not exist")
	}

	userKeyPair, err := nkeys.FromSeed(userNkey.Seed)
	if err != nil {
		return "", 0, err
	}
	userPublicKey, err := userKeyPair.PublicKey()
	if err != nil {
		return "", 0, err
	}

	// Set required fields
	if useSigningKey != "" {
		claims.IssuerAccount = accountPublicKey
	}
	claims.ClaimsData.Subject = userPublicKey
	claims.ClaimsData.Issuer = signingPublicKey

	// Set expiration if configured
	var expiresAt int64
	if issue.ExpirationS > 0 {
		expiresAt = time.Now().Add(time.Duration(issue.ExpirationS) * time.Second).Unix()
		claims.ClaimsData.Expires = expiresAt
	}

	// Convert and encode JWT
	natsJwt, err := v1alpha1.Convert(&claims)
	if err != nil {
		return "", 0, fmt.Errorf("could not convert claims to nats jwt: %s", err)
	}

	token, err := natsJwt.Encode(signingKeyPair)
	if err != nil {
		return "", 0, fmt.Errorf("could not encode jwt: %s", err)
	}

	log.Info().
		Str("operator", issue.Operator).
		Str("account", issue.Account).
		Str("user", issue.User).
		Int64("expiresAt", expiresAt).
		Msg("fresh JWT generated")

	return token, expiresAt, nil
}

func listUserCreds(ctx context.Context, storage logical.Storage, params UserCredsParameters) ([]string, error) {
	// List user issues (templates) instead of stored creds
	path := getUserIssuePath(params.Operator, params.Account, "")
	return listIssues(ctx, storage, path)
}

func createResponseUserCredsData(UserCredsData *UserCredsData) (*logical.Response, error) {
	rval := map[string]any{}
	err := stm.StructToMap(UserCredsData, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}
