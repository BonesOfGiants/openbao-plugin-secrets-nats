package natsbackend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/user/v1alpha1"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"

	"encoding/json"
)

type UserCredsParameters struct {
	Operator   string            `json:"operator"`
	Account    string            `json:"account"`
	User       string            `json:"user"`
	Parameters map[string]string `json:"parameters,omitempty"` // Template substitution parameters
}

type UserCredsData struct {
	Creds      string `json:"creds"`
	ExpiresAt  int64  `json:"expiresAt,omitempty"` // Unix timestamp when JWT expires
	Parameters map[string]string
	Sub        string
}

const (
	// An extra bit of time added to the lease duration to ensure that
	// under normal circumstances a revoke at the end of a lease is a noop
	leaseDurationBuffer = time.Duration(5) * time.Second
)

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
			ExistenceCheck: b.pathUserCredsExistenceCheck,
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
				"after": {
					Type:        framework.TypeString,
					Description: `Optional entry to list begin listing after, not required to exist.`,
					Required:    false,
				},
				"limit": {
					Type:        framework.TypeInt,
					Description: `Optional number of entries to return; defaults to all entries.`,
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

func (b *NatsBackend) userCredsSecretType() *framework.Secret {
	return &framework.Secret{
		Type:   userCredsType,
		Renew:  nil,
		Fields: map[string]*framework.FieldSchema{},
		Revoke: b.userCredsRevoke,
	}
}

func (b *NatsBackend) userCredsRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	op := req.Secret.InternalData["op"].(string)
	acc := req.Secret.InternalData["acc"].(string)
	sub := req.Secret.InternalData["sub"].(string)
	exp := req.Secret.InternalData["exp"].(float64)

	if int64(exp) <= time.Now().Unix() {
		// jwt is already expired, no need to do anything
		return nil, nil
	}

	err := b.addAccountRevocationIssue(ctx, req.Storage, IssueAccountRevocationParameters{
		Operator: op,
		Account:  acc,
		Subject:  sub,
	}, true)
	if err != nil {
		if errors.Is(err, accountNotFoundError) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to add account revocation: %w", err)
	}

	return nil, nil
}

func (b *NatsBackend) pathReadUserCreds(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	op := d.Get("operator").(string)
	acc := d.Get("account").(string)
	user := d.Get("user").(string)

	path := getUserIssuePath(op, acc, user)
	issue, err := getFromStorage[IssueUserStorage](ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		return nil, nil
	}

	parameters, err := parseUserParameters(d.Get("parameters"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse parameters: %w", err)
	}

	fmt.Printf("params: %+v, raw: %+v\n", parameters, d.Get("parameters"))

	userNkey, err := readUserNkey(ctx, req.Storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read user nkey: %w", err)
	}
	if userNkey == nil {
		return nil, nil
	}

	nkey, err := nkeys.FromSeed(userNkey.Seed)
	if err != nil {
		return nil, fmt.Errorf("could not create keypair from seed: %s", err)
	}

	result, err := generateUserCreds(ctx, req.Storage, &userJwtParams{
		operator:   op,
		account:    acc,
		group:      user,
		user:       user,
		ttl:        issue.ExpirationS,
		signingKey: issue.UseSigningKey,
		claims:     &issue.ClaimsTemplate,
		parameters: parameters,
		nkey:       nkey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate user creds: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("unexpected null creds")
	}

	resp := b.Secret(userCredsType).Response(map[string]any{
		"operator":   op,
		"account":    acc,
		"user":       user,
		"creds":      result.creds,
		"parameters": result.parameters,
		"expiresAt":  result.expiresAt,
	}, map[string]any{
		"op":  op,
		"acc": acc,
		"sub": result.sub,
		"exp": result.expiresAt,
	})

	resp.Secret.LeaseOptions.TTL = time.Duration(issue.ExpirationS)*time.Second + leaseDurationBuffer
	resp.Secret.LeaseOptions.MaxTTL = resp.Secret.TTL

	return resp, nil
}

func parseUserParameters(parameters any) (map[string]string, error) {
	result := map[string]string{}

	if parameters == nil {
		return result, nil
	}

	str, ok := parameters.(string)
	if !ok {
		return nil, fmt.Errorf("not a valid string")
	}
	if str == "" {
		return result, nil
	}

	err := json.Unmarshal([]byte(str), &result)
	if err != nil {
		for pair := range strings.SplitSeq(str, ",") {
			parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid key=value pair: %s", pair)
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key == "" {
				return nil, fmt.Errorf("empty key in pair: %s", pair)
			}
			result[key] = value
		}
	}

	return result, nil
}

// applyTemplateParameters replaces placeholders in claims template with actual values
func applyTemplateParameters(template *v1alpha1.UserClaims, parameters map[string]string) (*v1alpha1.UserClaims, error) {
	if template == nil {
		return &v1alpha1.UserClaims{}, nil
	}

	// Convert template to JSON for string replacement
	templateBytes, err := json.Marshal(template)
	if err != nil {
		return nil, fmt.Errorf("could not marshal template: %s", err)
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

	return &processedClaims, nil
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

func (b *NatsBackend) pathListUserCreds(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// defer to user issues list,
	// since we don't keep storage for user creds
	return b.pathListUserIssues(ctx, req, data)
}

func (b *NatsBackend) pathUserCredsExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	issue, err := readUserIssue(ctx, req.Storage, IssueUserParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
		User:     data.Get("user").(string),
	})
	if err != nil {
		return false, err
	}

	return issue != nil, nil
}

type userCredsResult struct {
	creds      string
	parameters map[string]string
	sub        string
	expiresAt  int64
}

func generateUserCreds(ctx context.Context, s logical.Storage, p *userJwtParams) (*userCredsResult, error) {
	result, err := generateUserJWT(ctx, s, p)
	if err != nil {
		return nil, fmt.Errorf("failed to generate jwt: %w", err)
	}

	seed, err := p.nkey.Seed()
	if err != nil {
		return nil, fmt.Errorf("failed to decode seed: %w", err)
	}

	creds, err := jwt.FormatUserConfig(result.jwt, seed)
	if err != nil {
		return nil, fmt.Errorf("failed to format user creds: %w", err)
	}

	publicKey, err := p.nkey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return &userCredsResult{
		creds:      string(creds),
		parameters: result.parameters,
		sub:        publicKey,
		expiresAt:  result.expiresAt,
	}, nil
}

type userJwtParams struct {
	operator   string
	account    string
	group      string
	user       string
	claims     *v1alpha1.UserClaims
	signingKey string
	ttl        int
	nkey       nkeys.KeyPair
	parameters map[string]string
}

type userJwtResult struct {
	jwt        string
	parameters map[string]string
	expiresAt  int64
}

func generateUserJWT(ctx context.Context, s logical.Storage, p *userJwtParams) (userJwtResult, error) {
	parameters := p.parameters

	if parameters == nil {
		parameters = make(map[string]string, 3)
	}

	parameters["name()"] = p.user
	parameters["account()"] = p.account
	parameters["operator()"] = p.operator

	claims, err := applyTemplateParameters(p.claims, parameters)
	if err != nil {
		return userJwtResult{}, fmt.Errorf("could not apply template parameters: %s", err)
	}

	var seed []byte

	accountNkey, err := readAccountNkey(ctx, s, NkeyParameters{
		Operator: p.operator,
		Account:  p.account,
	})
	if err != nil {
		return userJwtResult{}, fmt.Errorf("failed to read account nkey: %w", err)
	}
	if accountNkey == nil {
		return userJwtResult{}, fmt.Errorf("account nkey not found: %v", p.account)
	}

	if p.signingKey == "" {
		seed = accountNkey.Seed
	} else {
		signingNkey, err := readAccountSigningNkey(ctx, s, NkeyParameters{
			Operator: p.operator,
			Account:  p.account,
			Signing:  p.signingKey,
		})
		if err != nil {
			return userJwtResult{}, fmt.Errorf("failed to read signing key: %s", err)
		}
		if signingNkey == nil {
			return userJwtResult{}, fmt.Errorf("signing key not found: %v, %s", p.account, p.signingKey)
		}
		seed = signingNkey.Seed

		accountKeyPair, err := nkeys.FromSeed(accountNkey.Seed)
		if err != nil {
			return userJwtResult{}, fmt.Errorf("failed to decode account nkey: %w", err)
		}
		accountPublicKey, err := accountKeyPair.PublicKey()
		if err != nil {
			return userJwtResult{}, fmt.Errorf("failed to decode account public key: %w", err)
		}

		claims.IssuerAccount = accountPublicKey
	}

	signingKeyPair, err := nkeys.FromSeed(seed)
	if err != nil {
		return userJwtResult{}, fmt.Errorf("failed to decode signing key: %w", err)
	}
	signingPublicKey, err := signingKeyPair.PublicKey()
	if err != nil {
		return userJwtResult{}, fmt.Errorf("failed to decode account public key: %w", err)
	}

	sub, err := p.nkey.PublicKey()
	if err != nil {
		return userJwtResult{}, fmt.Errorf("failed to decode public key: %w", err)
	}

	claims.ClaimsData.Subject = sub
	claims.ClaimsData.Issuer = signingPublicKey

	if p.group != "" {
		claims.Tags = append(claims.Tags, p.group)
	}

	// Set expiration if configured
	var expiresAt int64
	if p.ttl > 0 {
		expiresAt = time.Now().Add(time.Duration(p.ttl) * time.Second).Unix()
		claims.ClaimsData.Expires = expiresAt
	}

	// Convert and encode JWT
	natsJwt, err := v1alpha1.Convert(claims)
	if err != nil {
		return userJwtResult{}, fmt.Errorf("failed to convert claims to nats jwt: %s", err)
	}

	jwt, err := natsJwt.Encode(signingKeyPair)
	if err != nil {
		return userJwtResult{}, fmt.Errorf("failed to encode jwt: %s", err)
	}

	log.Info().
		Str("operator", p.operator).
		Str("account", p.account).
		Str("group", p.group).
		Str("user", p.user).
		Int64("expiresAt", expiresAt).
		Msg("fresh JWT generated")

	return userJwtResult{
		jwt:        jwt,
		expiresAt:  expiresAt,
		parameters: parameters,
	}, nil
}
