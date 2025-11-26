package natsbackend

import (
	"context"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nats-io/nkeys"
)

func pathUserGroupCreds(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user-group/" + framework.GenericNameRegex("group") + "/user/" + framework.GenericNameRegex("user") + "$",
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
				"group": {
					Type:        framework.TypeString,
					Description: "user group name",
					Required:    false,
				},
				"user": {
					Type:        framework.TypeString,
					Description: "user name",
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
					Callback: b.pathUserGroupCredsRead,
				},
			},
			HelpSynopsis:    `Generates fresh user credentials on-demand.`,
			HelpDescription: `Reads the user template and generates a fresh JWT with current timestamp and provided parameters, then returns complete NATS credentials.`,
		},
	}
}

func (b *NatsBackend) pathUserGroupCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	op := d.Get("operator").(string)
	acc := d.Get("account").(string)
	group := d.Get("group").(string)

	issue, err := b.UserGroupIssue(ctx, req.Storage, op, acc, group)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		return nil, nil
	}

	user := d.Get("user").(string)

	parameters, err := parseUserParameters(d.Get("parameters"))
	if err != nil {
		return nil, fmt.Errorf("unable to parse parameters: %w", err)
	}

	nkey, err := nkeys.CreateUser()
	if err != nil {
		return nil, fmt.Errorf("failed to generate user nkey: %w", err)
	}

	userCreds, err := generateUserCreds(ctx, req.Storage, &userJwtParams{
		operator:   issue.operator,
		account:    issue.account,
		group:      issue.group,
		user:       user,
		ttl:        issue.ExpirationS,
		signingKey: issue.UseSigningKey,
		claims:     issue.ClaimsTemplate,
		parameters: parameters,
		nkey:       nkey,
	})
	if err != nil {
		return nil, err
	}
	if userCreds == nil {
		return nil, nil
	}

	resp := b.Secret(userCredsType).Response(map[string]any{
		"operator":   op,
		"account":    acc,
		"group":      group,
		"user":       user,
		"creds":      userCreds.creds,
		"parameters": userCreds.parameters,
		"expiresAt":  userCreds.expiresAt,
	}, map[string]any{
		"op":  op,
		"acc": acc,
		"sub": userCreds.sub,
		"exp": userCreds.expiresAt,
	})

	fmt.Printf("CREATING CREDS: %+v, %+v\n", userCreds.expiresAt, issue.ExpirationS)

	resp.Secret.LeaseOptions.TTL = time.Duration(issue.ExpirationS) * time.Second
	resp.Secret.LeaseOptions.MaxTTL = resp.Secret.TTL

	return resp, nil
}
