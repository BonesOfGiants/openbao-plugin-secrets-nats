package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"

	accountv1 "github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/account/v1alpha1"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/common"
	operatorv1 "github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/operator/v1alpha1"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/user/v1alpha1"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
)

type IssueOperatorStorage struct {
	Operator            string                    `json:"operator"`
	CreateSystemAccount bool                      `json:"createSystemAccount"`
	Claims              operatorv1.OperatorClaims `json:"claims"`
}

// IssueOperatorParameters
// +k8s:deepcopy-gen=true
type IssueOperatorParameters struct {
	Operator            string                    `json:"operator"`
	CreateSystemAccount bool                      `json:"createSystemAccount,omitempty"`
	Claims              operatorv1.OperatorClaims `json:"claims"`
}

type IssueOperatorData struct {
	Operator            string                    `json:"operator"`
	CreateSystemAccount bool                      `json:"createSystemAccount"`
	Claims              operatorv1.OperatorClaims `json:"claims"`
	Status              IssueOperatorStatus       `json:"status"`
}

type IssueOperatorStatus struct {
	Operator          IssueStatus `json:"operator"`
	SystemAccount     IssueStatus `json:"systemAccount"`
	SystemAccountUser IssueStatus `json:"systemAccountUser"`
}

type IssueStatus struct {
	Nkey bool `json:"nkey"`
	JWT  bool `json:"jwt"`
}

func pathOperatorIssue(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"createSystemAccount": {
					Type:        framework.TypeBool,
					Description: "Create system account (default: false)",
					Required:    false,
				},
				"claims": {
					Type:        framework.TypeMap,
					Description: "Operator claims (jwt.OperatorClaims from github.com/nats-io/jwt/v2)",
					Required:    false,
				},
				"syncAccountServer": {
					Type:        framework.TypeBool,
					Description: "Sync account jwt's with account server",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathOperatorIssueExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorIssue,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddOperatorIssue,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadOperatorIssue,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteOperatorIssue,
				},
			},
			HelpSynopsis:    `Manages operator issueing.`,
			HelpDescription: ``,
		},
		{
			Pattern: "issue/operator/?$",
			Fields: map[string]*framework.FieldSchema{
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
					Callback: b.pathListOperatorIssues,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}

}

func (b *NatsBackend) pathAddOperatorIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueOperatorParameters{}
	json.Unmarshal(jsonString, &params)

	err = addOperatorIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingIssueFailedError + ":" + err.Error()), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadOperatorIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	issue, err := readOperatorIssue(ctx, req.Storage, IssueOperatorParameters{
		Operator: data.Get("operator").(string),
	})
	if err != nil || issue == nil {
		return nil, err
	}

	status := getIssueOperatorStatus(ctx, req.Storage, issue)
	return createResponseIssueOperatorData(issue, status)
}

func (b *NatsBackend) pathOperatorIssueExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	issue, err := readOperatorIssue(ctx, req.Storage, IssueOperatorParameters{
		Operator: data.Get("operator").(string),
	})
	if err != nil {
		return false, err
	}

	return issue != nil, nil
}

func (b *NatsBackend) pathListOperatorIssues(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, issueOperatorPrefix, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(filterSubkeys(entries)), nil
}

func (b *NatsBackend) pathDeleteOperatorIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueOperatorParameters{}
	json.Unmarshal(jsonString, &params)

	// delete issue and all related nkeys and jwt
	err = deleteOperatorIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteIssueFailedError), nil
	}
	return nil, nil

}
func addOperatorIssue(ctx context.Context, storage logical.Storage, params IssueOperatorParameters) error {
	log.Info().
		Str("operator", params.Operator).
		Msgf("issue operator")

	issue, err := storeOperatorIssue(ctx, storage, params)
	if err != nil {
		return err
	}

	err = refreshOperator(ctx, storage, issue)
	if err != nil {
		return err
	}

	return syncOperatorAccounts(ctx, storage, issue)
}

func syncOperatorAccounts(ctx context.Context, storage logical.Storage, issue *IssueOperatorStorage) error {
	s, err := getAccountSync(ctx, storage, issue.Operator)
	if err != nil {
		log.Error().
			Str("operator", issue.Operator).
			Err(err).
			Msg("failed to sync accounts")
		return nil
	} else if s == nil {
		log.Info().Msgf("%s: account server sync disabled", issue.Operator)
		return nil
	}
	defer s.CloseConnection()

	path := getAccountIssuePath(issue.Operator, "")
	accounts, err := storage.List(ctx, path)
	if err != nil {
		return err
	}
	for _, account := range filterSubkeys(accounts) {
		err = syncAccountUpdate(ctx, storage, s, &IssueAccountStorage{
			Operator: issue.Operator,
			Account:  account,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func refreshOperator(ctx context.Context, storage logical.Storage, issue *IssueOperatorStorage) error {

	// create nkey and signing nkeys
	err := issueOperatorNkeys(ctx, storage, *issue)
	if err != nil {
		return err
	}

	// create jwt
	err = issueOperatorJWT(ctx, storage, *issue)
	if err != nil {
		return err
	}

	if issue.CreateSystemAccount {
		// create system account
		err := issueSystemAccount(ctx, storage, *issue)
		if err != nil {
			return err
		}
	}
	return nil
}

func readOperatorIssue(ctx context.Context, storage logical.Storage, params IssueOperatorParameters) (*IssueOperatorStorage, error) {
	path := getOperatorIssuePath(params.Operator)
	return getFromStorage[IssueOperatorStorage](ctx, storage, path)
}

func deleteOperatorIssue(ctx context.Context, storage logical.Storage, params IssueOperatorParameters) error {
	// get stored signing keys
	issue, err := readOperatorIssue(ctx, storage, params)
	if err != nil {
		return err
	}
	if issue == nil {
		// nothing to delete
		return nil
	}

	// delete operator nkey
	nkey := NkeyParameters{
		Operator: issue.Operator,
	}
	err = deleteOperatorNkey(ctx, storage, nkey)
	if err != nil {
		return err
	}

	// delete operator siginig nkeys
	for _, signingKey := range issue.Claims.SigningKeys {
		nkey := NkeyParameters{
			Operator: issue.Operator,
			Signing:  signingKey,
		}
		err := deleteOperatorSigningNkey(ctx, storage, nkey)
		if err != nil {
			return err
		}
	}

	// if generated, delete system account
	if issue.CreateSystemAccount {
		err = deleteAccountIssue(ctx, storage, IssueAccountParameters{
			Operator: issue.Operator,
			Account:  DefaultSysAccountName,
		})
		if err != nil {
			return err
		}

		err := deleteUserIssue(ctx, storage, IssueUserParameters{
			Operator: issue.Operator,
			Account:  DefaultSysAccountName,
			User:     DefaultPushUser,
		})
		if err != nil {
			return err
		}
	}

	// delete operator jwt
	jwt := JWTParameters{
		Operator: issue.Operator,
	}
	err = deleteOperatorJWT(ctx, storage, jwt)
	if err != nil {
		return err
	}

	// delete operator issue
	path := getOperatorIssuePath(params.Operator)
	return deleteFromStorage(ctx, storage, path)
}

func storeOperatorIssue(ctx context.Context, storage logical.Storage, params IssueOperatorParameters) (*IssueOperatorStorage, error) {
	path := getOperatorIssuePath(params.Operator)

	issue, err := getFromStorage[IssueOperatorStorage](ctx, storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		issue = &IssueOperatorStorage{}
	} else {
		// diff current and incomming signing keys
		// delete removed signing keys
		for _, signingKey := range issue.Claims.SigningKeys {
			if !slices.Contains(params.Claims.SigningKeys, signingKey) {
				p := NkeyParameters{
					Operator: params.Operator,
					Signing:  signingKey,
				}
				err := deleteOperatorSigningNkey(ctx, storage, p)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	issue.Claims = params.Claims
	issue.Operator = params.Operator
	issue.CreateSystemAccount = params.CreateSystemAccount
	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func issueOperatorNkeys(ctx context.Context, storage logical.Storage, issue IssueOperatorStorage) error {
	var refreshAccounts bool

	// issue operator nkey
	p := NkeyParameters{
		Operator: issue.Operator,
	}
	stored, err := readOperatorNkey(ctx, storage, p)
	if err != nil {
		return err
	}
	if stored == nil {
		err := addOperatorNkey(ctx, storage, p)
		if err != nil {
			return err
		}
		refreshAccounts = true
	}

	// issue operator siginig nkeys
	for _, signingKey := range issue.Claims.SigningKeys {
		p := NkeyParameters{
			Operator: issue.Operator,
			Signing:  signingKey,
		}
		stored, err := readOperatorSigningNkey(ctx, storage, p)
		if err != nil {
			return err
		}
		if stored == nil {
			err := addOperatorSigningNkey(ctx, storage, p)
			if err != nil {
				return err
			}
			refreshAccounts = true
		}
	}

	if refreshAccounts {
		// force update of all existing accounts
		// so they can use the new operator nkey to sign their jwt
		log.Info().Str("operator", issue.Operator).Msg("managed nkeys modified, all accounts will be updated")
		err = updateAccountIssues(ctx, storage, issue)
		if err != nil {
			log.Err(err).Str("operator", issue.Operator).Msg("failed to update accounts")
			return err
		}
	}

	log.Info().
		Str("operator", issue.Operator).Msgf("nkey assigned")

	return nil
}

func issueOperatorJWT(ctx context.Context, storage logical.Storage, issue IssueOperatorStorage) error {
	// receive operator nkey and puplic key
	data, err := readOperatorNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
	})
	if err != nil {
		return fmt.Errorf("could not read operator nkey: %s", err)
	}
	operatorKeyPair, err := nkeys.FromSeed(data.Seed)
	if err != nil {
		return err
	}
	operatorPublicKey, err := operatorKeyPair.PublicKey()
	if err != nil {
		return err
	}

	// receive public key of system account
	sysAccountPublicKey := ""
	data, err = readAccountNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  DefaultSysAccountName,
	})
	if err != nil {
		return fmt.Errorf("could not read system account nkey: %s", err)
	}
	if data != nil {
		// log.Warn().
		// 	Str("operator", issue.Operator).
		// 	Msgf("system account nkey does not exist: %s - Cannot create jwt.", DefaultSysAccountName)
		// return nil
		// } else {
		sysAccountKeyPair, err := nkeys.FromSeed(data.Seed)
		if err != nil {
			return fmt.Errorf("could not convert system account nkey to kp: %s", err)
		}
		sysAccountPublicKey, err = sysAccountKeyPair.PublicKey()
		if err != nil {
			return fmt.Errorf("could not extract pulic key from system account nkey: %s", err)
		}
	}

	// receive public keys of signing keys
	var signingPublicKeys []string
	for _, signingKey := range issue.Claims.SigningKeys {
		data, err := readOperatorSigningNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Signing:  signingKey,
		})
		if err != nil {
			return err
		}
		if data == nil {
			log.Warn().
				Str("operator", issue.Operator).
				Msgf("signing nkey does not exist: %s - Cannot create jwt.", signingKey)
			continue
		}
		signingKeyPair, err := nkeys.FromSeed(data.Seed)
		if err != nil {
			return err
		}

		signingKey, err := signingKeyPair.PublicKey()
		if err != nil {
			return err
		}
		signingPublicKeys = append(signingPublicKeys, signingKey)
	}

	issue.Claims.ClaimsData.Subject = operatorPublicKey
	issue.Claims.ClaimsData.Issuer = operatorPublicKey
	issue.Claims.Operator.SystemAccount = sysAccountPublicKey
	issue.Claims.Operator.SigningKeys = signingPublicKeys
	natsJwt := operatorv1.Convert(&issue.Claims)
	token, err := natsJwt.Encode(operatorKeyPair)
	if err != nil {
		return fmt.Errorf("could not encode operator jwt: %s", err)
	}

	// store operator jwt
	err = addOperatorJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		JWTStorage: JWTStorage{
			JWT: token,
		},
	})
	if err != nil {
		return err
	}

	log.Info().
		Str("operator", issue.Operator).
		Msgf("jwt created/updated")
	return nil
}

func issueSystemAccount(ctx context.Context, storage logical.Storage, issue IssueOperatorStorage) error {
	// create system account jwt and nkey
	err := addAccountIssue(ctx, storage, IssueAccountParameters{
		Operator: issue.Operator,
		Account:  DefaultSysAccountName,
		Claims: accountv1.AccountClaims{
			Account: accountv1.Account{
				Imports: []accountv1.Import{},
				Exports: []accountv1.Export{
					{
						Name:                 "account-monitoring-services",
						Subject:              "$SYS.REQ.ACCOUNT.*.*",
						Type:                 "Service",
						ResponseType:         jwt.ResponseTypeStream,
						AccountTokenPosition: 4,
						Info: common.Info{
							Description: `Request account specific monitoring services for: SUBSZ, CONNZ, LEAFZ, JSZ and INFO`,
							InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
						},
					},
					{
						Name:                 "account-monitoring-streams",
						Subject:              "$SYS.ACCOUNT.*.>",
						Type:                 "Stream",
						AccountTokenPosition: 3,
						Info: common.Info{
							Description: `Account specific monitoring stream`,
							InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
						},
					},
				},
				Limits: accountv1.OperatorLimits{
					NatsLimits: common.NatsLimits{
						Subs:    -1,
						Data:    -1,
						Payload: -1,
					},
					AccountLimits: accountv1.AccountLimits{
						Imports:         -1,
						Exports:         -1,
						WildcardExports: true,
						Conn:            -1,
						LeafNodeConn:    -1,
					},
				},
				DefaultPermissions: common.Permissions{
					Pub: &common.Permission{
						Allow: []string{},
						Deny:  []string{},
					},
					Sub: &common.Permission{
						Allow: []string{},
						Deny:  []string{},
					},
				},
			},
		},
	})
	if err != nil {
		return err
	}

	// create system account user jwt and nkey
	err = addUserIssue(ctx, storage, IssueUserParameters{
		Operator: issue.Operator,
		Account:  DefaultSysAccountName,
		User:     DefaultPushUser,
		ClaimsTemplate: v1alpha1.UserClaims{
			User: v1alpha1.User{
				UserPermissionLimits: v1alpha1.UserPermissionLimits{
					Limits: v1alpha1.Limits{
						NatsLimits: common.NatsLimits{
							Subs:    -1,
							Payload: -1,
							Data:    -1,
						},
					},
				},
			},
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func updateAccountIssues(ctx context.Context, storage logical.Storage, issue IssueOperatorStorage) error {
	path := getAccountIssuePath(issue.Operator, "")
	accounts, err := storage.List(ctx, path)
	if err != nil {
		return err
	}

	for _, account := range filterSubkeys(accounts) {
		acc, err := readAccountIssue(ctx, storage, IssueAccountParameters{
			Operator: issue.Operator,
			Account:  account,
		})
		if err != nil {
			return err
		}
		if acc == nil {
			return err
		}
		err = refreshAccount(ctx, storage, acc)
		if err != nil {
			return err
		}
	}
	return nil
}

func getOperatorIssuePath(operator string) string {
	return issueOperatorPrefix + operator
}

func getIssueOperatorStatus(ctx context.Context, storage logical.Storage, issue *IssueOperatorStorage) *IssueOperatorStatus {
	var status IssueOperatorStatus

	// operator status
	nkey, err := readOperatorNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
	})
	if err == nil && nkey != nil {
		status.Operator.Nkey = true
	}
	jwt, err := readOperatorJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
	})
	if err == nil && jwt != nil {
		status.Operator.JWT = true
	}

	// sys account status
	nkey, err = readAccountNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  DefaultSysAccountName,
	})
	if err == nil && nkey != nil {
		status.SystemAccount.Nkey = true

	}
	jwt, err = readAccountJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  DefaultSysAccountName,
	})
	if err == nil && jwt != nil {
		status.SystemAccount.JWT = true
	}

	// sys account user status - since JWTs are generated on-demand, check template and nkey
	nkey, err = readUserNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  DefaultSysAccountName,
		User:     DefaultPushUser,
	})
	if err == nil && nkey != nil {
		status.SystemAccountUser.Nkey = true
	}

	// Check if user template exists (since JWTs are generated on-demand)
	userTemplate, err := readUserIssue(ctx, storage, IssueUserParameters{
		Operator: issue.Operator,
		Account:  DefaultSysAccountName,
		User:     DefaultPushUser,
	})
	if err == nil && userTemplate != nil {
		// User template exists, so JWT can be generated on-demand
		status.SystemAccountUser.JWT = true
	}

	return &status
}

func createResponseIssueOperatorData(issue *IssueOperatorStorage, status *IssueOperatorStatus) (*logical.Response, error) {
	data := &IssueOperatorData{
		Operator:            issue.Operator,
		CreateSystemAccount: issue.CreateSystemAccount,
		Claims:              issue.Claims,
		Status:              *status,
	}

	rval := map[string]any{}
	err := stm.StructToMap(data, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}
