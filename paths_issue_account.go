package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/accountsync"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"

	v1alpha1 "github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/account/v1alpha1"
)

type IssueAccountStorage struct {
	Operator      string                 `json:"operator"`
	Account       string                 `json:"account"`
	UseSigningKey string                 `json:"useSigningKey"`
	Claims        v1alpha1.AccountClaims `json:"claims"`
	Status        IssueAccountStatus     `json:"status"`
}

// IssueAccountParameters is the user facing interface for configuring an account issue.
// Using pascal case on purpose.
// +k8s:deepcopy-gen=true
type IssueAccountParameters struct {
	Operator      string                 `json:"operator"`
	Account       string                 `json:"account"`
	UseSigningKey string                 `json:"useSigningKey,omitempty"`
	Claims        v1alpha1.AccountClaims `json:"claims"`
}

type IssueAccountData struct {
	Operator      string                 `json:"operator"`
	Account       string                 `json:"account"`
	UseSigningKey string                 `json:"useSigningKey"`
	Claims        v1alpha1.AccountClaims `json:"claims"`
	Status        IssueAccountStatus     `json:"status"`
}

type IssueAccountStatus struct {
	Account       IssueStatus         `json:"account"`
	AccountServer AccountServerStatus `json:"accountServer"`
}

type AccountServerStatus struct {
	Synced   bool  `json:"synced"`
	LastSync int64 `json:"lastSync"`
}

func pathAccountIssue(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "$",
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
				"useSigningKey": {
					Type:        framework.TypeString,
					Description: "Explicitly specified operator signing key to sign the account",
					Required:    false,
				},
				"claims": {
					Type:        framework.TypeMap,
					Description: "Account claims (jwt.AccountClaims from https://github.com/nats-io/jwt/tree/main/v2)",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathAccountIssueExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountIssue,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddAccountIssue,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAccountIssue,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteAccountIssue,
				},
			},
			HelpSynopsis:    `Manages account Issue's.`,
			HelpDescription: ``,
		},
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
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
					Callback: b.pathListAccountIssue,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddAccountIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueAccountParameters{}
	json.Unmarshal(jsonString, &params)
	err = addAccountIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("%s: %s", AddingIssueFailedError, err.Error())), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadAccountIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	issue, err := readAccountIssue(ctx, req.Storage, IssueAccountParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
	})
	if err != nil || issue == nil {
		return nil, err
	}

	return createResponseIssueAccountData(issue)
}

func (b *NatsBackend) pathAccountIssueExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	issue, err := readAccountIssue(ctx, req.Storage, IssueAccountParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
	})
	if err != nil {
		return false, err
	}

	return issue != nil, nil
}

func (b *NatsBackend) pathListAccountIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	operator := data.Get("operator").(string)
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	path := getAccountIssuePath(operator, "")
	entries, err := req.Storage.ListPage(ctx, path, after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(filterSubkeys(entries)), nil
}

func (b *NatsBackend) pathDeleteAccountIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// delete issue and all related nkeys and jwt
	err := deleteAccountIssue(ctx, req.Storage, IssueAccountParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
	})
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func addAccountIssue(ctx context.Context, storage logical.Storage, params IssueAccountParameters) error {
	log.Info().
		Str("operator", params.Operator).Str("account", params.Account).
		Msgf("issue account")

	// store issue
	issue, err := storeAccountIssue(ctx, storage, params)
	if err != nil {
		return err
	}

	return refreshAccount(ctx, storage, issue)
}

func refreshAccount(ctx context.Context, storage logical.Storage, issue *IssueAccountStorage) error {
	// create nkey and signing nkeys
	err := issueAccountNKeys(ctx, storage, *issue)
	if err != nil {
		return err
	}

	// create jwt
	err = issueAccountJWT(ctx, storage, *issue)
	if err != nil {
		return err
	}

	s, err := getAccountSync(ctx, storage, issue.Operator)
	if err != nil {
		log.Error().
			Str("operator", issue.Operator).
			Str("account", issue.Account).
			Err(err).
			Msg("failed to sync account")
	} else if s != nil {
		defer s.CloseConnection()
		err = syncAccountUpdate(ctx, storage, s, issue)
		if err != nil {
			log.Warn().
				Str("operator", issue.Operator).
				Str("account", issue.Account).
				Err(err).
				Msg("failed to sync account")
		}
	}

	err = updateAccountStatus(ctx, storage, issue)
	if err != nil {
		return err
	}

	_, err = storeAccountIssueUpdate(ctx, storage, issue)
	if err != nil {
		return err
	}

	return nil
}

func readAccountIssue(ctx context.Context, storage logical.Storage, params IssueAccountParameters) (*IssueAccountStorage, error) {
	path := getAccountIssuePath(params.Operator, params.Account)
	return getFromStorage[IssueAccountStorage](ctx, storage, path)
}

func deleteAccountIssue(ctx context.Context, storage logical.Storage, params IssueAccountParameters) error {
	// get stored signing keys
	issue, err := readAccountIssue(ctx, storage, params)
	if err != nil {
		return err
	}
	if issue == nil {
		// nothing to delete
		return nil
	}

	s, err := getAccountSync(ctx, storage, issue.Operator)
	if err != nil {
		log.Error().
			Str("operator", issue.Operator).
			Str("account", issue.Account).
			Err(err).
			Msg("failed to sync account")
	} else if s != nil {
		defer s.CloseConnection()
		err = syncAccountDelete(ctx, storage, s, issue)
		if err != nil {
			return err
		}
	}

	// delete account nkey
	nkey := NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	}
	err = deleteAccountNkey(ctx, storage, nkey)
	if err != nil {
		return err
	}

	// delete account siginig nkeys
	for _, signingKey := range issue.Claims.SigningKeys {
		nkey := NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			Signing:  signingKey,
		}
		err := deleteAccountSigningNkey(ctx, storage, nkey)
		if err != nil {
			return err
		}
	}

	// delete account jwt
	jwt := JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	}
	err = deleteAccountJWT(ctx, storage, jwt)
	if err != nil {
		return err
	}

	// delete account issue
	path := getAccountIssuePath(issue.Operator, issue.Account)
	return deleteFromStorage(ctx, storage, path)
}

func storeAccountIssueUpdate(ctx context.Context, storage logical.Storage, issue *IssueAccountStorage) (*IssueAccountStorage, error) {
	path := getAccountIssuePath(issue.Operator, issue.Account)

	err := storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func storeAccountIssue(ctx context.Context, storage logical.Storage, params IssueAccountParameters) (*IssueAccountStorage, error) {
	path := getAccountIssuePath(params.Operator, params.Account)

	issue, err := getFromStorage[IssueAccountStorage](ctx, storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		issue = &IssueAccountStorage{}
	} else {
		// diff current and incomming signing keys
		// delete removed signing keys
		for _, signingKey := range issue.Claims.SigningKeys {
			if !slices.Contains(params.Claims.SigningKeys, signingKey) {
				p := NkeyParameters{
					Operator: params.Operator,
					Account:  params.Account,
					Signing:  signingKey,
				}
				err := deleteAccountSigningNkey(ctx, storage, p)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	issue.Claims = params.Claims
	issue.Operator = params.Operator
	issue.Account = params.Account
	issue.UseSigningKey = params.UseSigningKey
	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func issueAccountNKeys(ctx context.Context, storage logical.Storage, issue IssueAccountStorage) error {

	var refreshTheOperator bool
	var refreshUsers bool

	// issue account nkey
	p := NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	}
	stored, err := readAccountNkey(ctx, storage, p)
	if err != nil {
		return err
	}
	if stored == nil {
		err := addAccountNkey(ctx, storage, p)
		if err != nil {
			return err
		}
		if issue.Account == DefaultSysAccountName {
			refreshTheOperator = true
		}
		refreshUsers = true
	}

	// issue account siginig nkeys
	for _, signingKey := range issue.Claims.SigningKeys {
		p := NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			Signing:  signingKey,
		}
		stored, err := readAccountSigningNkey(ctx, storage, p)
		if err != nil {
			return err
		}
		if stored == nil {
			err := addAccountSigningNkey(ctx, storage, p)
			if err != nil {
				return err
			}
			refreshUsers = true
		}
	}

	if refreshTheOperator {
		// force update of operator
		// so he gets updates from sys account
		op, err := readOperatorIssue(ctx, storage, IssueOperatorParameters{
			Operator: issue.Operator,
		})
		if err != nil {
			return err
		} else if op == nil {
			log.Warn().Str("operator", issue.Operator).Str("account", issue.Account).Msg("cannot refresh operator: operator issue does not exist")
			return nil
		}

		err = refreshOperator(ctx, storage, op)
		if err != nil {
			return err
		}
	}

	if refreshUsers {
		// force update of all existing users
		// so they can use the new account nkey to sign their jwt
		log.Info().Str("operator", issue.Operator).Str("account", issue.Account).Msg("managed nkeys modified, all users will be updated")
		err = updateUserIssues(ctx, storage, issue)
		if err != nil {
			log.Err(err).Str("operator", issue.Operator).Msg("failed to update users")
			return err
		}
	}

	log.Info().
		Str("operator", issue.Operator).Str("account", issue.Account).Msgf("nkey assigned")

	return nil
}

func issueAccountJWT(ctx context.Context, storage logical.Storage, issue IssueAccountStorage) error {
	// use either operator nkey or signing nkey to
	// sign jwt and add issuer claim
	useSigningKey := issue.UseSigningKey
	var seed []byte
	if useSigningKey == "" {
		data, err := readOperatorNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
		})
		if err != nil {
			return fmt.Errorf("could not read operator nkey: %s", err)
		}
		if data == nil {
			log.Error().
				Str("operator", issue.Operator).Str("account", issue.Account).
				Msgf("operator nkey does not exist: %s - Cannot create JWT.", issue.Operator)
			return fmt.Errorf("operator nkey does not exist: %s - Cannot create JWT", issue.Operator)
		}
		seed = data.Seed
	} else {
		data, err := readOperatorSigningNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Signing:  useSigningKey,
		})
		if err != nil {
			return fmt.Errorf("could not read signing nkey: %s", err)
		}
		if data == nil {
			log.Error().
				Str("operator", issue.Operator).Str("account", issue.Account).
				Msgf("operator signing nkey does not exist: %s - Cannot create JWT.", useSigningKey)
			return fmt.Errorf("operator signing nkey does not exist: %s - Cannot create JWT", useSigningKey)
		}
		seed = data.Seed
	}
	signingKeyPair, err := nkeys.FromSeed(seed)
	if err != nil {
		return err
	}
	signingPublicKey, err := signingKeyPair.PublicKey()
	if err != nil {
		return err
	}

	// receive account nkey puplic key
	// to add subject
	data, err := readAccountNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return fmt.Errorf("could not read account nkey: %s", err)
	}
	if data == nil {
		return fmt.Errorf("account nkey does not exist")
	}
	accountKeyPair, err := nkeys.FromSeed(data.Seed)
	if err != nil {
		return err
	}
	accountPublicKey, err := accountKeyPair.PublicKey()
	if err != nil {
		return err
	}

	// receive public keys of signing keys
	var signingPublicKeys []string
	for _, signingKey := range issue.Claims.SigningKeys {
		data, err := readAccountSigningNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			Signing:  signingKey,
		})
		if err != nil {
			return fmt.Errorf("could not read signing key")
		}
		if data == nil {
			log.Warn().
				Str("operator", issue.Operator).Str("account", issue.Account).
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

	// add any externally defined imports to the claim
	imports, err := readAllAccountImportIssues(ctx, storage, IssueAccountImportParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return err
	}

	if len(imports) > 0 {
		if issue.Claims.Imports == nil {
			issue.Claims.Imports = []v1alpha1.Import{}
		}
	}

	for _, imp := range imports {
		issue.Claims.Imports = append(issue.Claims.Imports, imp.Imports...)
	}

	// add any externally defined revocations to the claim
	revocations, err := readAllAccountRevocationIssues(ctx, storage, IssueAccountRevocationParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return err
	}

	if len(revocations) > 0 {
		if issue.Claims.Revocations == nil {
			issue.Claims.Revocations = make(map[string]int64)
		}
	}

	for _, revocation := range revocations {
		issue.Claims.Revocations[revocation.Subject] = revocation.CreationTime
	}

	issue.Claims.ClaimsData.Subject = accountPublicKey
	issue.Claims.ClaimsData.Issuer = signingPublicKey
	issue.Claims.ClaimsData.IssuedAt = time.Now().Unix()
	// TODO: dont know how to handle scopes of signing keys
	issue.Claims.Account.SigningKeys = signingPublicKeys
	natsJwt, err := v1alpha1.Convert(&issue.Claims)
	if err != nil {
		return fmt.Errorf("could not convert claims to nats jwt: %s", err)
	}
	token, err := natsJwt.Encode(signingKeyPair)
	if err != nil {
		return fmt.Errorf("could not encode account jwt: %s", err)
	}

	// store account jwt
	err = addAccountJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		JWTStorage: JWTStorage{
			JWT: token,
		},
	})
	if err != nil {
		return err
	}
	log.Info().
		Str("operator", issue.Operator).Str("account", issue.Account).
		Msgf("jwt nkey assigned")
	return nil
}

func updateUserIssues(ctx context.Context, storage logical.Storage, issue IssueAccountStorage) error {

	path := getUserIssuePath(issue.Operator, issue.Account, "")
	users, err := storage.List(ctx, path)
	if err != nil {
		return err
	}

	for _, user := range filterSubkeys(users) {
		user, err := readUserIssue(ctx, storage, IssueUserParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			User:     user,
		})
		if err != nil {
			return err
		}
		if user == nil {
			return err
		}
		err = refreshUser(ctx, storage, user)
		if err != nil {
			return err
		}
	}
	return nil
}

func syncAccountUpdate(
	ctx context.Context,
	storage logical.Storage,
	accountSync *accountsync.AccountSync,
	issue *IssueAccountStorage,
) error {
	// read account jwt
	accJWT, err := readAccountJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return err
	} else if accJWT == nil {
		return fmt.Errorf("unable to sync, account does not exist")
	}

	err = accountSync.PushAccount(issue.Account, []byte(accJWT.JWT))
	if err != nil {
		return err
	}

	// update issue status
	issue.Status.AccountServer.Synced = true
	issue.Status.AccountServer.LastSync = time.Now().Unix()

	return nil
}

func syncAccountDelete(
	ctx context.Context,
	storage logical.Storage,
	accountSync *accountsync.AccountSync,
	issue *IssueAccountStorage,
) error {
	wrapErr := func(err error) error {
		if accountSync.IgnoreSyncErrorsOnDelete {
			log.Debug().
				Err(err).
				Msg("swallowing sync error due to ignoreSyncErrorsOnDelete")
			return nil
		} else {
			return err
		}
	}

	operatorNkey, err := readOperatorNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
	})
	if err != nil {
		return wrapErr(err)
	} else if operatorNkey == nil {
		return wrapErr(fmt.Errorf("unable to sync, operator nkey does not exist"))
	}

	kp, err := toNkeyData(operatorNkey)
	if err != nil {
		return wrapErr(err)
	}
	operatorKeypair, err := nkeys.FromSeed([]byte(kp.Seed))
	if err != nil {
		return wrapErr(err)
	}

	// read account jwt
	accNkey, err := readAccountNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return wrapErr(err)
	} else if accNkey == nil {
		return wrapErr(fmt.Errorf("unable to sync, account nkey does not exist"))
	}
	kp, err = toNkeyData(accNkey)
	if err != nil {
		return wrapErr(err)
	}
	accountKeyPair, err := nkeys.FromSeed([]byte(kp.Seed))
	if err != nil {
		return wrapErr(err)
	}
	accountPubKey, err := accountKeyPair.PublicKey()
	if err != nil {
		return wrapErr(err)
	}
	_, err = accountSync.DeleteAccounts([]string{accountPubKey}, operatorKeypair)
	if err != nil {
		return wrapErr(err)
	}

	// update issue status
	issue.Status.AccountServer.Synced = true
	issue.Status.AccountServer.LastSync = time.Now().Unix()

	return nil
}

func getAccountIssuePath(operator string, account string) string {
	return issueOperatorPrefix + operator + "/account/" + account
}

func createResponseIssueAccountData(issue *IssueAccountStorage) (*logical.Response, error) {
	data := &IssueAccountData{
		Operator:      issue.Operator,
		Account:       issue.Account,
		UseSigningKey: issue.UseSigningKey,
		Claims:        issue.Claims,
		Status:        issue.Status,
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

func updateAccountStatus(ctx context.Context, storage logical.Storage, issue *IssueAccountStorage) error {
	// account status
	nkey, err := readAccountNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return err
	}

	if nkey == nil {
		issue.Status.Account.Nkey = false
	} else {
		issue.Status.Account.Nkey = true
	}

	jwt, err := readAccountJWT(ctx, storage, JWTParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})

	if err != nil {
		return err
	}

	if jwt == nil {
		issue.Status.Account.JWT = false
	} else {
		issue.Status.Account.JWT = true
	}

	return nil
}

func IsNatsUrl(url string) bool {
	url = strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(url, "nats://") || strings.HasPrefix(url, ",nats://")
}

func addUserToRevocationList(ctx context.Context, storage logical.Storage, account *IssueAccountStorage, user *IssueUserStorage) error {
	// get user public key
	userNkey, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: account.Operator,
		Account:  account.Account,
		User:     user.User,
	})
	if err != nil {
		return err
	} else if userNkey == nil {
		return nil
	}
	kp, err := toNkeyData(userNkey)
	if err != nil {
		return err
	}
	userKeypair, err := nkeys.FromSeed([]byte(kp.Seed))
	if err != nil {
		return err
	}
	userPubKey, err := userKeypair.PublicKey()
	if err != nil {
		return err
	}
	// add user to revocation list and store
	if account.Claims.Revocations == nil {
		account.Claims.Revocations = map[string]int64{}
	}
	account.Claims.Revocations[userPubKey] = time.Now().Unix()
	path := getAccountIssuePath(account.Operator, account.Account)
	err = storeInStorage(ctx, storage, path, &account)
	if err != nil {
		return err
	}
	// reissue account jwt and push by refresing account
	return refreshAccount(ctx, storage, account)
}
