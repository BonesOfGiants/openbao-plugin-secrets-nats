package natsbackend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/common"
	userv1 "github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/claims/user/v1alpha1"
	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
)

func TestCRUDUserIssue(t *testing.T) {

	b, reqStorage := getTestBackend(t)

	t.Run("Test initial state of user issuer", func(t *testing.T) {

		path := "issue/operator/op1/account/ac1/user/us1"

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then create account issue to be able to create user issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// call read/delete/list without creating the issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("operator signing nkey ReadOperation request failed, err: %s, resp %#v", err, resp)
		}

		if resp != nil {
			t.Fatalf("expected nil resp for operator signing nkey ReadOperation resp: %#v", resp)
		}

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/acc1/user",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.Equal(t, resp.Data, map[string]any{})

	})

	t.Run("Test CRUD logic for user issuer", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var path string = "issue/operator/op1/account/ac1/user/us1"
		var request map[string]any
		var expected IssueUserData
		var current IssueUserData

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then create account issue to be able to create user issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// That will be requested
		//////////////////////////
		stm.StructToMap(&IssueUserParameters{}, &request)

		//////////////////////////
		// That will be expected - FIXED: JWT status should be false since no JWT is stored
		//////////////////////////
		expected = IssueUserData{
			Operator:       "op1",
			Account:        "ac1",
			User:           "us1",
			UseSigningKey:  "",
			ClaimsTemplate: userv1.UserClaims{},
			Status: IssueUserStatus{
				User: IssueStatus{
					Nkey: true,
					JWT:  false, // FIXED: No JWT is stored, only nkey and template
				},
			},
		}

		/////////////////////////////
		// create the issue only
		// with defaults and read it
		/////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the created issue
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Compare the expected and current
		//////////////////////////////////
		stm.MapToStruct(resp.Data, &current)
		assert.Equal(t, expected, current)

		//////////////////////////
		// That will be requested
		//////////////////////////

		issue := IssueUserParameters{
			ClaimsTemplate: userv1.UserClaims{
				User: userv1.User{
					UserPermissionLimits: userv1.UserPermissionLimits{
						Limits: userv1.Limits{
							NatsLimits: common.NatsLimits{
								Subs: 1,
							},
						},
					},
				},
			},
		}
		tmp, err := json.Marshal(issue)
		assert.Nil(t, err)
		json.Unmarshal(tmp, &request)

		//////////////////////////
		// That will be expected - FIXED: JWT status should still be false
		//////////////////////////
		expected = IssueUserData{
			Operator: "op1",
			Account:  "ac1",
			User:     "us1",
			ClaimsTemplate: userv1.UserClaims{
				User: userv1.User{
					UserPermissionLimits: userv1.UserPermissionLimits{
						Limits: userv1.Limits{
							NatsLimits: common.NatsLimits{
								Subs: 1,
							},
						},
					},
				},
			},
			Status: IssueUserStatus{
				User: IssueStatus{
					Nkey: true,
					JWT:  false, // FIXED: Still false since JWTs are generated on-demand
				},
			},
		}

		//////////////////////////////////
		// Update with the requested data
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      request,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Read the updated data back
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Compare the expected and current
		//////////////////////////////////
		stm.MapToStruct(resp.Data, &current)

		assert.Equal(t, expected, current)

		//////////////////////////////////
		// List the issues
		//////////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "issue/operator/op1/account/ac1/user",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////////////
		// Check, only one key is listed
		//////////////////////////////////
		assert.Equal(t, map[string]any{"keys": []string{"us1"}}, resp.Data)

		/////////////////////////
		// Then delete the key
		/////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// ... and try to read it
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("operator signing nkey ReadOperation request failed, err: %s, resp %#v", err, resp)
		}

		if resp != nil {
			t.Fatalf("expected nil resp for operator signing nkey ReadOperation resp: %#v", resp)
		}

		//////////////////////////
		// Then recreate the key
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// ... read the key
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// ... and delete again
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
	})

	t.Run("Test issued nkeys and creds (JWT generation on-demand)", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var path string = "issue/operator/op1/account/ac1/user/us1"
		var request map[string]any

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then create account issue to be able to create user issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// That will be requested
		//////////////////////////
		stm.StructToMap(&IssueUserParameters{}, &request)

		/////////////////////////////
		// create the issue only
		// with defaults and read it
		/////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      path,
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the created issue
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the nkey (should exist)
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// FIXED: Since JWTs are now generated on-demand,
		// trying to read a stored JWT should fail (unsupported path)
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		// This should return an "unsupported path" error
		if err != nil {
			// If we get an error, it should be "unsupported path"
			assert.Contains(t, err.Error(), "unsupported path")
		} else {
			// If no error, then response should indicate error
			assert.True(t, resp.IsError())
		}

		//////////////////////////
		// FIXED: read the creds (this should work since it generates JWT on-demand)
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// Verify creds response contains expected fields
		assert.Contains(t, resp.Data, "creds")
		assert.Contains(t, resp.Data, "operator")
		assert.Contains(t, resp.Data, "account")
		assert.Contains(t, resp.Data, "user")

		/////////////////////////
		// Then delete the issue
		/////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		/////////////////////////////
		// ... and try to read again (all should fail now)
		/////////////////////////////

		//////////////////////////
		// read the nkey (should fail)
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nkey/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("operator signing nkey ReadOperation request failed, err: %s, resp %#v", err, resp)
		}

		if resp != nil {
			t.Fatalf("expected nil resp for operator signing nkey ReadOperation resp: %#v", resp)
		}

		//////////////////////////
		// read the jwt (should fail)
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "jwt/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		// Should return "unsupported path" error
		if err != nil {
			assert.Contains(t, err.Error(), "unsupported path")
		} else {
			assert.True(t, resp.IsError())
		}

		//////////////////////////
		// read the creds (should fail since template is deleted)
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/operator/op1/account/ac1/user/us1",
			Storage:   reqStorage,
		})
		assert.Equal(t, logical.ErrUnsupportedPath, err)
		assert.True(t, resp.IsError())
	})

	t.Run("Test sys account with default-push user", func(t *testing.T) {

		/////////////////////////
		// Prepare the test data
		/////////////////////////
		var path string = fmt.Sprintf("operator/op1/account/%s/user/%s", DefaultSysAccountName, DefaultPushUser)
		var issueUserPath = "issue/" + path
		var nkeyUserPath = "nkey/" + path
		var jwtUserPath = "jwt/" + path
		var credsUserPath = "creds/" + path
		var request map[string]any

		// first create operator issue to be able to create account issue
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// then create account issue to be able to create user issue
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/" + DefaultSysAccountName,
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// That will be requested
		//////////////////////////
		stm.StructToMap(&IssueUserParameters{}, &request)

		/////////////////////////////
		// create the issue only
		// with defaults and read it
		/////////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      issueUserPath,
			Storage:   reqStorage,
			Data:      map[string]any{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the created issue
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      issueUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the nkey
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      nkeyUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// FIXED: read the jwt - should fail since JWTs are not stored
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      jwtUserPath,
			Storage:   reqStorage,
		})
		assert.Equal(t, logical.ErrUnsupportedPath, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the creds - should work since it generates JWT on-demand
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      credsUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		/////////////////////////
		// Then delete the issue
		/////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      issueUserPath,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		/////////////////////////////
		// ... and try to read again
		/////////////////////////////

		//////////////////////////
		// read the nkey
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      nkeyUserPath,
			Storage:   reqStorage,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("operator signing nkey ReadOperation request failed, err: %s, resp %#v", err, resp)
		}

		if resp != nil {
			t.Fatalf("expected nil resp for operator signing nkey ReadOperation resp: %#v", resp)
		}

		//////////////////////////
		// read the jwt
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      jwtUserPath,
			Storage:   reqStorage,
		})
		assert.Equal(t, logical.ErrUnsupportedPath, err)
		assert.False(t, resp.IsError())

		//////////////////////////
		// read the creds
		//////////////////////////
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      credsUserPath,
			Storage:   reqStorage,
		})
		assert.Equal(t, logical.ErrUnsupportedPath, err)
		assert.True(t, resp.IsError())
	})

}

// UPDATED: This test needs significant updates since JWTs are no longer stored
// The test should focus on checking that templates exist and nkeys are present
// rather than checking stored JWTs
func TestWithUserRandomizedOrder(t *testing.T) {
	type action struct {
		description string
		req         *logical.Request
	}

	operatorName := "op1"
	accountName := "acc1"
	userName := "user1"

	b, reqStorage := getTestBackend(t)
	actions := []action{
		{
			description: "create operator without sys account",
			req: &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "issue/operator/" + operatorName,
				Storage:   reqStorage,
				Data:      map[string]any{},
			},
		},
		{
			description: "create sys account",
			req: &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "issue/operator/" + operatorName + "/account/" + DefaultSysAccountName,
				Storage:   reqStorage,
				Data:      map[string]any{},
			},
		},
		{
			description: "create sys account user push-default",
			req: &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "issue/operator/" + operatorName + "/account/" + DefaultSysAccountName + "/user/" + DefaultPushUser,
				Storage:   reqStorage,
				Data:      map[string]any{},
			},
		},
		{
			description: "create account",
			req: &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "issue/operator/" + operatorName + "/account/" + accountName,
				Storage:   reqStorage,
				Data:      map[string]any{},
			},
		},
		{
			description: "create user for account",
			req: &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "issue/operator/" + operatorName + "/account/" + accountName + "/user/" + userName,
				Storage:   reqStorage,
				Data:      map[string]any{},
			},
		},
	}

	check := func(identifier string) {
		// Check operator issue, nkey and jwt
		err := listPath(b, reqStorage, "issue/operator/", map[string]any{"keys": []string{operatorName}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "jwt/operator/", map[string]any{"keys": []string{operatorName}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "nkey/operator/", map[string]any{"keys": []string{operatorName}})
		bailOutOnErr(t, identifier, err)
		// Check account issue, nkey and jwt
		err = listPath(b, reqStorage, "issue/operator/"+operatorName+"/account/", map[string]any{"keys": []string{accountName, DefaultSysAccountName}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "jwt/operator/"+operatorName+"/account/", map[string]any{"keys": []string{accountName, DefaultSysAccountName}})
		bailOutOnErr(t, identifier, err)
		err = listPath(b, reqStorage, "nkey/operator/"+operatorName+"/account/", map[string]any{"keys": []string{accountName, DefaultSysAccountName}})
		bailOutOnErr(t, identifier, err)
		// Check default push-user issue (from sys account), nkey - skip JWT since it's not stored
		err = listPath(b, reqStorage, "issue/operator/"+operatorName+"/account/"+DefaultSysAccountName+"/user/", map[string]any{"keys": []string{DefaultPushUser}})
		bailOutOnErr(t, identifier, err)
		// UPDATED: Skip JWT list check since user JWTs are not stored anymore
		err = listPath(b, reqStorage, "nkey/operator/"+operatorName+"/account/"+DefaultSysAccountName+"/user/", map[string]any{"keys": []string{DefaultPushUser}})
		bailOutOnErr(t, identifier, err)
		// Check user issue, nkey - skip JWT since it's not stored
		err = listPath(b, reqStorage, "issue/operator/"+operatorName+"/account/"+accountName+"/user/", map[string]any{"keys": []string{userName}})
		bailOutOnErr(t, identifier, err)
		// UPDATED: Skip JWT list check since user JWTs are not stored anymore
		err = listPath(b, reqStorage, "nkey/operator/"+operatorName+"/account/"+accountName+"/user/", map[string]any{"keys": []string{userName}})
		bailOutOnErr(t, identifier, err)

		// Check JWTs for validity (only for operator and accounts, not users)
		err = checkOperatorJWTForSysAccount(b, reqStorage, operatorName)
		bailOutOnErr(t, identifier, err)
		err = checkAccountJWTForOperator(b, reqStorage, operatorName, DefaultSysAccountName)
		bailOutOnErr(t, identifier, err)
		err = checkAccountJWTForOperator(b, reqStorage, operatorName, accountName)
		bailOutOnErr(t, identifier, err)
		// UPDATED: Test user credential generation instead of stored JWTs
		err = checkUserCredsGeneration(b, reqStorage, operatorName, DefaultSysAccountName, DefaultPushUser)
		bailOutOnErr(t, identifier, err)
		err = checkUserCredsGeneration(b, reqStorage, operatorName, accountName, userName)
		bailOutOnErr(t, identifier, err)
	}

	permuations := combin.Permutations(len(actions), len(actions))
	for _, permutation := range permuations {
		identifier := fmt.Sprintf("Test permuation: %+v", permutation)
		t.Run(identifier, func(t *testing.T) {
			t.Logf("Test permuation: %+v", permutation)
			for _, actionIndex := range permutation {
				action := actions[actionIndex]
				resp, err := b.HandleRequest(context.Background(), action.req)
				if resp.IsError() {
					t.Fatal(errors.New(resp.Data["error"].(string)))
				}
				assert.False(t, resp.IsError())
				bailOutOnErr(t, identifier, err)
			}
			check(identifier)
		})
	}
}

func bailOutOnErr(t *testing.T, identifier string, err error) {
	if err != nil {
		t.Errorf("%s: %+v\n", identifier, err)
	}
}

func listPath(b *NatsBackend, reqStorage logical.Storage, path string, expected map[string]any) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      path,
		Storage:   reqStorage,
		Data:      map[string]any{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error listing nkeys: %s", resp.Error().Error())
	}

	if !reflect.DeepEqual(resp.Data, expected) {
		return fmt.Errorf("path: %s, op: list, expected: %+v, got: %+v", path, expected, resp.Data)
	}
	return nil
}

func checkOperatorJWTForSysAccount(b *NatsBackend, reqStorage logical.Storage, operatorName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwt/operator/" + operatorName,
		Storage:   reqStorage,
		Data:      map[string]any{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error reading operator JWT: %s", resp.Error().Error())
	}
	var current JWTData
	stm.MapToStruct(resp.Data, &current)
	operatorClaims, err := jwt.DecodeOperatorClaims(current.JWT)
	if err != nil {
		return err
	}
	// get sys account public key
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwt/operator/" + operatorName + "/account/" + DefaultSysAccountName,
		Storage:   reqStorage,
		Data:      map[string]any{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error reading sys account JWT: %s", resp.Error().Error())
	}
	var sysAccount JWTData
	stm.MapToStruct(resp.Data, &sysAccount)
	sysAccountClaims, err := jwt.DecodeAccountClaims(sysAccount.JWT)
	if err != nil {
		return err
	}
	if operatorClaims.SystemAccount != sysAccountClaims.Subject {
		return fmt.Errorf("operator JWT does not reference sys account")
	}
	return nil
}

func checkAccountJWTForOperator(b *NatsBackend, reqStorage logical.Storage, operatorName string, accountName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwt/operator/" + operatorName,
		Storage:   reqStorage,
		Data:      map[string]any{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error reading operator JWT: %s", resp.Error().Error())
	}
	var operator JWTData
	stm.MapToStruct(resp.Data, &operator)
	operatorClaims, err := jwt.DecodeOperatorClaims(operator.JWT)
	if err != nil {
		return err
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwt/operator/" + operatorName + "/account/" + accountName,
		Storage:   reqStorage,
		Data:      map[string]any{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error reading account JWT: %s", resp.Error().Error())
	}
	var account JWTData
	stm.MapToStruct(resp.Data, &account)
	accountClaims, err := jwt.DecodeAccountClaims(account.JWT)
	if err != nil {
		return err
	}
	if accountClaims.Issuer != operatorClaims.Subject {
		return fmt.Errorf("account JWT does not reference operator")
	}
	return nil
}

// NEW: Function to test user credential generation instead of stored JWTs
func checkUserCredsGeneration(b *NatsBackend, reqStorage logical.Storage, operatorName string, accountName string, userName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/operator/" + operatorName + "/account/" + accountName + "/user/" + userName,
		Storage:   reqStorage,
		Data:      map[string]any{},
	})
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("error generating user creds: %s", resp.Error().Error())
	}

	// Verify that creds response contains expected fields
	if _, exists := resp.Data["creds"]; !exists {
		return fmt.Errorf("creds field missing from response")
	}
	if _, exists := resp.Data["operator"]; !exists {
		return fmt.Errorf("operator field missing from response")
	}
	if _, exists := resp.Data["account"]; !exists {
		return fmt.Errorf("account field missing from response")
	}
	if _, exists := resp.Data["user"]; !exists {
		return fmt.Errorf("user field missing from response")
	}

	// Verify the creds content is not empty
	creds, ok := resp.Data["creds"].(string)
	if !ok || creds == "" {
		return fmt.Errorf("creds field is empty or not a string")
	}

	// Basic validation that it looks like a creds file
	if !strings.Contains(creds, "-----BEGIN NATS USER JWT-----") {
		return fmt.Errorf("creds does not contain expected JWT header")
	}
	if !strings.Contains(creds, "-----BEGIN USER NKEY SEED-----") {
		return fmt.Errorf("creds does not contain expected NKEY seed header")
	}

	return nil
}
