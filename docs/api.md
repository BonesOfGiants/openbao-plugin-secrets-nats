# NATS secrets engine (API) <!-- omit in toc -->

This is the API documentation for the OpenBao NATS
secrets engine. For general information about the usage and operation of
the NATS JWT secrets engine, please see the main [NATS JWT secrets documentation](./index.md).

This documentation assumes the NATS JWT secrets engine is enabled at the `/nats` path
in OpenBao. Since it is possible to mount secrets engines at any path, please
update your API calls accordingly.

<details>
<summary>Table of Contents</summary>

- [Quick Reference](#quick-reference)
  - [Operator management](#operator-management)
  - [Account management](#account-management)
  - [User management](#user-management)
  - [Utilities](#utilities)
- [Create/Update operator](#createupdate-operator)
  - [Request parameters](#request-parameters)
  - [Sample payload](#sample-payload)
  - [Sample request](#sample-request)
- [Read operator](#read-operator)
  - [Request parameters](#request-parameters-1)
  - [Sample request](#sample-request-1)
  - [Response parameters](#response-parameters)
  - [Sample response](#sample-response)
- [List operators](#list-operators)
  - [Request parameters](#request-parameters-2)
  - [Sample request](#sample-request-2)
  - [Sample response](#sample-response-1)
- [Delete operator](#delete-operator)
  - [Request parameters](#request-parameters-3)
  - [Sample request](#sample-request-3)
- [Create/Update sync configuration](#createupdate-sync-configuration)
  - [Request parameters](#request-parameters-4)
  - [Sample payload](#sample-payload-1)
  - [Sample request](#sample-request-4)
- [Read sync configuration](#read-sync-configuration)
  - [Request parameters](#request-parameters-5)
  - [Sample request](#sample-request-5)
  - [Response parameters](#response-parameters-1)
    - [Status parameters](#status-parameters)
  - [Sample response](#sample-response-2)
- [Delete sync configuration](#delete-sync-configuration)
  - [Request parameters](#request-parameters-6)
  - [Sample request](#sample-request-6)
- [Read operator key](#read-operator-key)
  - [Request parameters](#request-parameters-7)
  - [Sample request](#sample-request-7)
  - [Response parameters](#response-parameters-2)
  - [Sample response](#sample-response-3)
- [Read operator JWT](#read-operator-jwt)
  - [Request parameters](#request-parameters-8)
  - [Sample request](#sample-request-8)
  - [Response parameters](#response-parameters-3)
  - [Sample response](#sample-response-4)
- [Create operator signing key](#create-operator-signing-key)
  - [Request parameters](#request-parameters-9)
  - [Sample request](#sample-request-9)
- [Read operator signing key](#read-operator-signing-key)
  - [Request parameters](#request-parameters-10)
  - [Sample request](#sample-request-10)
  - [Response parameters](#response-parameters-4)
  - [Sample response](#sample-response-5)
- [List operator signing keys](#list-operator-signing-keys)
  - [Request parameters](#request-parameters-11)
  - [Sample request](#sample-request-11)
  - [Sample response](#sample-response-6)
- [Delete operator signing key](#delete-operator-signing-key)
  - [Request parameters](#request-parameters-12)
  - [Sample request](#sample-request-12)
- [Create/Update account](#createupdate-account)
  - [Request parameters](#request-parameters-13)
  - [Sample payload](#sample-payload-2)
  - [Sample request](#sample-request-13)
- [Read account](#read-account)
  - [Request parameters](#request-parameters-14)
  - [Sample request](#sample-request-14)
  - [Response parameters](#response-parameters-5)
    - [Status parameters](#status-parameters-1)
    - [Sync status parameters](#sync-status-parameters)
  - [Sample response](#sample-response-7)
- [List accounts](#list-accounts)
  - [Request parameters](#request-parameters-15)
  - [Sample request](#sample-request-15)
  - [Sample response](#sample-response-8)
- [Delete account](#delete-account)
  - [Sample request](#sample-request-16)
  - [Request parameters](#request-parameters-16)
- [Create/Update account import](#createupdate-account-import)
  - [Request parameters](#request-parameters-17)
    - [Import parameters](#import-parameters)
  - [Sample payload](#sample-payload-3)
  - [Sample request](#sample-request-17)
- [Read account import](#read-account-import)
  - [Request parameters](#request-parameters-18)
  - [Sample request](#sample-request-18)
  - [Response parameters](#response-parameters-6)
  - [Sample response](#sample-response-9)
- [List account imports](#list-account-imports)
  - [Request parameters](#request-parameters-19)
  - [Sample request](#sample-request-19)
  - [Sample response](#sample-response-10)
- [Read account key](#read-account-key)
  - [Request parameters](#request-parameters-20)
  - [Sample request](#sample-request-20)
  - [Response parameters](#response-parameters-7)
  - [Sample response](#sample-response-11)
- [Read account JWT](#read-account-jwt)
  - [Request parameters](#request-parameters-21)
  - [Sample request](#sample-request-21)
  - [Response parameters](#response-parameters-8)
  - [Sample response](#sample-response-12)
- [Create/Update account signing key](#createupdate-account-signing-key)
  - [Request parameters](#request-parameters-22)
  - [Sample request](#sample-request-22)
- [List account signing keys](#list-account-signing-keys)
  - [Request parameters](#request-parameters-23)
  - [Sample request](#sample-request-23)
  - [Sample response](#sample-response-13)
- [Read account signing key](#read-account-signing-key)
  - [Request parameters](#request-parameters-24)
  - [Sample request](#sample-request-24)
  - [Response parameters](#response-parameters-9)
  - [Sample response](#sample-response-14)
- [Delete account signing key](#delete-account-signing-key)
  - [Request parameters](#request-parameters-25)
  - [Sample request](#sample-request-25)
- [Create/Update user](#createupdate-user)
  - [Request parameters](#request-parameters-26)
  - [Sample payload](#sample-payload-4)
  - [Sample request](#sample-request-26)
- [List users](#list-users)
  - [Request parameters](#request-parameters-27)
  - [Sample request](#sample-request-27)
  - [Sample response](#sample-response-15)
- [Read user](#read-user)
  - [Request parameters](#request-parameters-28)
  - [Sample request](#sample-request-28)
  - [Response parameters](#response-parameters-10)
  - [Sample response](#sample-response-16)
- [Delete user](#delete-user)
  - [Request parameters](#request-parameters-29)
  - [Sample request](#sample-request-29)
- [Read user key](#read-user-key)
  - [Request parameters](#request-parameters-30)
  - [Sample request](#sample-request-30)
  - [Response parameters](#response-parameters-11)
  - [Sample response](#sample-response-17)
- [Create/Update ephemeral user](#createupdate-ephemeral-user)
  - [Request parameters](#request-parameters-31)
  - [Sample payload](#sample-payload-5)
  - [Sample request](#sample-request-31)
- [Read ephemeral user](#read-ephemeral-user)
  - [Request parameters](#request-parameters-32)
  - [Sample request](#sample-request-32)
  - [Response parameters](#response-parameters-12)
  - [Sample response](#sample-response-18)
- [Delete ephemeral user](#delete-ephemeral-user)
  - [Request parameters](#request-parameters-33)
  - [Sample request](#sample-request-33)
- [Generate user credentials](#generate-user-credentials)
  - [Request parameters](#request-parameters-34)
  - [Sample request](#sample-request-34)
  - [Response parameters](#response-parameters-13)
  - [Sample response](#sample-response-19)
  - [Request parameters](#request-parameters-35)
- [Generate ephemeral user credentials](#generate-ephemeral-user-credentials)
  - [Request parameters](#request-parameters-36)
  - [Sample request](#sample-request-35)
  - [Response parameters](#response-parameters-14)
  - [Sample response](#sample-response-20)
- [Create/Update a revocation](#createupdate-a-revocation)
  - [Request parameters](#request-parameters-37)
  - [Sample payload](#sample-payload-6)
  - [Sample request](#sample-request-36)
- [Read revocation](#read-revocation)
  - [Request parameters](#request-parameters-38)
  - [Sample request](#sample-request-37)
  - [Response parameters](#response-parameters-15)
  - [Sample response](#sample-response-21)
- [List revocations](#list-revocations)
  - [Request parameters](#request-parameters-39)
  - [Sample request](#sample-request-38)
  - [Sample response](#sample-response-22)
- [Delete revocation](#delete-revocation)
  - [Request parameters](#request-parameters-40)
  - [Sample request](#sample-request-39)
- [Rotate an operator identity key](#rotate-an-operator-identity-key)
  - [Request parameters](#request-parameters-41)
  - [Sample request](#sample-request-40)
- [Rotate an operator signing key](#rotate-an-operator-signing-key)
  - [Request parameters](#request-parameters-42)
  - [Sample request](#sample-request-41)
- [Rotate an account identity key](#rotate-an-account-identity-key)
  - [Request parameters](#request-parameters-43)
  - [Sample request](#sample-request-42)
- [Rotate an account signing key](#rotate-an-account-signing-key)
  - [Request parameters](#request-parameters-44)
  - [Sample request](#sample-request-43)
- [Rotate a user key](#rotate-a-user-key)
  - [Request parameters](#request-parameters-45)
  - [Sample payload](#sample-payload-7)
  - [Sample request](#sample-request-44)
- [Generate server config](#generate-server-config)
  - [Request parameters](#request-parameters-46)
  - [Sample request](#sample-request-45)
  - [Sample response](#sample-response-23)

</details>

## Quick Reference

### Operator management

| Path                                                                    | Purpose                      |
| :---------------------------------------------------------------------- | ---------------------------- |
| [`/nats/operators`](#list-operators)                                    | List operators               |
| [`/nats/operators/:op`](#createupdate-operator)                         | Manage operators             |
| [`/nats/sync-config/:op`](#createupdate-sync-config)                    | Configure account sync       |
| [`/nats/operator-keys/:op`](#read-operator-key)                         | Read operator id keys        |
| [`/nats/operator-jwts/:op`](#read-operator-jwt)                         | Read operator jwts           |
| [`/nats/operator-signing-keys/:op`](#list-operator-signing-keys)        | List operator signing keys   |
| [`/nats/operator-signing-keys/:op/:name`](#create-operator-signing-key) | Manage operator signing keys |

### Account management

| Path                                                                             | Purpose                     |
| :------------------------------------------------------------------------------- | --------------------------- |
| [`/nats/accounts/:op`](#list-accounts)                                           | List accounts               |
| [`/nats/accounts/:op/:acc`](#createupdate-account-configuration)                 | Manage accounts             |
| [`/nats/account-signing-keys/:op/:acc`](#list-account-signing-keys)              | List account signing keys   |
| [`/nats/account-signing-keys/:op/:acc/:name`](#createupdate-account-signing-key) | Manage account signing keys |
| [`/nats/account-imports/:op/:acc`](#list-account-imports)                        | List imports                |
| [`/nats/account-imports/:op/:acc/:name`](#createupdate-account-import)           | Manage account imports      |
| [`/nats/revocations/:op/:acc`](#list-revocations)                                | List revocations            |
| [`/nats/revocations/:op/:acc/:sub`](#create-a-revocation)                        | Manage user revocations     |
| [`/nats/account-keys/:op/:acc`](#read-account-key)                               | Read account id keys        |
| [`/nats/account-jwts/:op/:acc`](#read-account-jwt)                               | Read account jwts           |

### User management

| Path                                                                                    | Purpose                       |
| :-------------------------------------------------------------------------------------- | ----------------------------- |
| [`/nats/users/:op/:acc`](#list-users)                                                   | List users                    |
| [`/nats/users/:op/:acc/:user`](#createupdate-user-configuration)                        | Manage users                  |
| [`/nats/ephemeral-users/:op/:acc/:user`](#createupdate-ephemeral-user-configuration)    | Manage ephemeral users        |
| [`/nats/user-keys/:op/:acc/:user`](#read-user-key)                                      | Read user id keys             |
| [`/nats/creds/:op/:acc/:user`](#generate-user-credentials)                              | Generate user creds           |
| [`/nats/ephemeral-creds/:op/:acc/:user/:session`](#generate-ephemeral-user-credentials) | Generate ephemeral user creds |

### Utilities

| Path                                                                                | Purpose                     |
| :---------------------------------------------------------------------------------- | --------------------------- |
| [`/nats/rotate-operator/:op`](#rotate-an-operator-identity-key)                     | Rotate operator key         |
| [`/nats/rotate-operator-signing-key/:op/:name`](#rotate-an-operator-signing-key)    | Rotate operator signing key |
| [`/nats/rotate-account/:op/:acc`](#rotate-an-account-identity-key)                  | Rotate account key          |
| [`/nats/rotate-account-signing-key/:op/:acc/:name`](#rotate-an-account-signing-key) | Rotate account signing key  |
| [`/nats/rotate-user/:op/:acc/:user`](#rotate-a-user-key)                            | Rotate user key             |
| [`/nats/generate-server-config/:op`](#generate-server-config)                       | Generate NATS server config |

## Create/Update operator

This endpoint creates or updates an operator.

> [!WARNING] 
> Modifying an operator's claims will reissue the operator JWT.
> For the new claims to take effect, the operator JWT must be updated on 
> all NATS server configs using this operator. 
> Account and user JWTs are not affected by operator JWT reissues.

> [!NOTE]
> Modifying an operator's claims will **not** suspend the active sync configuration, as
> any modifications to the operator's claims don't affect how accounts managed by OpenBao
> are authorized.

| Method | Path                        |
| :----- | :-------------------------- |
| `POST` | `/nats/operators/:operator` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `create_system_account` `(bool: true)` - Whether to create a managed system account for this operator.
- `system_account_name` `(string: "SYS")` - The name of the account to use with this operator.
  If `create_system_account` is true, a managed account with this name will be created. 
  If the named account already exists as a non-managed account, the request will fail.
  If `create_system_account` is false and the named account does not exist, 
  this field is ignored and the operator JWT will not specify a system account.
- `default_signing_key` `(string: "")` - Specify which operator signing key to use by default when signing account JWTs. 
  By setting this field, accounts under this operator will be unable to be signed using the operator identity key. 
  If empty, not set, or if the specified signing key does not exist, accounts will be signed using the operator's identity key. 
  This field may be overridden by the `accounts` `signing_key` parameter.
- `claims` `(map: nil)` - Override default claims in the JWT issued for this operator. 
  See [nats-io/jwt](https://pkg.go.dev/github.com/nats-io/jwt/v2#OperatorClaims) for available fields. See [the guide](/docs/index.md#operator-claims) for details and an example of all available fields.

### Sample payload

```json
{
    "create_system_account": true,
    "system_account_name": "SYS",
    "claims": {
        "nats": {
            "tags": ["openbao"]
        }
    }
}
```

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/nats/operators/dev-cluster
```

## Read operator

This endpoint returns the operator definition.

| Method | Path                        |
| :----- | :-------------------------- |
| `GET`  | `/nats/operators/:operator` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    http://127.0.0.1:8200/v1/nats/operators/dev-cluster
```

### Response parameters

- `create_system_account` `(bool)` - Whether a managed system account has been created for this operator.
- `system_account_name` `(string)` - The name of account designated as the system account for this operator.
- `default_signing_key` `(string: <optional>)` - The default signing key used when signing account JWTs.
- `claims` `(map: <optional>)` - Default claims used in the JWT issued for this operator.

### Sample response

```json
{
    "data": {
        "create_system_account": true,
        "system_account_name": "SYS",
        "claims": {
            "nats": {
                "tags": ["openbao"]
            }
        }
    }
}
```

## List operators

List all of the operators that are configured.

| Method | Path                        |
| :----- | :-------------------------- |
| `LIST` | `/nats/operators`           |
| `GET`  | `/nats/operators?list=true` |

For convenience, the following paths are aliases that also work to list operators:

| Path                  |
| :-------------------- |
| `/nats/operator-keys` |
| `/nats/operator-jwts` |

### Request parameters

- `after` `(string: "")` - Optional entry to begin listing after for pagination; not required to exist.
- `limit` `(int: 0)` - Optional number of entries to return; defaults to all entries.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request LIST \
    http://127.0.0.1:8200/v1/nats/operators
```

### Sample response

```json
{
    "data": {
        "keys": ["dev-cluster", "prod-cluster"]
    }
}
```

## Delete operator

This endpoint deletes an operator definition.

> [!WARNING]
> Deleting an operator will also delete all of the objects under the operator:
> - sync config
> - all keys and jwts
> - account configurations
> - account imports
> - account revocations
> - users and ephemeral users

| Method   | Path                        |
| :------- | :-------------------------- |
| `DELETE` | `/nats/operators/:operator` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request DELETE
    http://127.0.0.1:8200/v1/nats/operators/dev-cluster
```

## Create/Update sync configuration

This endpoint configures sync behavior for an operator. 

> [!NOTE]
> This system of syncing account changes is separate from the concept of 
> [Managed Operators](https://docs.nats.io/using-nats/nats-tools/nsc/managed)
> in nsc. The servers configured here are **not** added to the operator JWT under `operator_service_urls`.

| Method | Path                          |
| :----- | :---------------------------- |
| `POST` | `/nats/sync-config/:operator` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `servers` `(array: <required>)` - A list of NATS servers to connect to.
- `suspend` `(bool: false)` - Whether to pause sync operations for this operator.
- `connect_timeout` `(string: "")` - Connection timeout for the NATS connection, 
  specified in seconds or as a Go duration format string, e.g. `"1h"`.
  If not set or set to 0, the default NATS value will be used.
- `max_reconnects` `(int: 0)` - Maximum reconnects for the NATS connection.
  If not set or set to 0, the default NATS value will be used.
- `reconnect_wait` `(string: "")` - Reconnect wait for the NATS connection,
  specified in seconds or as a Go duration format string, e.g. `"1h"`.
  If not set or set to 0, the default NATS value will be used.
- `sync_user_name` `(string: "openbao")` - The name given to the ephemeral user used for sync operations.
- `ignore_sync_errors_on_delete` `(bool: false)` - Whether to abort account deletions if unable to sync.

### Sample payload

```json
{
    "servers": ["nats://example.com:4222"],
    "connect_timeout": "30s",
    "max_reconnects": 5,
}
```

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/nats/sync-config/dev-cluster
```

## Read sync configuration

This endpoint reads a sync configuration.

The configuration will also return information about the status of the sync,
such as whether it is currently suspended or any errors that occurred
when last attempting a sync.

| Method | Path                          |
| :----- | :---------------------------- |
| `GET`  | `/nats/sync-config/:operator` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/sync-config/dev-cluster
```

### Response parameters

- `servers` `(array[string])` - The list of NATS servers to connect to.
- `suspend` `(bool: <optional>)` - Whether sync operations are paused for this operator.
- `connect_timeout` `(int: <optional>)` - Connection timeout for the NATS connection in seconds.
- `max_reconnects` `(int: <optional>)` - Maximum reconnects for the NATS connection.
- `reconnect_wait` `(int: <optional>)` - Reconnect wait for the NATS connection in seconds.
- `sync_user_name` `(string)` - The name given to the user credentials used for sync operations.
- `ignore_sync_errors_on_delete` `(bool: <optional>)` - Whether sync errors are ignored when accounts are deleted.
- `status` [`(status)`](#status-parameters) - Information about the current sync status.

#### Status parameters

- `status` `(string)` - The most recent status of the sync. This field may have the following values:
  - `"created"` - An initial status before the first sync attempt.
  - `"active"` - The sync is active and not erroring.
  - `"suspended"` - The sync is suspended.
  - `"error"` - The last sync attempt failed. Error details are available in the `errors` array. 
- `last_sync_time` `(string: <optional>)` - The most recent successful sync time in RFC3339 format.
- `errors` `(array[string]: <optional>)` - Any errors that occurred during the most recent sync.

### Sample response

```json
{
    "data": {
        "servers": ["nats://example.com:4222"],
        "connect_timeout": "30s",
        "max_reconnects": 5,
        
        "status": {
            "status": "active",
            "last_sync_time": "2025-12-26T18:36:13.7238536-08:00",
            "errors": []
        }
    }
}
```

## Delete sync configuration

This endpoint removes the sync configuration for an operator.

| Method   | Path                          |
| :------- | :---------------------------- |
| `DELETE` | `/nats/sync-config/:operator` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request DELETE \
    http://127.0.0.1:8200/v1/nats/sync-config/dev-cluster
```

## Read operator key

This endpoint returns the identity key for an operator.

| Method | Path                            |
| :----- | :------------------------------ |
| `GET`  | `/nats/operator-keys/:operator` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/operator-keys/dev-cluster
```

### Response parameters

- `public_key` `(string)` - The operator identity key public key.
- `private_key` `(string)` - The operator identity key private key.
- `seed` `(string)` - The operator identity key seed.

### Sample response

```json
{
    "data": {
        "public_key": "ODFKY...",
        "private_key": "PD4D3...",
        "seed": "SOAPQ...."
    }
}
```

## Read operator JWT

This endpoint reads the JWT for an operator.

| Method | Path                            |
| :----- | :------------------------------ |
| `GET`  | `/nats/operator-jwts/:operator` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/operator-jwts/dev-cluster
```

### Response parameters

- `jwt` `(string)` - The operator jwt.

### Sample response

```json
{
    "data": {
        "jwt": "eyJ0e...",
    }
}
```

## Create operator signing key

This endpoint create a signing key for an operator.
Calling the same endpoint more than once is a noop.

> [!WARNING]
> Creating an operator signing keys will reissue the operator JWT.
> For the new claims to take effect, the operator JWT must be updated on 
> all NATS server configs using this operator. 
> Account and user JWTs are not affected by operator JWT reissues.
>
> Creating an operator signing key will also [suspend the active sync configuration](./index.md#account-syncing).

| Method | Path                                          |
| :----- | :-------------------------------------------- |
| `POST` | `/nats/operator-signing-keys/:operator/:name` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `name` `(string: <required>)` - A name for the signing key. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    http://127.0.0.1:8200/v1/nats/operator-signing-keys/dev-cluster/my-signing-key
```

## Read operator signing key

This endpoint reads a signing key for an operator.

| Method | Path                                          |
| :----- | :-------------------------------------------- |
| `GET`  | `/nats/operator-signing-keys/:operator/:name` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `name` `(string: <required>)` - The name of the signing key. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/operator-signing-keys/dev-cluster/my-signing-key
```

### Response parameters

- `public_key` `(string)` - The signing key public key.
- `private_key` `(string)` - The signing key private key.
- `seed` `(string)` - The signing key seed.

### Sample response

```json
{
    "data": {
        "public_key": "OCSTK...",
        "private_key": "PB5SF...",
        "seed": "SOAHW...."
    }
}
```

## List operator signing keys

List all of the signing keys for the given operator.

| Method | Path                                              |
| :----- | :------------------------------------------------ |
| `LIST` | `/nats/operator-signing-keys/:operator`           |
| `GET`  | `/nats/operator-signing-keys/:operator?list=true` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `after` `(string: "")` - Optional entry to begin listing after for pagination; not required to exist.
- `limit` `(int: 0)` - Optional number of entries to return; defaults to all entries.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request LIST \
    http://127.0.0.1:8200/v1/nats/operator-signing-keys/dev-cluster
```

### Sample response

```json
{
    "data": {
        "keys": ["signing-key-1", "signing-key-2"]
    }
}
```

## Delete operator signing key

This endpoint deletes an operator signing key.

> [!WARNING] 
> Deleting an operator signing key will reissue the operator JWT.
> For the new claims to take effect, the operator JWT must be updated on 
> all NATS server configs using this operator. 
> Account and user JWTs are not affected by operator JWT reissues.
>
> Deleting an operator signing key will also [suspend the active sync configuration](./index.md#account-syncing).

| Method   | Path                                          |
| :------- | :-------------------------------------------- |
| `DELETE` | `/nats/operator-signing-keys/:operator/:name` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `name` `(string: <required>)` - The name of the signing key. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request DELETE \
    http://127.0.0.1:8200/v1/nats/operator-signing-keys/dev-cluster/my-signing-key
```

## Create/Update account

This endpoint create an account configuration under the specified operator.

> [!WARNING]
> Modifying an accounts's claims will reissue the account JWT. If a [sync config](#createupdate-sync-config)
> is configured, account JWT changes will be automatically synced to the NATS server.

| Method | Path                                |
| :----- | :---------------------------------- |
| `POST` | `/nats/accounts/:operator/:account` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `signing_key` `(string: "")` - Optionally specify the name of an operator signing key to use when signing this account's JWT. 
  If not set, the `operators` `default_signing_key` or the operator identity key will be used.
- `default_signing_key` `(string: "")` - Specify which account signing key to use by default when signing user and ephemeral user creds. 
  By setting this field, users and ephemeral users of this account will be unable to be signed using the account identity key. 
  If empty or not set, users and ephemeral users will be signed using the account's identity key. 
  This field may be overridden by the `users`/`ephemeral-users` `default_signing_key` or the `creds` `signing_key` parameter.
  If the specified signing key does not exist, an error will be raised when generating user or ephemeral user credentials.
- `claims` `(map: {})` - Override default claims in the JWT issued for this operator. See [nats-io/jwt](https://pkg.go.dev/github.com/nats-io/jwt/v2#AccountClaims) 
  for available fields. See [the guide](./index.md#account-claims) for details and an example of all available fields.

### Sample payload

```json
{
    "signing_key": "op-signing-key",
    "claims": {
        "nats": {
            "limits": {
                "subs": -1,
                "data": -1,
                "payload": -1,
            }
        }
    }
}
```

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/nats/accounts/dev-cluster/my-account
```

## Read account

This endpoint reads an account configuration.

| Method | Path                                |
| :----- | :---------------------------------- |
| `GET`  | `/nats/accounts/:operator/:account` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/accounts/dev-cluster/my-account
```

### Response parameters

- `signing_key` `(string: <optional>)` - The operator signing key specified to sign this account's JWT.
- `default_signing_key` `(string: <optional>)` - The default account signing key used when signing user or ephemeral user credentials.
- `claims` `(map: <optional>)` - Default claims used in the JWT issued for this account.
- `status` [`(status)`](#status-parameters-1) - Information about this account's status.

#### Status parameters

- `is_system_account` `(string)` - Whether this account is designated as the system account for its operator.
- `is_managed` `(string)` - Whether this account is a managed account (ie. created by the plugin).
- `sync_status`  [`(sync_status: <optional>)`](#sync-status-parameters) - Information about this account's latest sync.

#### Sync status parameters

- `synced` `(bool)` - Whether the last sync attempt for this account was successful. If `false`, details are available in the `last_error` field.
- `last_error` `(string: <optional>)` - The last error that occurred during syncing, if applicable.
- `last_sync_time`  `(string: <optional>)` - The last time this account was successfully synced, in RFC3339 format.

### Sample response

```json
{
    "signing_key": "op-signing-2",
    "default_signing_key": "acc-signing-1",
    "claims": {
        "nats": {
            "limits": {
                "subs": -1,
                "data": -1,
                "payload": -1
            }
        }
    },
    "status": {
        "is_system_account": false,
        "is_managed": false
    }
}
```

## List accounts

List all of the accounts that are configured under an operator.

| Method | Path                                 |
| :----- | :----------------------------------- |
| `LIST` | `/nats/accounts/:operator`           |
| `GET`  | `/nats/accounts/:operator?list=true` |

For convenience, the following paths are aliases that also work to list accounts:

| Path                            |
| :------------------------------ |
| `/nats/accounts-keys/:operator` |
| `/nats/accounts-jwts/:operator` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `after` `(string: "")` - Optional entry to begin listing after for pagination; not required to exist.
- `limit` `(int: 0)` - Optional number of entries to return; defaults to all entries.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request LIST \
    http://127.0.0.1:8200/v1/nats/accounts/dev-cluster
```

### Sample response

```json
{
    "data": {
        "keys": ["account1", "account2"]
    }
}
```

## Delete account

This endpoint deletes an account.

> [!WARNING]
> Deleting an account will also delete all of the objects under the account:
> - all keys and the account jwt
> - account imports
> - account revocations
> - users and ephemeral users

Warning! Deleting an account will also delete all of the objects under the account:

| Method   | Path                                |
| :------- | :---------------------------------- |
| `DELETE` | `/nats/accounts/:operator/:account` |

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request DELETE \
    http://127.0.0.1:8200/v1/nats/accounts/dev-cluster/my-account
```

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.

## Create/Update account import

This endpoint create an account import configuration for the given account.

As a convenience, the [import parameters](#import-parameters) for a single import claim may be passed
as top-level parameters. `imports` may not be passed along with root-level parameters. 
If creating an account import with more than one import claim using the CLI,  
JSON input must be used as the CLI cannot pass nested values using parameter arguments.

Root-level parameters cannot be used to modify an existing account import with more than one
import claim. When modifying an existing account import, the list of imports will be overwritten
entirely. 

> [!WARNING]
> Modifying an accounts's claims will reissue the account JWT. If a [sync config](#createupdate-sync-config)
> is configured, account JWT changes will be automatically synced to the NATS server.

| Method | Path                                             |
| :----- | :----------------------------------------------- |
| `POST` | `/nats/account-imports/:operator/:account/:name` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `name` `(string: <required>)` - A name for the import configuration. Included in the path.
- `imports` `(array: [])` - The list of import objects (see [possible fields below](#import-parameters)). At least one import must be defined.

#### Import parameters

Imports must follow the [nats-io/jwt](https://pkg.go.dev/github.com/nats-io/jwt/v2#Import) spec. 
See [the guide](./index.md#account-claims) for a sample import including all possible fields.

- `name` `(string)` - The name of the import.
- `subject` `(string: <required>)` - The subject being imported.
- `account` `(string: <required>)` - The account id to import from. This must be an account public key (`A123...`), **not** an account name.
- `token` `(string: "")` - An [activation token](https://docs.nats.io/using-nats/nats-tools/nsc/services#generating-an-activation-token). Required for imports of private exports (those with `"token_req": true`).
- `local_subject` `(string: "")` - An optional mapping to a different subject in the account.
- `type` `(string: <required>)` - Describes the type of the import. Valid values are `stream` and `service`.
- `share` `(bool: false)` - If importing a service, indicates if the import supports latency tracking.
- `allow_trace` `(bool: false)` - If importing a stream, indicates if the import allows message tracing.

### Sample payload

```json
{
    "imports": [
        {
            "name": "my-special-import",
            "account": "ADLQAYOH6XEMPI6PL4QTU4QH7KNPAEMGXY77XSMKXHVBKVXXYD23LYRU",
            "subject": "foo.bar",
            "type": "stream"
        }
    ]
}
```

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/nats/account-imports/dev-cluster/my-account/some-import
```

## Read account import

This endpoint reads an account import configuration.

| Method | Path                                             |
| :----- | :----------------------------------------------- |
| `GET`  | `/nats/account-imports/:operator/:account/:name` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `name` `(string: <required>)` - A name for the import configuration. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/account-imports/dev-cluster/my-account/some-import
```

### Response parameters

- `imports` `(array)` - The array of [import claims](#import-parameters).

### Sample response

```json
{
    "imports": [
        {
            "name": "my-special-import",
            "account": "ADLQAYOH6XEMPI6PL4QTU4QH7KNPAEMGXY77XSMKXHVBKVXXYD23LYRU",
            "subject": "foo.bar",
            "type": "stream"
        }
    ]
}
```

## List account imports

List all of the imports for the given account.

| Method | Path                                                 |
| :----- | :--------------------------------------------------- |
| `LIST` | `/nats/account-imports/:operator/:account`           |
| `GET`  | `/nats/account-imports/:operator/:account?list=true` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `after` `(string: "")` - Optional entry to begin listing after for pagination; not required to exist.
- `limit` `(int: 0)` - Optional number of entries to return; defaults to all entries.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request LIST \
    http://127.0.0.1:8200/v1/nats/account-imports/dev-cluster/my-account
```

### Sample response

```json
{
    "data": {
        "keys": ["import-1", "import-2"]
    }
}
```

## Read account key

This endpoint reads the identity key for an account.

| Method | Path                                    |
| :----- | :-------------------------------------- |
| `GET`  | `/nats/account-keys/:operator/:account` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/account-keys/dev-cluster/my-app
```

### Response parameters

- `public_key` `(string)` - The account identity key public key.
- `private_key` `(string)` - The account identity key private key.
- `seed` `(string)` - The account identity key seed.

### Sample response

```json
{
    "data": {
        "public_key": "AA4AN...",
        "private_key": "PBAYZ...",
        "seed": "SAAED..."
    }
}
```

## Read account JWT

This endpoint reads the JWT for an account.

| Method | Path                                    |
| :----- | :-------------------------------------- |
| `GET`  | `/nats/account-jwts/:operator/:account` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/account-jwts/dev-cluster/my-account
```

### Response parameters

- `jwt` `(string)` - The account jwt.

### Sample response

```json
{
    "data": {
        "jwt": "eyJ0e...",
    }
}
```

## Create/Update account signing key

This endpoint create a signing key for an account. Account signing keys can either be scoped or unscoped.
See [the NATS docs](https://docs.nats.io/using-nats/nats-tools/nsc/signing_keys#scoped-signing-keys) for more details.

When creating a `scoped` signing key, the signing key name will be used as the role name.

> [!WARNING]
> Creating an account signing key will reissue the account JWT. 
> 
> If a [sync config](#createupdate-sync-config) is configured, 
> account JWT changes will be automatically synced to the NATS server.

| Method | Path                                                  |
| :----- | :---------------------------------------------------- |
| `POST` | `/nats/account-signing-keys/:operator/:account/:name` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `name` `(string: <required>)` - A name for the signing key. Included in the path.
- `scoped` `(bool: false)` - Whether this signing key should be [scoped](https://docs.nats.io/using-nats/nats-tools/nsc/signing_keys#scoped-signing-keys).
- `description` `(string: "")` - A description for the signing key if `scoped` is `true`.
- `permission_template` `(map: {})` - Default permissions that will apply to users issued under this key if `scoped` is `true`.
  The permissions specified here may use [template functions](https://docs.nats.io/using-nats/nats-tools/nsc/signing_keys#template-functions) 
  in subjects.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    http://127.0.0.1:8200/v1/nats/account-signing-keys/dev-cluster/my-account/my-signing-key
```

## List account signing keys

List all of the signing keys for the given account.

| Method | Path                                                      |
| :----- | :-------------------------------------------------------- |
| `LIST` | `/nats/account-signing-keys/:operator/:account`           |
| `GET`  | `/nats/account-signing-keys/:operator/:account?list=true` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `after` `(string: "")` - Optional entry to begin listing after for pagination; not required to exist.
- `limit` `(int: 0)` - Optional number of entries to return; defaults to all entries.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request LIST \
    http://127.0.0.1:8200/v1/nats/account-signing-keys/dev-cluster/my-account
```

### Sample response

```json
{
    "data": {
        "keys": ["signing-key-1", "signing-key-2"]
    }
}
```

## Read account signing key

This endpoint reads a signing key for an account.

| Method | Path                                                  |
| :----- | :---------------------------------------------------- |
| `GET`  | `/nats/account-signing-keys/:operator/:account/:name` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `name` `(string: <required>)` - The name of the signing key. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/account-signing-keys/dev-cluster/my-account/my-signing-key
```

### Response parameters

- `scoped` `(bool: <optional>)` - Whether this signing key is [scoped](https://docs.nats.io/using-nats/nats-tools/nsc/signing_keys#scoped-signing-keys).
- `description` `(string: <optional>)` - A description for the signing key if `scoped` is `true`.
- `permission_template` `(map: <optional>)` - Default permissions that will apply to users issued under this key if `scoped` is `true`.
  The permissions specified here may use [template functions](https://docs.nats.io/using-nats/nats-tools/nsc/signing_keys#template-functions) 
  in subjects.

### Sample response

```json
{
    "data": {
        "public_key": "ACWIZ...",
        "private_key": "PS2AL...",
        "seed": "SAAI2....",
        "scoped": true,
        "permission_template": {
          "subs": 10,
          "data": -1,
          "payload": -1
        }
    }
}
```

## Delete account signing key

This endpoint deletes an account signing key.

> [!WARNING]
> Deleting an account signing keys will reissue the account JWT. 
> 
> If a [sync config](#createupdate-sync-config) is configured, 
> account JWT changes will be automatically synced to the NATS server. 
> As a consequence, all user credentials signed with this signing key will immediately be invalidated.

| Method   | Path                                                  |
| :------- | :---------------------------------------------------- |
| `DELETE` | `/nats/account-signing-keys/:operator/:account/:name` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `name` `(string: <required>)` - The name of the signing key. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request DELETE \
    http://127.0.0.1:8200/v1/nats/account-signing-keys/dev-cluster/my-account/my-signing-key
```

## Create/Update user

This endpoint create a user configuration under the specified operator and account.

| Method | Path                                   |
| :----- | :------------------------------------- |
| `POST` | `/nats/users/:operator/:account/:user` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `user` `(string: <required>)` - The name of the user. Included in the path.
- `default_signing_key` `(string: "")` - Specify the name of an account signing key to use by default when generating credentials. If empty or not set, the user will be signed using the account's default signing key. This may be overridden by the creds `signing_key` parameter.
- `creds_max_ttl` `(string: "")` - The maximum TTL for generated credentials, specified in seconds or as a Go duration format string, e.g. `"1h"`.
  If not set or 0, the [system default](https://openbao.org/docs/configuration/#max_lease_ttl) will be used.
- `creds_default_ttl` `(string: "")` - The default TTL for generated credentials, specified in seconds or as a Go duration format string, e.g. `"1h"`.
  If not set or 0, the [system default](https://openbao.org/docs/configuration/#default_lease_ttl) will be used.
- `revoke_on_delete` `(bool: false)` - Whether this user's identity key should be added to the account revocation list upon deletion.
- `claims` `(map: nil)` - Provide claims to be used in the credentials generated for this user. 
  See [nats-io/jwt](https://pkg.go.dev/github.com/nats-io/jwt/v2#UserClaims) for available fields. See [the guide](./index.md#user-claims) for details and an example of all available fields.

### Sample payload

```json
{
    "creds_max_ttl": "1h",
    "creds_default_ttl": "1h",
    "revoke_on_delete": true,
    "claims": {
        "nats": {
            "subs": -1,
            "data": -1,
            "payload": -1,
            "pub": {
                "allow": ["my-service.>"]
            },
            "sub": {
                "allow": ["_INBOX.*"]
            }
        }
    }
}
```

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/nats/users/dev-cluster/my-account/my-user
```

## List users

List all of the users that are configured under an account.

| Method | Path                                       |
| :----- | :----------------------------------------- |
| `LIST` | `/nats/users/:operator/:account`           |
| `GET`  | `/nats/users/:operator/:account?list=true` |

For convenience, the following paths are aliases that also work to list users:

| Path                                 |
| :----------------------------------- |
| `/nats/user-jwts/:operator/:account` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `after` `(string: "")` - Optional entry to begin listing after for pagination; not required to exist.
- `limit` `(int: 0)` - Optional number of entries to return; defaults to all entries.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request LIST \
    http://127.0.0.1:8200/v1/nats/accounts/dev-cluster
```

### Sample response

```json
{
    "data": {
        "keys": ["account1", "account2"]
    }
}
```

## Read user

This endpoint reads a user configuration.

| Method | Path                                   |
| :----- | :------------------------------------- |
| `GET`  | `/nats/users/:operator/:account/:user` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `user` `(string: <required>)` - The name of the user. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/users/dev-cluster/my-account/my-user
```

### Response parameters

- `default_signing_key` `(string: <optional>)` - The name of the specified account signing key used by default when generating credentials.
- `creds_max_ttl` `(int: <optional>)` - The maximum TTL for generated credentials in seconds.
- `creds_default_ttl` `(int: <optional>)` - The default TTL for generated credentials in seconds.
- `revoke_on_delete` `(bool: <optional>)` - Whether this user's identity key will be added to the account revocation list upon deletion.
- `claims` `(map: <optional>)` - Default claims used in the credentials issued for this user.

### Sample response

```json
{
    "creds_max_ttl": "1h",
    "creds_default_ttl": "1h",
    "revoke_on_delete": true,
    "claims": {
        "nats": {
            "subs": -1,
            "data": -1,
            "payload": -1,
            "pub": {
                "allow": ["my-service.>"]
            },
            "sub": {
                "allow": ["_INBOX.*"]
            }
        }
    }
}
```

## Delete user

This endpoint deletes a user configuration.

| Method   | Path                                   |
| :------- | :------------------------------------- |
| `DELETE` | `/nats/users/:operator/:account/:user` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `user` `(string: <required>)` - The name of the user. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request DELETE \
    http://127.0.0.1:8200/v1/nats/users/dev-cluster/my-account/my-user
```

## Read user key

This endpoint reads the identity key for a user.

| Method | Path                                       |
| :----- | :----------------------------------------- |
| `GET`  | `/nats/user-keys/:operator/:account/:user` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `user` `(string: <required>)` - The name of the user. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/operator-keys/dev-cluster/my-app/my-user
```

### Response parameters

- `public_key` `(string)` - The user identity key public key.
- `private_key` `(string)` - The user identity key private key.
- `seed` `(string)` - The user identity key seed.

### Sample response

```json
{
    "data": {
        "public_key": "UDK45...",
        "private_key": "PC4GD...",
        "seed": "SUALQ..."
    }
}
```

## Create/Update ephemeral user

This endpoint create an ephemeral user configuration under the specified operator and account.

Ephemeral users act similar to normal users, except they do not have a fixed identity key. Instead,
a new user key is generated for every credentials request. This allows credentials to be generated
for less secure contexts, such as end-user authentication. This prevents man-in-the-middle attacks
by ensuring that user identity keys are never reused.

| Method | Path                                             |
| :----- | :----------------------------------------------- |
| `POST` | `/nats/ephemeral-users/:operator/:account/:user` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `user` `(string: <required>)` - The name of the ephemeral user. Included in the path.
- `default_signing_key` `(string: "")` - Specify the name of an account signing key to use by default when generating credentials. If empty or not set, the user will be signed using the account's default signing key. This may be overridden by the creds `signing_key` parameter.
- `creds_max_ttl` `(string: "")` - The maximum TTL for generated credentials, specified in seconds or as a Go duration format string, e.g. `"1h"`.
  If not set or 0, the [system default](https://openbao.org/docs/configuration/#max_lease_ttl) will be used.
- `creds_default_ttl` `(string: "")` - The default TTL for generated credentials, specified in seconds or as a Go duration format string, e.g. `"1h"`.
  If not set or 0, the [system default](https://openbao.org/docs/configuration/#default_lease_ttl) will be used.
- `claims` `(map: nil)` - Provide claims to be used in the credentials generated for this user. 
  See [nats-io/jwt](https://pkg.go.dev/github.com/nats-io/jwt/v2#UserClaims) for available fields. See [the guide](./index.md#user-claims) for details and an example of all available fields.

### Sample payload

```json
{
    "creds_max_ttl": "1h",
    "creds_default_ttl": "1h",
    "claims": {
        "nats": {
            "subs": 10,
            "pub": {
                "allow": ["my-service.>"]
            },
            "sub": {
                "allow": ["_INBOX.*"]
            }
        }
    }
}
```

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/nats/ephemeral-users/dev-cluster/my-account/my-ephemeral-user
```

## Read ephemeral user

This endpoint reads an ephemeral user configuration.

| Method | Path                                             |
| :----- | :----------------------------------------------- |
| `GET`  | `/nats/ephemeral-users/:operator/:account/:user` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `user` `(string: <required>)` - The name of the ephemeral user. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/ephemeral-users/dev-cluster/my-account/my-ephemeral-user
```

### Response parameters

- `default_signing_key` `(string: <optional>)` - The name of the specified account signing key used by default when generating credentials.
- `creds_max_ttl` `(int: <optional>)` - The maximum TTL for generated credentials in seconds.
- `creds_default_ttl` `(int: <optional>)` - The default TTL for generated credentials in seconds.
- `claims` `(map: <optional>)` - Default claims used in the credentials issued for this ephemeral user.

### Sample response

```json
{
    "creds_max_ttl": "1h",
    "creds_default_ttl": "1h",
    "revoke_on_delete": true,
    "claims": {
        "nats": {
            "subs": -1,
            "data": -1,
            "payload": -1,
            "pub": {
                "allow": ["my-service.>"]
            },
            "sub": {
                "allow": ["_INBOX.*"]
            }
        }
    }
}
```

## Delete ephemeral user

This endpoint deletes an ephemeral user configuration.

| Method   | Path                                             |
| :------- | :----------------------------------------------- |
| `DELETE` | `/nats/ephemeral-users/:operator/:account/:user` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `user` `(string: <required>)` - The name of the ephemeral user. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request DELETE \
    http://127.0.0.1:8200/v1/nats/ephemeral-users/dev-cluster/my-account/my-ephemeral-user
```

## Generate user credentials

This endpoint generates credentials for a user.

| Method | Path                                   |
| :----- | :------------------------------------- |
| `GET`  | `/nats/creds/:operator/:account/:user` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `user` `(string: <required>)` - The name of the user. Included in the path.
- `signing_key` `(string: "")` - Specify the name of an account signing key to use when signing these credentials. 
  If empty or not set, the credentials will be signed using the specified by the `accounts` `default_signing_key` parameter or the account's identity key.
  If the signing key does not exist, an error will be raised.
- `not_before` `(string|int: "")` - Optionally specify a unix timestamp or RFC3339-formatted string to use as the `nbf` time of the generated creds.
- `tags` `(array: [])` - Additional tags to add to the user claims.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/creds/dev-cluster/my-account/my-user
```

### Response parameters

- `operator` `(string)` - The name of the operator.
- `account` `(string)` - The name of the account.
- `user` `(string)` - The name of the user.
- `creds` `(string)` - The decorated credentials including the JWT and seed string. 
- `jwt` `(string)` - The undecorated JWT. 
- `seed` `(string)` - The undecorated seed string. 
- `signing_key` `(string)` - The name of the signing key used to sign these creds, if applicable. 
- `expires_at` `(int)` - The expiration time for these creds, specified as a unix timestamp.

### Sample response

```json
{
    "lease_id": "nats/creds/dev-cluster/my-account/my-user/PCa6O3oDQDKIzvyAFpxult9s",
    "lease_duration": 3600,
    "data": {
        "operator": "dev-cluster",
        "account": "my-account",
        "user": "my-user",
        "creds": "-----BEGIN NATS USER JWT-----\neyJ0e...",
        "jwt": "eyJ0e...",
        "seed": "SUALQ...",
        "expires_at": 1766795354,
    }
}
```

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `user` `(string: <required>)` - The name of the user. Included in the path.

## Generate ephemeral user credentials

This endpoint generates credentials for an ephemeral user with the provided session name.

| Method | Path                                                      |
| :----- | :-------------------------------------------------------- |
| `GET`  | `/nats/ephemeral-creds/:operator/:account/:user/:session` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `user` `(string: <required>)` - The name of the ephemeral user. Included in the path.
- `session` `(string: <required>)` - A name for this session. Included in the path.
- `not_before` `(string|int: "")` - Optionally specify a unix timestamp or RFC3339-formatted string to use as the `nbf` time of the generated creds.
- `tags` `(array: [])` - Additional tags to add to the user claims.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/ephemeral-creds/dev-cluster/my-account/my-ephemeral-user/my-session
```

### Response parameters

- `operator` `(string)` - The name of the operator.
- `account` `(string)` - The name of the account.
- `user` `(string)` - The name of the ephemeral user.
- `session` `(string)` - The name of the session.
- `creds` `(string)` - The decorated credentials including the JWT and seed string. 
- `jwt` `(string)` - The undecorated JWT. 
- `seed` `(string)` - The undecorated seed string. 
- `signing_key` `(string)` - The name of the signing key used to sign these creds, if applicable. 
- `expires_at` `(int)` - The expiration time for these creds, specified as a unix timestamp.

### Sample response

```json
{
    "data": {
        "operator": "dev-cluster",
        "account": "my-account",
        "user": "my-user",
        "session": "my-session",
        "creds": "-----BEGIN NATS USER JWT-----\neyJ0e...",
        "jwt": "eyJ0e...",
        "seed": "SUACG...",
        "expires_at": 1766795354,
    }
}
```

## Create/Update a revocation

This endpoint creates a revocation entry on the account JWT for the provided user public key.
If the revocation already exists, the `ttl` will be overwritten and the `creation_time` reset
to the current time.

> [!WARNING]
> Revoking a user reissues the account JWT. If the JWT is synced to the NATS server, 
> this will immediately result in all user creds using the specified identity to become
> unauthorized.

| Method | Path                                        |
| :----- | :------------------------------------------ |
| `GET`  | `/nats/revocations/:operator/:account/:sub` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `sub` `(string: <required>)` - The public key (subject) of the user to revoke. This endpoint does not accept user names, only public keys.
- `ttl` `(string: "")` - The TTL of the revocation, specified in seconds or as a Go duration format string, e.g. `"1h"`.
  At the end of this period, the revocation will automatically be deleted. If not set or set to 0, the revocation will never expire.

### Sample payload

```json
{
    "ttl": "5h"
}
```

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/nats/revocations/dev-cluster/my-account/UCCMLTR5QQNO4M25RXCBPII5MEXRZMXHSV746EYA3CUPGQ2A424CVJ6H
```

## Read revocation

This endpoint reads a revocation.

| Method | Path                                        |
| :----- | :------------------------------------------ |
| `GET`  | `/nats/revocations/:operator/:account/:sub` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `sub` `(string: <required>)` - The public key (subject) of the revoked user. This endpoint does not accept user names, only public keys.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/nats/revocations/dev-cluster/my-account/UCCMLTR5QQNO4M25RXCBPII5MEXRZMXHSV746EYA3CUPGQ2A424CVJ6H
```

### Response parameters

- `ttl` `(int)` - The ttl of the revocation in seconds. A ttl of 0 means the revocation will not expire.
- `creation_time` `(string)` - The creation time of the revocation in RFC3339 format.

### Sample response

```json
{
    "ttl": 3600,
    "creation_time": "2025-12-26T18:36:13.7238536-08:00"
}
```

## List revocations

List all of the revocations for the given account.

| Method | Path                                             |
| :----- | :----------------------------------------------- |
| `LIST` | `/nats/revocations/:operator/:account`           |
| `GET`  | `/nats/revocations/:operator/:account?list=true` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `after` `(string: "")` - Optional entry to begin listing after for pagination; not required to exist.
- `limit` `(int: 0)` - Optional number of entries to return; defaults to all entries.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request LIST \
    http://127.0.0.1:8200/v1/nats/revocations/dev-cluster/my-account
```

### Sample response

```json
{
    "data": {
        "keys": ["UDD2I...", "UCCML..."]
    }
}
```

## Delete revocation

This endpoint deletes a revocation from an account.

> [!WARNING]
> Unrevoking a user reissues the account JWT. If the JWT is synced to the NATS server, 
> this will immediately enable all user creds using the specified identity to authorize.

| Method   | Path                                        |
| :------- | :------------------------------------------ |
| `DELETE` | `/nats/revocations/:operator/:account/:sub` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `sub` `(string: <required>)` - The public key (subject) of the user to revoke. This endpoint does not accept user names, only public keys.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request DELETE \
    http://127.0.0.1:8200/v1/nats/users/dev-cluster/my-account/UCCMLTR5QQNO4M25RXCBPII5MEXRZMXHSV746EYA3CUPGQ2A424CVJ6H
```

## Rotate an operator identity key

This endpoint rotates the identity key of the specified operator.

> [!WARNING]
> Rotating an operator identity key will reissue all account JWTs signed with the key.
> It will also result in the operator JWT being reissued.
> Operator JWT changes are not able to be automatically synced, 
> and must be updated in the target NATS server config.
> The [generate-server-config](#generate-server-config) endpoint may assist with this.
>
> Modifying the operator's signing keys will automatically suspend all active sync operations.
> Syncing may be resumed once the target NATS servers have been updated with the new operator JWT.

| Method | Path                              |
| :----- | :-------------------------------- |
| `POST` | `/nats/rotate-operator/:operator` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    http://127.0.0.1:8200/v1/nats/rotate-operator/dev-cluster
```

## Rotate an operator signing key

This endpoint rotates a signing key of an operator. The new signing key is generated randomly
using [github.com/nats-io/nkeys](https://github.com/nats-io/nkeys).

> [!WARNING]
> Rotating an operator signing key will reissue all account JWTs signed with the key.
> It will also result in the operator JWT being reissued. 
> Operator JWT changes are not able to be automatically synced, 
> and must be updated in the target NATS server config.
> The [generate-server-config](#generate-server-config) endpoint may assist with this.
>
> Modifying the operator's signing keys will automatically suspend all active sync operations.
> Syncing may be resumed once the target NATS servers have been updated with the new operator JWT.

| Method | Path                                                |
| :----- | :-------------------------------------------------- |
| `POST` | `/nats/rotate-operator-signing-key/:operator/:name` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `name` `(string: <required>)` - The name of the signing key. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    http://127.0.0.1:8200/v1/nats/rotate-operator-signing-key/dev-cluster/my-signing-key
```

## Rotate an account identity key

This endpoint rotates the identity key of the specified account.

> [!WARNING]
> Rotating an account identity key will invalidate all user creds signed with that key.
> It will also result in the account JWT being reissued. If the JWT is synced to the NATS server, 
> this will immediately result in all user creds signed by the old key to become unauthorized.
> Users signed by signing keys under this account are unaffected.

| Method | Path                                      |
| :----- | :---------------------------------------- |
| `POST` | `/nats/rotate-account/:operator/:account` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    http://127.0.0.1:8200/v1/nats/rotate-account/dev-cluster/my-account
```

## Rotate an account signing key

This endpoint rotates a signing key of an account to a new randomly generated one.

> [!WARNING]
> Rotating an account signing key will invalidate all user creds signed with that key.
> It will also result in the account JWT being reissued. If the JWT is synced to the NATS server, 
> this will immediately invalidate all user credentials signed by the old key.
> Users signed by the account identity key are unaffected.

| Method | Path                                                        |
| :----- | :---------------------------------------------------------- |
| `POST` | `/nats/rotate-account-signing-key/:operator/:account/:name` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `name` `(string: <required>)` - The name of the signing key. Included in the path.

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    http://127.0.0.1:8200/v1/nats/rotate-account-signing-key/dev-cluster/my-account/my-signing-key
```

## Rotate a user key

This endpoint rotates the identity key of the specified user to a new randomly generated one, 
and optionally revokes the previous identity key. 

> [!WARNING]
> Revoking the identity key will result in the account JWT being reissued. 
> If the JWT is synced to the NATS server, it will immediately invalidate 
> all user creds issued under the old user identity key.

| Method | Path                                         |
| :----- | :------------------------------------------- |
| `POST` | `/nats/rotate-user/:operator/:account/:user` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `account` `(string: <required>)` - The name of the account. Included in the path.
- `user` `(string: <required>)` - The name of the user. Included in the path.
- `revoke` `(bool: true)` - Whether to add the old public key to the account's revocation list. 
  The revocation will use the maximum TTL of the user as its TTL. Pass `revoke=false` to disable this behavior.
  
### Sample payload

```json
{
    "revoke": false
}
```

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/nats/rotate-user/dev-cluster/my-account/my-user
```

## Generate server config

Generates a valid NATS server config file for the given operator.

> [!NOTE]
> Unlike the similar `nsc generate config` command, this endpoint does not generate
> configuration for a
> [resolver block](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/jwt/resolver).

| Method | Path                                     |
| :----- | :--------------------------------------- |
| `GET`  | `/nats/generate-server-config/:operator` |

### Request parameters

- `operator` `(string: <required>)` - The name of the operator. Included in the path.
- `format` `(string: "json")` - The desired output format. Valid values are `json` or `nats`.
- `include_resolver_preload` `(bool: false)` - Whether to include a `resolver_preload` block in the generated config. 
  This is only supported for NATS and MEMORY resolvers. It will contain the public key and current JWT of all accounts 
  under the specified operator. 

### Sample request

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    http://127.0.0.1:8200/v1/nats/generate-server-config/dev-cluster?format=json
```

### Sample response

```json
{
    "data": {
        "config": "{\"operator\":\"ODFKY...\",\"system_account\":\"ADGMW...\"}"
    }
}
```
