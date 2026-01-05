# NATS JWT secrets engine

<!-- 
- introduction
    - this plugin acts as a replacement for the nsc command line tool
    - manage the entire lifecycle of NATS operators, accounts, and users
    - generate user credentials with templating support and full openbao lease support
    - rotate account signing keys
    - automatically sync accounts to nats server
    - automatically fetch accounts using the companion `openbao-nats-account-server`
-->

The NATS JWT secrets engine dynamically generates NATS operator, account, and user JWTs. 
For more information about how NATS JWT authentication works, view the [official NATS documentation](https://docs.nats.io/running-a-nats-service/nats_admin/security/jwt).

This guide assumes a basic understanding of how to operate OpenBao, as well as a working knowledge of the NATS JWT system.

## Setup

<!-- 
- setup
    - OCI image or release binary
    - using CLI
    - using declarative plugin syntax -->

### OCI Image

This plugin is available as an OCI image and can be installed & registered via the [declarative plugin](https://openbao.org/docs/configuration/plugins/) configuration block in the OpenBao configuration.

> [!IMPORTANT]
> Declarative plugins require a OpenBao version `2.5.0` or higher

<!-- todo: post real image tag & use semantic-release to auto-update the README -->
```hcl
plugin "secret" "nats" {
    image = "ghcr.io/bonesofgiants/openbao-plugin-secrets-nats"
    version = "v2.1.1"
    binary_name = "openbao-plugin-secrets-nats"
    sha256sum = "dec5b2c17a4616de030d7945cf4b4eeb87c037a30e4fa3b99c2bd4502e25e1bc"
}

# recommended settings
plugin_auto_download = true
plugin_auto_register = true
```

### Release Binary

This plugin is also available as a prebuilt binary in the [Releases page](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats/releases) of the repository.

The binary must be placed within the configured `plugin_directory` as part of your OpenBao deployment.

It can then be registered using the `bao` CLI:

<!-- todo: post real image tag & use semantic-release to auto-update the README -->
```sh
$ bao plugin register \
    -version=v2.1.1 \
    -sha256=dec5b2c17a4616de030d7945cf4b4eeb87c037a30e4fa3b99c2bd4502e25e1bc \
    -command=openbao-plugin-secrets-nats \
    nats
Success! TODO
```

### Mount the plugin

Once registered, the plugin can be mounted:

```sh
$ bao secrets enable nats
Success! Enabled the nats secrets engine at: nats/
```

## Operators
<!-- 
- operator
    - claims
        - fields that are overridden when generating the jwt
            - system account name will be overwritten if systemaccountname is set & the specified account exists,
              or if create_system_account is true
            - expires time is ignored, issued operator jwts don't expire
            - issuer is always overwritten
            - issuedat is always overwritten
            - ID is always overwritten
            - subject is always overwritten with the operator id 
            - signingkeys list is merged with any declared signing keys
        - they're self-signed
        - warning!! updating operator claims will also suspend the account sync, since the operator is no longer in sync with the nats server
    - signing keys
        - rotating signing key
            - warning!! will reissue all accounts signed by this key
            - warning!! will also suspend the account sync, since the operator is no longer in sync with the nats server
    - rotating operator key
        - warning!! will reissue all account jwts under the operator
        - warning!! will also suspend the account sync, since the operator is no longer in sync with the nats server
    - system account
        - managed system account
            - cannot edit claims of the managed system account
        - custom system account
            - if you provide your own, it should have at least these claims: https://github.com/nats-io/nsc/blob/a8cd1b14b5694a65a1d4f97501435f001a538596/cmd/init.go#L328-L347 (or provide a link to my iteration of the default)
    - sync config
        - generates sync user creds on the fly using the system account
        - if there is no system account for the operator, sync will not function
        - accounts will be synced whenever their JWT is reissued
        - sync may be suspended by setting suspend=true
        - sync will be suspended **automatically** if the operator jwt changes for any reason
        - sync behavior
            - will push all accounts under the operator on a background interval
            - changes to the account will result in a sync
                - changing claims
                - changing imports
                - changing revocations
        - account server
            - openbao cannot directly act as an account server for lookups
            - but openbao-nats-account-proxy can fill that function!
    - managed operators (eg. synadia)
        - not currently supported
-->
Operators own NATS servers. Their JWTs are provided directly in the NATS server config. All other objects are 
created within the context of an operator.

The simplest operator requires no additional configuration:
```sh
$ bao write -force=true nats/operators/my-operator
```

This will create an operator called `my-operator`. It will also generate an identity key, issue a self-signed JWT, 
and create a system account called `SYS`.

At this point the operator is ready to be installed into a NATS server. The utility `generate-server-config` is
designed to assist in this by providing a pre-configured NATS configuration file.

```sh
$ bao read -format=json nats/generate-server-config/my-operator | jq -r '.data.config' > nats-conf.json
``` 

```sh
$ nats-server -c nats-conf.json
```

### Operator configuration

A complete example of all possible fields when creating or updating an operator follows.
See the following section for details on the `claims` object.

```json
{
    "create_system_account": true,
    "system_account_name": "SYS",
    "default_signing_key": "sk1",
    "claims": {}
}
```

### Operator claims

The claims object may contain any valid field for a NATS operator JWT.

Additionally, while all claims of the operator JWT may be overridden by 
providing custom claims in the `claims` field, there are some important caveats:

1. `nats.system_account` will be overwritten with the account public key if 
   the system account specified by `system_account_name` exists.
2. `exp` is always zeroed out, as operator JWTs do not expire.
3. `issuer` and `sub` are is always overwritten with the operator's public key.
4. `issuedat` is always overwritten with the time the JWT was generated.
5. `jti` is always overwritten with a hash of the contents.
6. If you've created any [operator signing keys](#operator-signing-keys), 
   those keys will be merged with the existing list of signing keys.

<details>
<summary>Example claims with all fields</summary>

Note that some fields may be mutually incompatible in a real JWT,
and will result in a validation error when attempting a write.

```json
{
    "aud": "NATS",
    "exp": 1766876393,
    "jti": "abc123",
    "iat": 1620242553,
    "iss": "OABC123",
    "name": "my-operator",
    "nbf": 1620242553,
    "sub": "OABC123",
    "nats": {
        "signing_keys": ["OGHI456", "OMNO789"],
        "account_server_url": "http://example.com",
        "operator_service_urls": ["nats://s1.example.com"],
        "system_account": "A1234",
        "assert_server_version": "1.2.3",
        "strict_signing_key_usage": false,
        "tags": ["tag1:value", "tag2:value"],
        "type": "operator",
        "version": 2
    }
}
```

</details>

### System account

By default, operators will be created along with a managed system account. Managed system accounts cannot be modified or deleted, though users may be created under managed system accounts.

Managed system accounts are preconfigured with following claims:

```json
{
    "nats": {
        "exports": [
            {
                "name": "account-monitoring-services",
                "subject": "$SYS.REQ.ACCOUNT.*.*",
                "type": "service",
                "response_type": "Stream",
                "account_token_position": 4,
                "description": "Request account specific monitoring services for: SUBSZ, CONNZ, LEAFZ, JSZ and INFO",
                "info_url": "https://docs.nats.io/nats-server/configuration/sys_accounts"
            },
            {
                "name": "account-monitoring-streams",
                "subject": "$SYS.ACCOUNT.*.>",
                "type": "stream",
                "account_token_position": 3,
                "description": "Account specific monitoring stream",
                "info_url": "https://docs.nats.io/nats-server/configuration/sys_accounts"
            }
        ],
        "limits": {
            "subs": -1,
            "data": -1,
            "payload": -1,
            "imports": -1,
            "exports": -1,
            "wildcards": true,
            "conn": -1,
            "leaf": -1
        }
    }
}
```

You can migrate from a managed system account to a custom system account by setting `create_system_account` to `false`.
If it exists, the managed system account will be deleted and you may create a new account with a name matching `system_account_name`. If you use a custom system account, it must at least have the above claims, or it will not function
properly as a system account.

> [!WARNING]
> Deleting an account will result in all dependent objects being deleted as well.

If you wish to migrate from a custom system account to a managed system account, you must simultaneously set
`create_system_account` to `true` and modify the `system_account_name`. This is because the plugin will not
delete custom system accounts, and the generated system account will clash with the existing account of the
same name.

If the `system_account_name` specified in the operator does not exist, the operator JWT will be issued without any
system account specified. In general, there is no reason not to have a system account and in most situations
the managed system account should prove adequate without any modification.

### Operator signing keys

Signing keys may be created under an operator by giving them a human-readable alias:

```sh
$ bao write -force=true nats/operator-signing-keys/my-operator/sk-1
```

Creating a signing key will automatically add its public key to the operator's claims and reissue the operator JWT.
<!-- todo add blurb about syncing -->

By default, the operator will sign account JWTs using its identity key. This can be overridden by supplying the name of
a signing key in the `default_signing_key` field of the operator.

### Account syncing

The plugin can be configured to automatically push account modifications to a target NATS cluster.

<!-- todo flesh out -->

### Managed and pre-existing operators

Operators can either be local or managed. More information on this distinction is available in the 
[NATS documentation](https://docs.nats.io/using-nats/nats-tools/nsc/managed). 
This plugin currently only supports local operators.

Additionally, the plugin does not currently support importing of pre-existing operator JWTS or Nkeys.

## Accounts

<!-- 
- account
    - claims
        - fields that are overwritten/modified when generating the jwt
            - expires time is ignored, issued account jwts don't expire
            - issuer is always overwritten
            - issuedat is always overwritten
            - ID is always overwritten
        - they're signed by the owning operator
    - signing keys
        - rotating signing key
            - warning!! will invalidate all previously issued user jwts signed by this key
        - activation claims are not currently supported for exports
    - rotating account key
        - warning!! will invalidate all previously issued user jwts signed by this key
    - imports
    - revocations
        - note: revocations result in a sync, so be careful of creating too many revocations at once
-->

### Account claims

The claims object may contain any valid field for a NATS account JWT.

Additionally, while all claims of the account JWT may be overridden by 
providing custom claims in the `claims` field, there are some important caveats:

1. `exp` is always zeroed out, as account JWTs do not expire.
2. `iss` is always overwritten with the operator or signing public key.
3. `sub` is always overwritten with the account public key.
4. `iat` is always overwritten with the time the JWT was generated.
5. `jti` is always overwritten with a hash of the contents.
6. If you've created any [account signing keys](#account-signing-keys), 
   those keys will be merged with the existing list of signing keys.

<details>
<summary>Example claims with all fields</summary>

Note that some fields may be mutually incompatible in a real JWT,
and will result in a validation error when attempting a write.

```json
{
    "aud": "NATS",
    "exp": 1766876393,
    "jti": "abc123",
    "iat": 1620242553,
    "iss": "AABC123",
    "name": "my-account",
    "nbf": 1620242553,
    "sub": "AABC123",
    "nats": {
        "imports": [
            {
                "name": "import-name",
                "subject": "some.subject",
                "account": "AA123",
                "token": "eyJ0eXAiOiJKV1QiLCJ...",
                "local_subject": "to.local.subject",
                "type": "stream",
                "share": false,
                "allow_trace": false
            }
        ],
        "exports": [
            {
                "name": "export-name",
                "subject": "some.subject",
                "type": "service",
                "token_req": false,
                "revocations": {
                    "U1234": 1620242553,
                },
                "response_type": "Singleton",
                "response_threshold": 10,
                "service_latency": {
                    "sampling": 100,
                    "results": "latency.subject"
                },
                "account_token_position": 0,
                "advertise": false,
                "allow_trace": false
            }
        ],
        "limits": {
            "subs": -1,
            "data": -1,
            "payload": -1,
            "imports": -1,
            "exports": -1,
            "wildcards": false,
            "disallow_bearer": false,
            "conn": -1,
            "leaf": -1,
            "mem_storage": -1,
            "disk_storage": -1,
            "streams": -1,
            "consumer": -1,
            "max_ack_pending": -1,
            "mem_max_stream_bytes": -1,
            "disk_max_stream_bytes": -1,
            "max_bytes_required": false,
            "tiered_limits": {
                "tier1": {
                    "mem_storage": -1,
                    "disk_storage": -1,
                    "streams": -1,
                    "consumer": -1,
                    "max_ack_pending": -1,
                    "mem_max_stream_bytes": -1,
                    "disk_max_stream_bytes": -1,
                    "max_bytes_required": false
                }
            }
        },
        "signing_keys": ["AGHI456", "AMNO789"],
        "revocations": {
            "U1234": 1620242553,
        },
        "default_permissions": {
            "pub": {
                "allow": ["sub1"],
                "deny": ["sub2"]
            },
            "sub": {
                "allow": ["sub3"],
                "deny": ["sub4"]
            },
            "resp": {
                "max": 1,
                "ttl": 10
            }
        },
        "mappings": {
            "sub1": [
                {
                    "subject": "sub2",
                    "weight": 100,
                    "cluster": "cluster1"
                }
            ]
        },
        "authorization": {
            "auth_users": ["UABC123"],
            "allowed_accounts": ["AABC123"],
            "xkey": "12341234"
        },
        "trace": {
            "dest": "trace.subject",
            "sampling": 100,
        },
        "cluster_traffic": "owner",
        "tags": ["tag1:value", "tag2:value"],
        "type": "account",
        "description": "This is an account.",
        "info_url": "http://example.com"
        "version": 2
    }
}
```

</details>

## Account imports

This plugin supports declarative imports for accounts. 
A named import represents logically grouped lists of import claims. These imports are merged into the 
list of imports on the account claim whenever the account JWT is reissued.



- imports presently require the account public key
  - this can be retrieved from the `nats/account-keys/:op/:acc` path
- at least one import must be specified or the request is rejected.
- import shape example

## Account revocations

This plugin supports declarative revocations for accounts.
Revocations may have TTLs and their lifecycle will automatically be
managed by OpenBao.

- revocations require the user public key
  - this can be retrieved from the `nats/user-keys/:op/:acc/:user` path 
- revocation shape example
  - ttl -- if not specified the revocation will not expire

### Revocations

## Users and ephemeral users
<!-- 
- users and ephemeral users
    - claims
        - fields that are overridden when generating the jwt
    - user templating (default template params op/acc/user)
    - leases (default & max ttl + specify ttl when requesting)
        - revoke behavior on lease expiry (ie. should be a noop)
        - revoke an ephemeral user by prefix
    - ephemeral users will be tagged with their user id
    - dynamic creds
     -->
### User claims

The claims object may contain any valid field for a NATS user JWT.

Additionally, while all claims of the user JWT may be overridden by 
providing custom claims in the `claims` field, there are some important caveats:

1. `iss` is always overwritten with the account or signing public key.
2. `sub` is always overwritten with the user public key.
3. `iat` is always overwritten with the time the JWT was generated.
4. `jti` is always overwritten with a hash of the contents.
5. `nats.issuer_account` is always overwritten with the account public key if using a signing key, or cleared otherwise.

Most fields need not be specified under normal circumstances. It is important to
specify the pub/sub permissions and limits under the 
`pub`, `sub`, `resp`, `subs`, `data`, and `payload`
fields, or the generated user won't have permissions to do anything.

<details>
<summary>Example claims with all fields</summary>

Note that some fields may be mutually incompatible in a real JWT,
and will result in a validation error when attempting a write.

```json
{
    "aud": "NATS",
    "exp": 1766876393,
    "jti": "abc123",
    "iat": 1620242553,
    "iss": "AABC123",
    "name": "my-user",
    "nbf": 1620242553,
    "sub": "UABC123",
    "nats": {
        "pub": {
            "allow": ["sub1"],
            "deny": ["sub2"]
        },
        "sub": {
            "allow": ["sub3"],
            "deny": ["sub4"]
        },
        "resp": {
            "max": 1,
            "ttl": 10
        },
        "subs": -1,
        "data": -1,
        "payload": -1,
        "src": ["192.0.2.0/24"],
        "times": [{"start": "00:00:00", "end": "23:59:59"}],
        "times_location": "UTC",
        "bearer_token": false,
        "proxy_required": false,
        "allowed_connection_types": ["STANDARD"],
        "issuer_account": "A123ABC",
        "tags": ["tag1:value", "tag2:value"],
        "type": "user",
        "version": 2
    }
}
```
</details>

### Ephemeral users

- ephemeral users have a "session" name that can be templated into the generated creds

### Revoking ephemeral user credentials

As ephemeral users don't have a fixed identity, it's not possible to revoke ephemeral users
using the account revocation feature directly. Instead, the ephemeral user can be revoked using the
OpenBao `sys/leases/revoke-prefix` endpoint or the `bao lease revoke -prefix` command.

For example, if your ephemeral user is configured on the path `nats/ephemeral-users/my-operator/my-account/my-user`,
you can revoke all active sessions for that user:

```sh
$ bao lease revoke -prefix nats/ephemeral-creds/my-operator/my-account/my-user
```

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    http://127.0.0.1:8200/v1/sys/leases/revoke-prefix/nats/ephemeral-creds/my-operator/my-account/my-user
```

Or revoke a specific session name:

```sh
$ bao lease revoke -prefix nats/ephemeral-creds/my-operator/my-account/my-user/my-session
```

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    http://127.0.0.1:8200/v1/sys/leases/revoke-prefix/nats/ephemeral-creds/my-operator/my-account/my-user/my-session
```

Since the `sys/leases/revoke-prefix` requires the `sudo` capability, policies granting the capability should be kept as specific as possible. For example, the following policy would only allow revoking of a specific ephemeral user's
credentials.

```hcl
path "sys/leases/revoke-prefix/nats/ephemeral-creds/my-operator/my-account/my-user/*" {
    capabilities = ["sudo"]
}
```

> [!IMPORTANT]
> If you need to revoke a large number of users at once, it may be more efficient to sign the ephemeral users
> with a dedicated account signing key, and rotate the signing key instead.

<!-- todo add blurbs about modifying account jwts and keeping ttls short to minimize the number of 
revocations/account updates necessary -->

## Key rotation

### Operator key rotation

```sh
$ bao write -force=true nats/rotate-operator/my-operator
```

<!-- todo add blurbs about modifying operator jwts and pausing sync configs -->

### Operator signing key rotation

```sh
$ bao write -force=true nats/rotate-operator-signing-key/my-operator/my-signing-key
```

<!-- todo add blurbs about modifying operator jwts and pausing sync configs -->

### Account key rotation

```sh
$ bao write -force=true nats/rotate-account/my-operator/my-account
```

<!-- todo add blurbs about modifying account jwts invalidating users -->

### Account signing key rotation

```sh
$ bao write -force=true nats/rotate-account-signing-key/my-operator/my-account/my-signing-key
```

<!-- todo add blurbs about modifying account jwts invalidating users -->

### User key rotation

```sh
$ bao write -force=true nats/rotate-user/my-operator/my-account/my-user
```

By default, rotating a user key will automatically revoke the previous one. The revocation will
have a TTL of the maximum TTL of the user's credentials. This behavior can be disabled by passing
`revoke=false`.

<!-- todo add blurbs about modifying user jwts & revoking modifying account jwts -->

Ephemeral users do not have fixed keys and so cannot be rotated.
