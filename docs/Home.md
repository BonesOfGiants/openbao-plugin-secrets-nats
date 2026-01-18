# NATS JWT secrets engine

<!-- 
- introduction
    - this plugin acts as a replacement for the nsc command line tool
    - manage the entire lifecycle of NATS operators, accounts, and users
    - generate user credentials with templating support and full openbao lease support
    - rotate account signing keys
    - automatically sync accounts to nats cluster
    - automatically fetch accounts using the companion `openbao-nats-account-server`
-->

The NATS JWT secrets engine provides a declarative interface for managing NATS operators, accounts, and users. 
For more information about how NATS JWT authentication works, view the [official NATS documentation](https://docs.nats.io/running-a-nats-service/nats_admin/security/jwt).

This guide assumes a basic understanding of how to operate OpenBao, as well as a working knowledge of the NATS JWT system.

This plugin is untested with Vault and is intended to be used with OpenBao.
However, as long as the OpenBao SDK remains cross-compatible with Vault's plugin API,
this plugin should be usable as a Vault plugin with no modifications.

## Setup

A quickstart guide is also available in the [README](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats?tab=readme-ov-file#quickstart).

### OCI Image

This plugin is available as an OCI image and can be installed & registered via the [declarative plugin](https://openbao.org/docs/configuration/plugins/) configuration block in the OpenBao configuration.
The latest release can be found on the [Releases page](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats/releases) of the repository.

> [!IMPORTANT]
> Declarative plugins require a OpenBao version `2.5.0` or higher

Replace the version and sha256sum fields with the correct values for the release version you are using.

```hcl
plugin "secret" "nats" {
    image = "ghcr.io/bonesofgiants/openbao-plugin-secrets-nats"
    version = "v0.0.0"
    binary_name = "openbao-plugin-secrets-nats"
    sha256sum = "dec5b2c17a4616de030d7945cf4b4eeb87c037a30e4fa3b99c2bd4502e25e1bc"
}
```

### Release Binary

This plugin is also available as a prebuilt binary in the [Releases page](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats/releases) of the repository.

The binary must be placed within the configured `plugin_directory` as part of your OpenBao deployment.

It can then be registered using the `bao` CLI. Replace the version and sha256sum fields with the correct values for the release version you are using.

```sh
$ bao plugin register \
    -version=v0.0.0 \
    -sha256=dec5b2c17a4616de030d7945cf4b4eeb87c037a30e4fa3b99c2bd4502e25e1bc \
    -command=openbao-plugin-secrets-nats \
    nats
Success! TODO
```

### Mount the plugin

Once registered, the plugin may be mounted:

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
        - warning!! updating operator claims will also suspend the account sync, since the operator is no longer in sync with the nats cluster
    - signing keys
        - rotating signing key
            - warning!! will reissue all accounts signed by this key
            - warning!! will also suspend the account sync, since the operator is no longer in sync with the nats cluster
    - rotating operator key
        - warning!! will reissue all account jwts under the operator
        - warning!! will also suspend the account sync, since the operator is no longer in sync with the nats cluster
    - system account
        - managed system account
            - cannot edit claims of the managed system account
        - custom system account
            - if you provide your own, it should have at least these claims: https://github.com/nats-io/nsc/blob/a8cd1b14b5694a65a1d4f97501435f001a538596/cmd/init.go#L328-L347 (or provide a link to my iteration of the default)
    - account server
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

Operators own NATS clusters. Their JWTs are provided directly in the NATS cluster config. All other objects are
created within the context of an operator.

The simplest operator requires no additional configuration:
```sh
$ bao write -force=true nats/operators/my-operator
```

This will create an operator called `my-operator`. When created, the operator will automatically generate an identity key,
issue a self-signed JWT, and create a system account called `SYS`.

If you're planning to utilize the [account server](#account-server) feature, the operator may be installed into the target NATS cluster at this point.
The utility path [`nats/generate-server-config/:op`](API.md#generate-server-config) is
designed to assist with this by providing a pre-configured NATS configuration file that can easily be included in another
NATS cluster config.

> [!NOTE]
> The configuration generated by `nats/generate-server-config/:op` cannot be used *by itself* as
> a valid NATS configuration. At minimum you must also provide a [resolver block](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/jwt/resolver#nats-based-resolver).

```sh
$ bao read -format=json nats/generate-server-config/my-operator | jq -r '.data.config' > operator.conf
``` 

```sh
$ cat << EOF > nats-server.conf
include ./operator.conf

resolver: {
  type: "full"
  dir: "./jwt"
}
EOF
$ nats-server -c nats-server.conf
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

The claims object may contain any valid operator JWT claims. To be specific, you may provide any of the
values under the `nats` section of an issued JWT. The `iss`, `jti`, `name`, and other root fields of the
JWT are fixed and cannot be customized. However, some additional field values are calculated when the 
JWT is signed and will always be overwritten/modified:

1. `system_account` will be overwritten with the account public key if 
   the system account specified by `system_account_name` exists, or otherwise
   cleared.
2. If you've declared any [operator signing keys](#operator-signing-keys), 
   those keys will be merged with the list of signing keys in the template
   claims.
3. `type` and `version` are set by the NATS jwt library and can't be modified.

<details>
<summary><b>Example claims with all possible fields</b></summary>

```json
{
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
```

</details>

### System account

By default, operators will be created along with a managed system account. Managed system accounts cannot be modified or deleted, though users may be created under managed system accounts.

Managed system accounts are preconfigured with following claims:

```json
{
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

> [!WARNING]
> Modifying an operator's signing keys will **suspend** the active account server for that operator.
> Syncing may be re-enabled once the reissued operator JWT has been updated in the target NATS cluster config.

By default, the operator will sign account JWTs using its identity key. This can be overridden by supplying the name of
a signing key in the `default_signing_key` field of the operator.

### Account server

The plugin can be configured to act as an account server for a target NATS cluster. This includes both
pushing deletions and updates to account JWTs to the target cluster, as well as responding to account lookup requests
by the NATS cluster. The plugin only supports clusters using the [NATS based resolver](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/jwt/resolver#nats-based-resolver), *not* the legacy URL resolver.

Account server behavior is controlled via the `account-servers` resource.

The simplest account server specifies a target NATS cluster url:

```sh
$ bao write nats/account-servers/my-operator servers="nats://localhost:4222"
```

> [!IMPORTANT]
> Creating the account server requires the operator to have a system account configured.

Once created, any issued account JWTs will be immediately pushed to the target NATS cluster.
The modifications that result in an update include:

- Updating the account claims
- Adding, removing, or updating account imports
- Adding, removing, or updating account signing keys,
- Adding, removing, or updating revocations

Account deletions will be pushed to the NATS server as well.

If a NATS server makes a request for an account JWT, which it will do if it does not
contain a local copy of the JWT, or if its cached JWT has expired, the account server
may respond with the account JWT.

These behaviors can be [customized](#selectively-disabling-account-server-behavior).

#### Suspend the account server

If desired, sync behavior may be paused at any time by setting `suspend=true`:

```sh
$ bao write nats/account-servers/my-operator suspend=true
```

However, changes to the operator JWT will also result in the account server being suspended. This is because
changes to the operator JWT must be manually updated in the target NATS cluster config. For example,
if the operator's signing keys were to be rotated, and all accounts were therefore resigned 
with those new keys, pushing the resigned accounts to a NATS cluster with an out of date operator JWT
would result in the accounts becoming unable to be validated.

If a change results in suspending the account server, a warning will be emitted in the response. Once the NATS
server has been brought up to date with the new operator, the account server may be resumed at any time by
disabling the suspension:

```sh
$ bao write nats/account-servers/my-operator suspend=false
```

#### Selectively disabling account server behavior

If desired, specific behaviors of the account server may be disabled:

- `disable_lookups`: If `true`, the account server will not respond to requests for account JWTs from the NATS cluster.
- `disable_updates`: If `true`, the account server will not send updates when account JWTs are created or reissued.
- `disable_deletes`: If `true`, the account server will not send deletions when accounts are deleted.

If all three of these fields are set to `true`, it is functionally equivalent to setting `suspend` to true and the account server
will not run at all.

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

The claims object may contain any valid account JWT claims. To be specific, you may provide any of the
values under the `nats` section of an issued JWT. The `iss`, `jti`, `name`, and other root fields of the
JWT are fixed and cannot be customized. However, some additional field values are calculated when the 
JWT is signed and will always be overwritten/modified:

1. If you've created any [account signing keys](#account-signing-keys), 
   those keys will be merged with the existing list of signing keys.
2. `type` and `version` are set by the NATS jwt library and can't be modified.

<details>
<summary>Example claims with all fields</summary>

> [!NOTE]
> Some fields may be mutually incompatible in a real JWT,
> and will result in a validation error.

```json
{
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
```

</details>

### Account signing keys

This plugin supports declarative signing keys (both scoped and non-scoped) for accounts.

### Account imports

This plugin supports declarative imports for accounts. 
A named import represents logically grouped lists of import claims. These imports are merged into the 
list of imports on the account claim whenever the account JWT is reissued.

When creating an account import, you must specify at least one import claim or the request will be rejected.

For convenience when using the CLI, the details for a single import may be passed as parameters.
For example:

```sh
$ bao write nats/account-imports/my-operator/my-account/inline-import account=A1234 subject=foo.bar type=service
``` 

- imports presently require the account public key
  - this can be retrieved from the `nats/account-keys/:op/:acc` path
- at least one import must be specified or the request is rejected.
- import shape example

### Account revocations

This plugin supports declarative revocations for accounts.
Revocations may have TTLs and their lifecycle will automatically be
managed by OpenBao.

Revocations are created by writing a user id (ie. the user's public key) to the [`nats/revocations`](./api.md#createupdate-a-revocation) path.
User ids may be retrieved via the [`nats/user-nkeys`](./api.md#read-user-key) path. 

To create a revocation with a TTL, use the `ttl` parameter:

```sh
$ bao write nats/revocations/my-operator/my-account/U1234 ttl=60s
```

The `ttl` of a revocation represents a **minimum** TTL. Expired revocations will be deleted during the next
periodic sweep. If no `ttl` is specified, the revocation will never expire.

Writing to a revocation that already exists will refresh its creation time to the present time,
effectively refreshing its TTL.

Since every revocated user id is listed in the account JWT, it's recommended to keep revocations to a minimum.
If you foresee the need to revoke many user or ephemeral user credentials at once, it is best to use an [account signing key](#account-signing-keys)
that can be [rotated](#account-signing-key-rotation), effectively revoking all users simultaneously without requiring individual revocation entries.

### Exports and activation tokens

This plugin does not presently support declarative exports or declarative activation tokens.
You may still pull accounts from your cluster using [nsc](https://docs.nats.io/using-nats/nats-tools/nsc) and generate activation tokens manually,
then pass the tokens via the target account imports (or directly in the account's claims).

## Users and ephemeral users

This plugin supports two flavors of user: standard and ephemeral.
Unlike operators and accounts, user JWTs/credentials are not created when the user is created.
Rather, a fresh JWT is generated and signed whenever credentials are requested.

### Standard users

Standard users consist of a claims template and an identity key. The claims template is used when generating
credentials, and the identity key is passed along with the credentials to prove identity when connecting to NATS.

### Ephemeral users

Ephemeral users also define a claims template. Unlike standard users, however, ephemeral users don't store 
a persistent identity key. Instead, a unique identity key is generated for each credentials request. Ephemeral users 
are especially useful when issuing credentials in untrusted contexts, as the secret identity key is never reused.

Ephemeral users can also be used to template permissions and limits for a large number of unique entities
while keeping the footprint within OpenBao small. Ephemeral user credentials are given a session name as part of the path.
This name can be used to correlate credentials together. For instance, a single ephemeral user called 'all-users'
can be used to generate credentials for any registered user in a system by passing the application-specific username
as the session name. If standard users were used for this purpose, a user entry would need to be created within OpenBao 
for every registered user.

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

1. `issuer_account` is always overwritten with the account public key if using a signing key, or cleared otherwise.
2. `type` and `version` are defined by the library and may not be modified.

Most fields need not be specified under normal circumstances. It is important to
specify the pub/sub permissions and limits under the 
`pub`, `sub`, `resp`, `subs`, `data`, and `payload`
fields, or the generated user won't have permissions to do anything.

<details>
<summary>Example claims with all fields</summary>

```json
{
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
```
</details>

### Revoking user credentials

Requesting user credentials also issues a lease that is valid for the ttl of the generated credentials.
Credential leases are non-renewable and the lease time can't be shortened.

If left untouched, a lease that expires will result in a noop, as the JWT will naturally expire at that time.

However, credential leases may also be revoked prematurely. Revoking a credential prematurely results in a 
revocation entry being created for the user identity key. The revocation will have a TTL of the remaining TTL
of the JWT. For standard users, it is not possible to revoke a *specific* set of credentials. Since revocations
are keyed to the identity key, revoking one lease will revoke *all* credentials for that user for the period.

Due to this behavior, it may make more sense to revoke all active leases for a user at once by using the `sys/leases/revoke-prefix`
endpoint. When revoking all leases for a user, the created revocation will adopt the longest remaining TTL of all
outstanding credentials.

> [!NOTE]
> The account revocations created by lease revocations are the same as those created using the `nats/revocations/` endpoint.
> If revoking a lease for a user that is already revoked, the revocation will be overwritten if the new expiration time is later.

Account revocations created by lease revocations will be cleaned up automatically at the end of their TTL, meaning
that the user will no longer be revoked. After that point, if it is desired that the user remains 'disabled', don't issue
new credentials for that user.

Upon deleting a user, if the user has `revoke_on_delete` enabled, a revocation will be created for that user with a
TTL equal to the maximum possible TTL of the user.

### Revoking ephemeral user credentials

As ephemeral users don't have a fixed identity, it's not possible to fetch identity keys for an ephemeral user
to revoke them using the account revocation feature directly. Instead, the ephemeral user can be revoked using the
OpenBao `sys/leases/revoke-prefix` endpoint or the `bao lease revoke -prefix` command.

> [!IMPORTANT]
> For ephemeral users, each non-expired credential issued results in an entry within the owning account's JWT.
> If you need to revoke a large amount of credentials at once, it may be more efficient to sign the ephemeral users
> with an account signing key, and rotate the signing key instead.
> It is best practice to sign user credentials with dedicated signing keys instead of account identity keys.
>
> The number of revocations necessary can be minimized by keeping credential TTLs short and refreshing more often.

For example, if your ephemeral user is configured on the path `nats/ephemeral-users/my-operator/my-account/my-user`,
you can revoke all active sessions for that user:

**CLI:**

```sh
$ bao lease revoke -prefix nats/ephemeral-creds/my-operator/my-account/all-users
```

**API:**

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    http://127.0.0.1:8200/v1/sys/leases/revoke-prefix/nats/ephemeral-creds/my-operator/my-account/my-user
```

Or revoke a specific session name:

**CLI:**

```sh
$ bao lease revoke -prefix nats/ephemeral-creds/my-operator/my-account/all-users/my-session
```

**API:**

```sh
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    http://127.0.0.1:8200/v1/sys/leases/revoke-prefix/nats/ephemeral-creds/my-operator/my-account/my-user/my-session
```

Since the `sys/leases/revoke-prefix` requires the `sudo` capability, policies granting the capability should be kept as specific as possible. For example, the following policy would only allow revoking of a specific ephemeral user's
credentials.

```hcl
path "sys/leases/revoke-prefix/nats/ephemeral-creds/my-operator/my-account/all-users/*" {
    capabilities = ["sudo"]
}
```

## Key rotation

### Operator key rotation

```sh
$ bao write -force=true nats/rotate-operator/my-operator
```

<!-- todo add blurbs about modifying operator jwts and pausing account server -->

### Operator signing key rotation

```sh
$ bao write -force=true nats/rotate-operator-signing-key/my-operator/my-signing-key
```

<!-- todo add blurbs about modifying operator jwts and pausing account server -->

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

By default, rotating a user identity key will automatically revoke the old identity key. The revocation will
have a TTL of the maximum TTL of the user's credentials. This behavior can be disabled by passing
`revoke=false`.

<!-- todo add blurbs about modifying user jwts & revoking modifying account jwts -->

Ephemeral users do not have fixed identity keys and so cannot be rotated. Instead, ephemeral user sessions 
can be revoked using [the OpenBao lease system](#revoking-ephemeral-user-credentials).