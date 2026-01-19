# openbao-plugin-secrets-nats

This plugin provides OpenBao with a declarative interface for NATS JWT authentication/authorization.

## Getting Started

This is an [OpenBao plugin](https://openbao.org/docs/plugins/) and is meant to work with OpenBao.
This guide assumes you have already installed Openbao and have a basic understanding of how OpenBao works.

Otherwise, first read this guide on how to [get started with OpenBao](https://openbao.org/docs/get-started/developer-qs/).

To learn specifically about how plugins work, see documentation on [OpenBao plugins](https://openbao.org/docs/plugins/).

## Usage

Detailed [documentation](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats/wiki) and [API reference](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats/wiki/API) are available in the repository wiki.

### Quickstart

First, make sure you have OpenBao, nats & nats-server, and jq installed and available on the path.

#### OCI Image

The best way to quickly try out this plugin is to utilize the [declarative plugin](https://openbao.org/docs/configuration/plugins/)
feature of OpenBao. This requires OpenBao to be on version `2.5.0` or higher. If on a lower version, or if you want to register the plugin manually, follow the [manual registration instructions](#manual-registration) instead.

Create a configuration registering the plugin:

<!-- BEGIN DECLARATIVE SAMPLE -->
> [!NOTE]
> The pre-filled sha256sum is for the linux-amd64 build.
> The value should be updated with the appropriate hash for
> your execution environment. You can find sums for all releases 
> on the [release page](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats/releases/tag/v1.3.2).

```sh
cat << EOF > openbao-config.hcl 
plugin "secret" "nats" {
    image = "ghcr.io/bonesofgiants/openbao-plugin-secrets-nats"
    version = "v1.3.2"
    binary_name = "openbao-plugin-secrets-nats"
    sha256sum = "f35b702fa46218942df9dc991ca08c1c2bc6bdec9013b935a85f2e8cf64a4000"
}

plugin_directory = "$HOME/openbao_plugins" # or wherever it pleases

plugin_auto_download = true
plugin_auto_register = true
EOF
```
<!-- END DECLARATIVE SAMPLE -->

Start OpenBao with the configuration: 

```sh
$ bao server -dev -config=openbao-config.hcl
```

#### Manual registration

On OpenBao versions below `2.5.0`, the plugin may be registered using the OpenBao CLI.

Create a configuration:

```sh
$ cat << EOF > openbao-config.hcl 
plugin_directory = "$HOME/openbao_plugins" # or wherever it pleases
EOF
```

In a new terminal, start the OpenBao server:

```sh
$ bao server -dev -config=openbao-config.hcl
```

<!-- BEGIN CLI SAMPLE -->
Download the appropriate binary for your platform from the 
[release page](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats/releases/tag/v1.3.2).
Place the downloaded and decompressed `openbao-plugin-secrets-nats` binary in the configured plugin directory.

In a separate terminal, register the plugin with the following command:

> [!NOTE]
> The pre-filled sha256sum is for the linux-amd64 build.
> The value should be updated with the appropriate hash for
> your execution environment. You can find sums for all releases 
> on the [release page](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats/releases/tag/v1.3.2).

```sh
$ bao plugin register \
    -version="v1.3.2" \
    -sha256="f35b702fa46218942df9dc991ca08c1c2bc6bdec9013b935a85f2e8cf64a4000" \ 
    -command="openbao-plugin-secrets-nats" \
    nats
Success! Registered plugin: nats
```
<!-- END CLI SAMPLE -->

#### Creating your first user

Once the configuration is deployed, you can mount the plugin in a separate terminal:

```sh
$ export BAO_ADDR='http://127.0.0.1:8200'
$ bao secrets enable nats
Success! Enabled the nats secrets engine at: nats/
```

Create an operator, account, and user:

```sh
$ bao write -force=true nats/operators/dev
$ bao write -force=true nats/accounts/dev/hello-app
$ cat << EOF | bao write nats/users/dev/hello-app/app-user -
{
  "claims": {
    "pub": {
      "allow": ["events.hello"]
    }
  }
}
EOF
```

Generate a server config:

```sh
$ bao read -format=json nats/generate-server-config/dev include_resolver_preload=true | jq -r '.data.config' > operator.conf
```

Include the generated config into your main nats config:

```sh
$ cat << EOF > nats-server.conf
include ./operator.conf

resolver: {
  type: "full"
  dir: "./jwt"
}
EOF
```

In a new terminal, start a nats server using the generated config:

```sh
$ nats-server -c nats-server.conf
```

Generate creds:

```sh
$ bao read -format=json nats/creds/dev/hello-app/app-user | jq -r '.data.creds' > user.creds
```

Publish to the NATS server using the credentials:
```sh
$ nats --server=0.0.0.0:4222 --creds=./user.creds pub events.hello 'Hello world!'
15:03:16 Published 12 bytes to "events.hello"
$ nats --server=0.0.0.0:4222 --creds=./user.creds pub events.goodbye 'Goodbye world!'
nats: error: nats: permissions violation: Permissions Violation for Publish to "events.goodbye"
```

#### Automatically syncing account changes

Set up an account server for the operator:

```sh
$ bao write nats/account-servers/dev servers="0.0.0.0:4222"
# Validate that the account server is active with no errors
$ bao read -format=json nats/account-servers/dev | jq '.data.status'
{
  "last_status_change": 1765874985,
  "status": "active"
}
```

Modify the account to limit payload size to 6 bytes:

```sh
$ cat << EOF | bao write nats/accounts/dev/hello-app -
{
  "claims": {
    "limits": {
      "payload": 6
    }
  }
}
EOF
```

Now attempt to write using the same user creds as before. The NATS server has automatically
been updated to use the new payload limit:

```sh
$ nats --server=0.0.0.0:4222 --creds=./user.creds pub events.hello 'Hello world!'
nats: error: nats: Maximum Payload Violation
$ nats --server=0.0.0.0:4222 --creds=./user.creds pub events.hello 'Hello!'
15:03:16 Published 6 bytes to "events.hello"
```

<!-- todo: create developer guide -->

## Acknowledgements

Though it shares no code with its progenitor, this plugin owes its existence 
to the [vault-plugin-secrets-nats plugin](https://github.com/edgefarm/vault-plugin-secrets-nats)
created by the original [edgefarm](https://github.com/edgefarm) team.
Furthermore, [nunu-ai](https://github.com/nunu-ai)'s [enhanced fork](https://github.com/nunu-ai/vault-plugin-secrets-nats) 
added the 'dynamic credentials' feature that inspired the development of this plugin.
