# openbao-plugin-secrets-nats

This plugin provides OpenBao with a fully-managed interface for NATS JWT authentication/authorization.

## Getting Started

This is an [OpenBao plugin](https://openbao.org/docs/plugins/) and is meant to work with OpenBao. 
This guide assumes you have already installed Openbao and have a basic understanding of how OpenBao works.

Otherwise, first read this guide on how to [get started with OpenBao](https://openbao.org/docs/get-started/developer-qs/).

To learn specifically about how plugins work, see documentation on [OpenBao plugins](https://openbao.org/docs/plugins/).

## Usage

Detailed [documentation](./docs/index.md) and [API reference](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats/wiki/API#createupdate-account-configuration) are available in the repository wiki.

### Quickstart

First, make sure you have OpenBao, nats & nats-server, and jq installed and available on the path.

#### OCI Image

The best way to quickly try out this plugin is to utilize the [declarative plugin](https://openbao.org/docs/configuration/plugins/)
feature of OpenBao. This requires OpenBao to be on version `2.5.0` or higher.

Create a configuration registering the plugin:

<!-- todo: post real image tag & use semantic-release to auto-update the README -->
```sh
cat << EOF > openbao-config.hcl 
plugin "secret" "nats" {
    image = "ghcr.io/bonesofgiants/openbao-plugin-secrets-nats"
    version = "v2.1.1"
    binary_name = "openbao-plugin-secrets-nats"
    sha256sum = "dec5b2c17a4616de030d7945cf4b4eeb87c037a30e4fa3b99c2bd4502e25e1bc"
}

plugin_directory = "$HOME/openbao_plugins" # or wherever it pleases

plugin_auto_download = true
plugin_auto_register = true
EOF
```

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

Start the OpenBao server:

```sh
$ bao server -dev -config=openbao-config.hcl
```

Place the downloaded `openbao-plugin-secrets-nats` binary in the selected plugin folder.

In a separate terminal, register the plugin with the following command:

<!-- todo: post real version and sha256 & use semantic-release to auto-update the README -->
```sh
$ bao plugin register \
    -version=v2.1.1 \
    -sha256=dec5b2c17a4616de030d7945cf4b4eeb87c037a30e4fa3b99c2bd4502e25e1bc \
    -command=openbao-plugin-secrets-nats \
    nats
Success! TODO
```

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
Success! Data written to: nats/operators/dev
$ bao write -force=true nats/operators/dev/hello-app
Success! Data written to: nats/operators/dev/hello-app
$ cat << EOF | bao write nats/operators/dev/hello-app/app-user -
{
  "claims": {
    "nats": {
      "pub": {
        "allow": ["events.hello"]
      },
      "subs": -1,
      "payload": -1
    }
  }
}
EOF
Success! Data written to: nats/operators/dev/hello-app/app-user
```

Generate a server config:

```sh
$ bao read -format=json nats/generate-server-config/dev | jq '.data.config' > operator-conf.json
```

Start a nats server using the generated config:

```sh
$ nats-server -c operator-conf.json
```

Generate creds:

```sh
$ bao read nats/creds/dev/hello-app/app-user | jq -r '.data.creds' > user.creds
```

Publish to the NATS server using the credentials:
```sh
$ nats --creds=./user.creds pub events.hello "Hello world!"
15:03:16 Published 12 bytes to "events.hello"
```

<!-- todo: create developer guide -->

## Acknowledgements

Though it has been rewritten from the ground up, this plugin owes its existence 
to the [vault-plugin-secrets-nats plugin](https://github.com/edgefarm/vault-plugin-secrets-nats)
created by the original [edgefarm](https://github.com/edgefarm) team.
Furthermore, [nunu-ai](https://github.com/nunu-ai)'s modifications in their [enhanced fork](https://github.com/nunu-ai/vault-plugin-secrets-nats) 
provided the impetus for the development of this plugin.
