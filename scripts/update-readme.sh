#!/bin/bash
set -euo pipefail

IMAGE_NAME=${IMAGE_NAME:-"image name"}
TAG=${TAG:-"tag"}
BINARY_NAME=${BINARY_NAME:-"openbao-plugin-secrets-nats"}
SHA256SUM=${SHA256SUM:-"8a02d607d61450b2e23a919129486eb83856534f5aadb1ba829f1f357ad67ea8"}

delim='```'

note="> [!NOTE]
> The pre-filled sha256sum is for the linux-amd64 build.
> The value should be updated with the appropriate hash for
> your execution environment. You can find sums for all releases 
> on the [release page](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats/releases/tag/$TAG)."

declarative="$note

${delim}sh
cat << EOF > openbao-config.hcl 
plugin \"secret\" \"nats\" {
    image = \"$IMAGE_NAME\"
    version = \"$TAG\"
    binary_name = \"$BINARY_NAME\"
    sha256sum = \"$SHA256SUM\"
}

plugin_directory = \"\$HOME/openbao_plugins\" # or wherever it pleases

plugin_auto_download = true
plugin_auto_register = true
EOF
${delim}"

cli="Download the appropriate binary for your platform from the 
[release page](https://github.com/BonesOfGiants/openbao-plugin-secrets-nats/releases/tag/$TAG).
Place the downloaded and decompressed \`openbao-plugin-secrets-nats\` binary in the configured plugin directory.

In a separate terminal, register the plugin with the following command:

$note

${delim}sh
$ bao plugin register \\\\
    -version=\"$TAG\" \\\\
    -sha256=\"$SHA256SUM\" \\\\ 
    -command=\"$BINARY_NAME\" \\\\
    nats
Success! Registered plugin: nats
${delim}"

awk -v declarative="$declarative" -v cli="$cli" '
/<!-- BEGIN DECLARATIVE SAMPLE -->/ {
  print $0
	print declarative
  skip = 1
}
/<!-- END DECLARATIVE SAMPLE -->/ {
  skip = 0
}
/<!-- BEGIN CLI SAMPLE -->/ {
  print $0
	print cli
  skip = 1
}
/<!-- END CLI SAMPLE -->/ {
  skip = 0
}
!skip' README.md > README.md.tmp && mv README.md.tmp README.md