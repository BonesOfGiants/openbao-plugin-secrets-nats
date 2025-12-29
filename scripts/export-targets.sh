#!/bin/bash
set -euo pipefail

DIR="${1:-.}"
PLUGIN_NAME="${2:-"openbao-plugin-secrets-nats"}"

re="$PLUGIN_NAME-([^-]+)-(.+)$"

csv=$(
  for f in "$DIR"/*; do
    name=$(basename $f)
    if [[ "$name" =~ $re ]]; then 
        OS=${BASH_REMATCH[1]};
        ARCH=${BASH_REMATCH[2]};
        
        echo "$OS/$ARCH"
    fi
  done | sort -u | paste -sd,
)

echo $csv
