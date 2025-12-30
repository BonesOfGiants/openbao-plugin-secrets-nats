FROM scratch

ARG BIN
ARG PLUGIN_NAME
ARG TARGETOS
ARG TARGETARCH

COPY $BIN/$PLUGIN_NAME-$TARGETOS-$TARGETARCH /openbao-plugin-secrets-nats

ENTRYPOINT ["/openbao-plugin-secrets-nats"]
