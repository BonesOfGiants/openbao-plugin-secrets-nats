FROM openbao/openbao:2.4.0

COPY --chown=openbao:openbao \
    build/openbao/plugins/openbao-plugin-secrets-nats-linux-amd64 \
    /etc/openbao/plugins/openbao-plugin-secrets-nats

RUN chmod +x /etc/openbao/plugins/openbao-plugin-secrets-nats

RUN (sha256sum /etc/openbao/plugins/openbao-plugin-secrets-nats | cut -d' ' -f1) \
    > /etc/openbao/plugins/openbao-plugin-secrets-nats.sha256 && \
    chown openbao:openbao /etc/openbao/plugins/openbao-plugin-secrets-nats.sha256
