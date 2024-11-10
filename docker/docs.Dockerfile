FROM uwebarthel/asciidoctor:1.79.0@sha256:a24f3fa5b62eaaadde81c067eed9880e9e00f4961dcfe3e85186843c041a7f2c
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
        hugo=0.135.0-r0 npm=10.8.3-r1 && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

RUN adduser -u 1000 -D docs
USER docs

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]