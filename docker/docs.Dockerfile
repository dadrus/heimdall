FROM uwebarthel/asciidoctor:1.68.0@sha256:0cb3daa79064b0393b78f48ec3a7caf1301592d0960f43ccadac4e11ee10ad9d
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community hugo && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]