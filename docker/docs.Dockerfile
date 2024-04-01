FROM uwebarthel/asciidoctor:1.69.0@sha256:8d7f40d0c995f515f23f413761008c3077d22c1a562cf64321359172131d5a29
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community hugo && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]