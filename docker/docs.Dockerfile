FROM uwebarthel/asciidoctor:1.75.0@sha256:3dc2f34c81084046d3fe1b2b0c360613896acabf92a218b90b7d8e92c0740bd4
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community hugo && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]