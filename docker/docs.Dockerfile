FROM uwebarthel/asciidoctor:1.74.1@sha256:1bfab98a2a857124fce5b31ee5a1fa006c91acad872d50ab539ded336e8aae11
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community hugo && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]