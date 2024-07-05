FROM uwebarthel/asciidoctor:1.73.0@sha256:b924bd7d9dd7c78ecf37003b561aff38d0e6b6415e2afebf9dbfae87fd0dabdb
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community hugo && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]