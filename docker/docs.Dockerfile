FROM uwebarthel/asciidoctor:1.75.1@sha256:c74bb133aa8f1d0ef0ec33b1e612b404e17ec00df637d96228e0de5cc182eeeb
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community hugo && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]