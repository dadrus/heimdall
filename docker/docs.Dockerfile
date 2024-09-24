FROM uwebarthel/asciidoctor:1.77.0@sha256:47004b1dd559f5c74cb5b60ba5d4653c65940477efc65b16f03f6dcf3070ab48
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community hugo && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]