FROM uwebarthel/asciidoctor:1.84.0@sha256:cbb1f6e7a0eafb96c02a0ffd158f8b9268813165ea71c53af2330d65aa8dc358
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    hugo=0.145.0-r0 npm=10.9.1-r0 && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

RUN adduser -u 1000 -D docs
USER docs

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]
