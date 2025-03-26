FROM uwebarthel/asciidoctor:1.83.0@sha256:17a5b46d46c6214ea436fa8a3d675740f8b7d49f8d1a9a93d25b659b91663f7b
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