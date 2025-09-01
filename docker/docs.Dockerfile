FROM uwebarthel/asciidoctor:1.93.0@sha256:cd080a37ba2041ffc48d2b9fc0d81d58d2e7ddbf8f8119e057e43de21df4bbbb
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    hugo=0.148.2-r1 npm=11.5.2-r0 && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

RUN adduser -u 1000 -D docs
USER docs

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]
