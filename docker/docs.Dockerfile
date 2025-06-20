FROM uwebarthel/asciidoctor:1.88.0@sha256:a2f8430e996aaa5478a5ab3de5306895f8ad9809f93171bb24ea4a7fca157978
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
