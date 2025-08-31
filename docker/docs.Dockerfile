FROM uwebarthel/asciidoctor:1.92.0@sha256:939db8d5c75bd3fea96a3e64b24851f61dbde1dad29a156c8591f82d397f466a
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    hugo=0.148.2-r0 npm=11.3.0-r0 && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

RUN adduser -u 1000 -D docs
USER docs

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]
