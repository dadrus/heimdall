FROM uwebarthel/asciidoctor:1.78.0@sha256:2b1a9b1dfc852540f66badc3081aeb1a4b302aeb7a7011497efed74c5cd2356d
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