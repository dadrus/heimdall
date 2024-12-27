FROM uwebarthel/asciidoctor:1.80.0@sha256:d3324ba3712e7525e57f7088e32e4c42d3f50087619d5a6a852abe89a14fe760
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