FROM uwebarthel/asciidoctor:1.89.0@sha256:19dfd3487a01fe27d8c6ac8d09827fa05efa473bb82a54e4298c127f5f1fb88b
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    hugo=0.147.7-r1 npm=11.3.0-r0 && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

RUN adduser -u 1000 -D docs
USER docs

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]
