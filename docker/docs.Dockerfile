FROM uwebarthel/asciidoctor:1.82.0@sha256:1bab5003e21a9ad242bd94dd2800acdd526e1bb01f8ed1c3ccf4ef24a0c15114
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    hugo=0.144.0-r0 npm=10.9.1-r0 && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

RUN adduser -u 1000 -D docs
USER docs

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]
