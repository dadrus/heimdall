FROM uwebarthel/asciidoctor:1.91.0@sha256:44372137039b9438057ff37834cc19a7c41c6f5732d63f9a346d6b1b5f21ed64
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
