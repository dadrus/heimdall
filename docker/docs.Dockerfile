FROM uwebarthel/asciidoctor:1.95.1@sha256:6c5d8a2b20f2a46f1ebe9cb1d1a97a0427e941afa736e7f27c1c8c9d72d77353
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028,DL3018
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    hugo npm && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

RUN adduser -u 1000 -D docs
USER docs

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]
