FROM uwebarthel/asciidoctor:1.70.0@sha256:8f4f7f21bc972a3fb1841bb210921e4adf42348592cc8b41b5934393051747eb
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community hugo && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]