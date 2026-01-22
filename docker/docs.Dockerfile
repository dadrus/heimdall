FROM uwebarthel/asciidoctor:1.101.0@sha256:aeee21246fc98c979271bf6a50e0249d60be2f649604e3a069f38022593fc3ec
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
