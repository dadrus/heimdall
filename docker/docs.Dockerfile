FROM uwebarthel/asciidoctor:1.106.0@sha256:77ff82824cbc0991e0ccc3d64c317eb4d2546de1b2e06b4b11f431e73886fff6
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
