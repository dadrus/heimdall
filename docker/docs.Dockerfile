FROM uwebarthel/asciidoctor:1.102.0@sha256:716d5ec8eda3a880196e4e7cf084f11f1d7bc0cd8044ba9df9a102ab0cab19f2
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
