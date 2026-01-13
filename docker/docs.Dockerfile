FROM uwebarthel/asciidoctor:1.96.0@sha256:2fd1115acb7aa15359bedfb91b9233ff7276d69caf371ae5bea3cd169a850f6d
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
