FROM uwebarthel/asciidoctor:1.95.0@sha256:1ed3d195a8bbe24dce362f4be5ed99113494b374d14c41fee64754f390f1d44a
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    hugo=0.148.2-r1 npm=11.5.2-r0 && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

RUN adduser -u 1000 -D docs
USER docs

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]
