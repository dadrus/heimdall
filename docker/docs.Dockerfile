FROM uwebarthel/asciidoctor:1.81.0@sha256:a151b591c06d47a480cf2694a98913a01f28f660d6faa8df13dc6b5b1ad38b4c
LABEL maintainer=dadrus@gmx.de

# hadolint ignore=DL3028
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    hugo=0.135.0-r0 npm=10.8.3-r1 && fc-cache -f && \
    gem install asciidoctor-html5s

COPY scripts/run-docs.sh /run-docs.sh

RUN adduser -u 1000 -D docs
USER docs

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]