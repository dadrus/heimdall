
FROM uwebarthel/asciidoctor:1.106.0@sha256:697efb70631d7a87aa2955aa79c2a8101f1bae455e4bb5026475e5d67769848e
LABEL maintainer=dadrus@gmx.de

ARG HUGO_VERSION=0.170.0
ARG DART_SASS_VERSION=1.108.2
ARG TARGETARCH

# hadolint ignore=DL3028,DL3018
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    npm curl && fc-cache -f && \
    gem install asciidoctor-html5s

# Install Hugo from the official GitHub release.
RUN set -eux; \
    curl -fsSL \
      "https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_${HUGO_VERSION}_linux-${TARGETARCH}.tar.gz" \
      -o /tmp/hugo.tar.gz; \
    tar -xzf /tmp/hugo.tar.gz -C /usr/local/bin hugo; \
    rm /tmp/hugo.tar.gz; \
    hugo version

# Install standalone Dart Sass for Alpine (musl).
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) dart_arch=x64 ;; \
      arm64) dart_arch=arm64 ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL \
      "https://github.com/sass/dart-sass/releases/download/${DART_SASS_VERSION}/dart-sass-${DART_SASS_VERSION}-linux-${dart_arch}-musl.tar.gz" \
      -o /tmp/dart-sass.tar.gz; \
    tar -xzf /tmp/dart-sass.tar.gz -C /opt; \
    rm /tmp/dart-sass.tar.gz; \
    /opt/dart-sass/sass --version

ENV PATH="/opt/dart-sass:${PATH}"

COPY scripts/run-docs.sh /run-docs.sh

RUN adduser -u 1000 -D docs
USER docs

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]
