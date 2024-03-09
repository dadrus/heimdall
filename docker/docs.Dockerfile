FROM asciidoctor/docker-asciidoctor:1.62.0
LABEL maintainer=dadrus@gmx.de

ENV CHROME_BIN="/usr/bin/chromium-browser" \
    PUPPETEER_SKIP_CHROMIUM_DOWNLOAD="true" \
    PUPPETEER_EXECUTABLE_PATH="/usr/bin/chromium-browser"

# hadolint ignore=DL3018,DL3016,DL3028
RUN apk add --no-cache chromium font-noto-cjk font-noto-emoji \
        terminus-font ttf-dejavu ttf-freefont ttf-font-awesome \
        ttf-inconsolata ttf-linux-libertine npm \
        --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community hugo \
        && fc-cache -f && \
    gem install asciidoctor-html5s && \
    npm install -g @mermaid-js/mermaid-cli

COPY scripts/run-docs.sh /run-docs.sh

WORKDIR /opt/heimdall/docs

CMD ["/run-docs.sh"]