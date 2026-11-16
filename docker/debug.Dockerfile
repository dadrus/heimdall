FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d
ENV CGO_ENABLED 1

RUN apt-get update && apt-get install -y --no-install-recommends inotify-tools=3.14-7 psmisc=23.2-1+deb10u1 \
    && rm -rf /var/lib/apt/lists/*
RUN go get github.com/go-delve/delve/cmd/dlv@v1.23.6

COPY scripts/debug-entrypoint.sh /entrypoint.sh

VOLUME /dockerdev

WORKDIR /dockerdev

ENV DELVE_PORT 40000
ENV SERVICE_NAME service

EXPOSE 8000 $DELVE_PORT

ENTRYPOINT ["/entrypoint.sh"]
