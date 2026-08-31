FROM golang:1.27.0-trixie@sha256:df98008ecd2b0ecc9f0a94d1b07e3564a9c92b555369b33d9b5f60d0765b2db7
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
