FROM golang:1.25.4-bookworm@sha256:e17419604b6d1f9bc245694425f0ec9b1b53685c80850900a376fb10cb0f70cb
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
