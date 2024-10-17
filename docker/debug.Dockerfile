FROM golang:1.23.2-bookworm@sha256:2eb2527fa642a9ad1e229af63c7510121ea99638c499c87b6e24ad371e17bd9c
ENV CGO_ENABLED 1

RUN apt-get update && apt-get install -y --no-install-recommends inotify-tools=3.14-7 psmisc=23.2-1+deb10u1 \
    && rm -rf /var/lib/apt/lists/*
RUN go get github.com/go-delve/delve/cmd/dlv@v1.22.3

COPY scripts/debug-entrypoint.sh /entrypoint.sh

VOLUME /dockerdev

WORKDIR /dockerdev

ENV DELVE_PORT 40000
ENV SERVICE_NAME service

EXPOSE 8000 $DELVE_PORT

ENTRYPOINT ["/entrypoint.sh"]
