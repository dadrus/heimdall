FROM golang:1.22.3-bookworm@sha256:c2bc4ef4064059a5dbd083e573dbd5d074858130fa3f1ed14807903b71ed99f1
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
