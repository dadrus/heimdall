# syntax = docker/dockerfile:experimental
# Builder image to build the app
# hadolint ignore=DL3006
FROM golang:1.18.1-buster as builder
LABEL maintainer=dadrus@gmx.de

ENV USER=heimdall
ENV UID=10001
RUN useradd -s "/sbin/nologin" -M -U -r -u ${UID} ${USER}

RUN apt-get update && apt-get install -y xz-utils

# UPX is GPL
ADD https://github.com/upx/upx/releases/download/v3.96/upx-3.96-amd64_linux.tar.xz /usr/local
RUN xz -d -c /usr/local/upx-3.96-amd64_linux.tar.xz | \
    tar -xOf - upx-3.96-amd64_linux/upx > /bin/upx && \
    chmod a+x /bin/upx

ARG VERSION="unknown"

WORKDIR /go/src/heimdall

COPY . .
RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -X heimdall/cmd.Version=${VERSION}"
# hadolint ignore=DL3059
ARG HOST_ARCH
RUN if [ "$HOST_ARCH" = "arm64" ] ; then echo "skipping upx on ARM" ; else upx  heimdall; fi

# The actual image of the app
# hadolint ignore=DL3007
FROM scratch
LABEL maintainer=dadrus@gmx.de

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /go/src/heimdall/heimdall /opt/heimdall/heimdall

WORKDIR /opt/heimdall

USER ${USER}:${USER}

ENTRYPOINT ["/opt/heimdall/heimdall"]