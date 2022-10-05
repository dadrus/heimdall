# syntax = docker/dockerfile:experimental
# Builder image to build the app
FROM --platform=$BUILDPLATFORM golang:1.19.2-buster as builder
LABEL maintainer=dadrus@gmx.de

ARG TARGETARCH
ARG VERSION="unknown"

ENV USER=heimdall
ENV UID=10001

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN useradd -l -s "/sbin/nologin" -M -U -r -u ${UID} ${USER}

WORKDIR /build

COPY . .
RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-buildid= -w -s -X github.com/dadrus/heimdall/cmd.Version=${VERSION}"

# The actual image of the app
FROM scratch
LABEL maintainer=dadrus@gmx.de

WORKDIR /opt/heimdall

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /build/heimdall .

USER ${USER}:${USER}

ENTRYPOINT ["/opt/heimdall/heimdall"]