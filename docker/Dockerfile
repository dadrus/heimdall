# syntax = docker/dockerfile:experimental
# Builder image to build the app
ARG USER=heimdall

FROM --platform=$BUILDPLATFORM golang:1.23.1-bookworm@sha256:1a5326b07cbab12f4fd7800425f2cf25ff2bd62c404ef41b56cb99669a710a83 as builder
ARG USER
ARG TARGETARCH
ARG VERSION="unknown"

LABEL maintainer=dadrus@gmx.de

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update & apt-get -y --no-install-recommends install tzdata
RUN useradd -l -M -U -s "/usr/sbin/nologin" -d "/nonexistent" -u 10001 ${USER}

WORKDIR /build

COPY . .
RUN go mod download && go mod verify &&\
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-buildid= -w -s -X github.com/dadrus/heimdall/version.Version=${VERSION}"

# The actual image of the app
FROM scratch
ARG USER
LABEL maintainer=dadrus@gmx.de

WORKDIR /opt/heimdall

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /build/heimdall .

USER ${USER}:${USER}

ENTRYPOINT ["/opt/heimdall/heimdall"]
