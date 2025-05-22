# Builder image to build the app
ARG USER=heimdall

FROM --platform=$BUILDPLATFORM golang:1.24.3-bookworm@sha256:030fb56fc7d01d1400e90e4548f97454b8f2af842fe3f67cd43a3c7587fe34d7 AS builder
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
