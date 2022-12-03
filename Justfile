default:
  @just --list

lint:
  golangci-lint run

test:
  go test -v -coverprofile=coverage.cov -coverpkg=./... ./...
  go tool cover -html coverage.cov

build:
  #!/usr/bin/env bash
  git_ref=$(git rev-parse --short HEAD)
  CGO_ENABLED=0 go build -trimpath -ldflags="-buildid= -w -s -X github.com/dadrus/heimdall/cmd.Version=${git_ref}"

build-image:
  #!/usr/bin/env bash
  git_ref=$(git rev-parse --short HEAD)
  docker build --build-arg VERSION=${git_ref} -t heimdall:local -f docker/Dockerfile .
