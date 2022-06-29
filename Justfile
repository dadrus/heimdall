default:
  @just --list

build:
  #!/usr/bin/env bash
  git_ref=$(git rev-parse --short HEAD)
  go build -trimpath -ldflags="-buildid= -w -s -X github.com/dadrus/heimdall/cmd.Version=${git_ref}"

build-docker:
  #!/usr/bin/env bash
  git_ref=$(git rev-parse --short HEAD)
  docker build --build-arg VERSION=${git_ref} -t heimdall:local -f docker/Dockerfile .
