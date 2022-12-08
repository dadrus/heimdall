default:
  @just --list

lint-code:
  golangci-lint run

lint-dockerfile:
  hadolint docker/Dockerfile
  hadolint docker/debug.Dockerfile

lint-helmchart:
  helm lint ./charts/heimdall
  helm template --set demo.enable=true ./charts/heimdall > /tmp/decision-demo.yaml
  helm template --set operationMode=proxy --set demo.enable=true ./charts/heimdall > /tmp/proxy-demo.yaml
  kubeconform --skip RuleSet -kubernetes-version 1.23.0 /tmp/decision-demo.yaml
  kubeconform --skip RuleSet -kubernetes-version 1.23.0 /tmp/proxy-demo.yaml
  rm /tmp/decision-demo.yaml
  rm /tmp/proxy-demo.yaml

lint: lint-code lint-dockerfile lint-helmchart

test:
  go test -v -coverprofile=coverage.cov -coverpkg=./... ./...

coverage: test
  go tool cover -html coverage.cov

build:
  #!/usr/bin/env bash
  git_ref=$(git rev-parse --short HEAD)
  CGO_ENABLED=0 go build -trimpath -ldflags="-buildid= -w -s -X github.com/dadrus/heimdall/cmd.Version=${git_ref}"

build-image:
  #!/usr/bin/env bash
  git_ref=$(git rev-parse --short HEAD)
  docker build --build-arg VERSION=${git_ref} -t heimdall:local -f docker/Dockerfile .
