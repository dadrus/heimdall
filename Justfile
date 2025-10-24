default:
  @just --list

check-licenses:
  go-licenses check --disallowed_types=forbidden,restricted,reciprocal,permissive,unknown .

lint-api:
  redocly lint

lint-code:
  golangci-lint run

lint-dockerfile:
  hadolint docker/Dockerfile
  hadolint docker/debug.Dockerfile

lint-helmchart:
  #!/usr/bin/env bash

  helm lint ./charts/heimdall
  helm template --set crds.enabled=true ./charts/heimdall > /tmp/decision-config.yaml
  helm template --set crds.enabled=true --set operationMode=proxy ./charts/heimdall > /tmp/proxy-config.yaml
  kubeconform \
    -schema-location default \
    -schema-location "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master/{{{{ .NormalizedKubernetesVersion }}/{{{{ .ResourceKind }}.json" \
    --skip RuleSet -kubernetes-version 1.31.0 /tmp/decision-config.yaml
  kubeconform \
    -schema-location default \
    -schema-location "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master/{{{{ .NormalizedKubernetesVersion }}/{{{{ .ResourceKind }}.json" \
    --skip RuleSet -kubernetes-version 1.31.0 /tmp/proxy-config.yaml
  rm /tmp/decision-config.yaml
  rm /tmp/proxy-config.yaml

lint: check-licenses lint-api lint-code lint-dockerfile lint-helmchart

dependencies:
  go mod tidy
  go mod download
  go mod verify

test-chart:
  helm unittest ./charts/heimdall

test: dependencies
  go test -v -coverprofile=coverage.cov -coverpkg=./... ./...

test-all: lint test-chart test

coverage: test
  go tool cover -html coverage.cov

build: dependencies
  #!/usr/bin/env bash
  git_ref=$(git rev-parse --short HEAD)
  CGO_ENABLED=0 go build -trimpath -ldflags="-buildid= -w -s -X github.com/dadrus/heimdall/version.Version=${git_ref}"

build-image:
  #!/usr/bin/env bash
  git_ref=$(git rev-parse --short HEAD)
  docker build --build-arg VERSION=${git_ref} -t heimdall:local -f docker/Dockerfile .

build-docs-debug-image:
  #!/usr/bin/env bash
  docker build -t heimdall-docs:local -f docker/docs.Dockerfile .

run-docs: build-docs-debug-image
  #!/usr/bin/env bash
  docker run -ti --rm -p 1313:1313 -v ./:/opt/heimdall heimdall-docs:local
