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
  helm lint ./charts/heimdall
  helm template --set demo.enabled=true ./charts/heimdall > /tmp/decision-demo.yaml
  helm template --set operationMode=proxy --set demo.enabled=true ./charts/heimdall > /tmp/proxy-demo.yaml
  kubeconform --skip RuleSet -kubernetes-version 1.27.0 /tmp/decision-demo.yaml
  kubeconform --skip RuleSet -kubernetes-version 1.27.0 /tmp/proxy-demo.yaml
  rm /tmp/decision-demo.yaml
  rm /tmp/proxy-demo.yaml

lint: check-licenses lint-api lint-code lint-dockerfile lint-helmchart

dependencies:
  go mod tidy
  go mod download
  go mod verify

test: dependencies
  go test -v -coverprofile=coverage.cov -coverpkg=./... ./...

coverage: test
  go tool cover -html coverage.cov

build: dependencies
  #!/usr/bin/env bash
  git_ref=$(git rev-parse --short HEAD)
  CGO_ENABLED=0 go build -trimpath -ldflags="-buildid= -w -s -X github.com/dadrus/heimdall/version.Version=${git_ref}"

build-image:
  #!/usr/bin/env bash
  git_ref=$(git rev-parse --short HEAD)
  docker buildx build --build-arg VERSION=${git_ref} -t heimdall:local -f docker/Dockerfile .

build-docs-debug-image:
  #!/usr/bin/env bash
  docker buildx build -t heimdall-docs:local -f docker/docs.Dockerfile .

run-docs: build-docs-debug-image
  #!/usr/bin/env bash
  docker run -ti --rm -p 1313:1313 -v ./:/opt/heimdall heimdall-docs:local
