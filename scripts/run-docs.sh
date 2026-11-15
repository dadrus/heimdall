#!/bin/bash
set -euo pipefail

git config --global --add safe.directory /opt/heimdall
npm ci
mkdir -p /tmp/heimdall-doc-versions
../scripts/generate-doc-versions.sh > /tmp/heimdall-doc-versions/data.json
hugo serve -D --config config.yaml,config.local.yaml --bind 0.0.0.0 --logLevel debug --noHTTPCache --disableFastRender -d /tmp/heimdall-docs-build