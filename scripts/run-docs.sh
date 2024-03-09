#!/bin/bash

git config --global --add safe.directory /opt/heimdall
npm install
hugo serve -D --bind 0.0.0.0 --logLevel debug --noHTTPCache --disableFastRender -d /tmp/heimdall-docs-build