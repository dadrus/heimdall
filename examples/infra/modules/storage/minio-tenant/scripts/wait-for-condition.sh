#!/usr/bin/env sh
set -e

kubectl wait --timeout=${timeout_seconds}s --for=condition=${condition} -n ${namespace}