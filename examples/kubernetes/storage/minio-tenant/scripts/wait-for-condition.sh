#!/usr/bin/env sh
set -e

kubectl --kubeconfig=${kubeconfig_path} wait --timeout=${timeout_seconds}s --for=condition=${condition} -n ${namespace}