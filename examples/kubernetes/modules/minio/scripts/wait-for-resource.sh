#!/usr/bin/env sh
set -e

NAMESPACE="${namespace}"
RESOURCE_TYPE="${resource_type}"
RESOURCE_NAME="${resource_name}"
TIMEOUT_SECONDS="${timeout_seconds}"
SLEEP_INTERVAL="${sleep_interval}"

echo "Waiting for $RESOURCE_TYPE named '$RESOURCE_NAME' in Namespace '$NAMESPACE'"

elapsed=0
while [ "$elapsed" -lt "$TIMEOUT_SECONDS" ]; do
  if kubectl -n "$NAMESPACE" get $RESOURCE_TYPE "$RESOURCE_NAME" >/dev/null 2>&1; then
    echo "$RESOURCE_TYPE '$RESOURCE_NAME' has been created!"
    exit 0
  fi

  echo "$RESOURCE_NAME $RESOURCE_TYPE not yet created..."
  sleep "$SLEEP_INTERVAL"
  elapsed=$((elapsed + SLEEP_INTERVAL))
done

echo "ERROR: Timeout! $RESOURCE_TYPE '$RESOURCE_NAME' in Namespace '$NAMESPACE' was not found after waiting for $TIMEOUT_SECONDS seconds"

exit 1