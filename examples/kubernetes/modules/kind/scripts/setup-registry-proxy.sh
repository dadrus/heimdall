#!/bin/bash
set -euo pipefail

IMAGE="${proxy_image}"
NAME="${container_name}"
CACHE_VOL="${cache_volume}"
CERTS_VOL="${certs_volume}"

echo "Setting up global Container Image Registry Proxy..."

if docker container inspect "$NAME" >/dev/null 2>&1; then
  current_image="$(docker container inspect --format '{{.Config.Image}}' "$NAME")"
  if [[ "$current_image" != "$IMAGE" ]]; then
    echo "ERROR: Existing registry proxy uses a different image:" >&2
    echo "  current: $current_image" >&2
    echo "  expected: $IMAGE" >&2
    echo "Remove only the container manually, then rerun the command you were using:" >&2
    echo "  docker rm -f $NAME" >&2
    echo "The registry-mirror-cache and registry-mirror-certs volumes must be kept." >&2
    exit 1
  fi

  # Never silently accept a container using a different cache or CA.
  current_cache="$(docker container inspect --format '{{range .Mounts}}{{if eq .Destination "/docker_mirror_cache"}}{{.Name}}{{end}}{{end}}' "$NAME")"
  current_certs="$(docker container inspect --format '{{range .Mounts}}{{if eq .Destination "/ca"}}{{.Name}}{{end}}{{end}}' "$NAME")"
  if [[ "$current_cache" != "$CACHE_VOL" || "$current_certs" != "$CERTS_VOL" ]]; then
    echo "ERROR: Existing registry proxy does not use the expected cache and CA volumes" >&2
    exit 1
  fi

  if [[ "$(docker container inspect --format '{{.State.Running}}' "$NAME")" == "true" ]]; then
    echo "Proxy already running with the requested image"
    exit 0
  fi

  echo "Starting existing registry proxy container..."
  docker start "$NAME" >/dev/null
else
  docker volume create "$CACHE_VOL" >/dev/null
  docker volume create "$CERTS_VOL" >/dev/null
  docker pull "$IMAGE"

  echo "Creating registry proxy container..."
  docker run -d \
    --name "$NAME" \
    --hostname "$NAME" \
    --restart always \
    -v "$CACHE_VOL:/docker_mirror_cache" \
    -v "$CERTS_VOL:/ca" \
    -e ENABLE_MANIFEST_CACHE=true \
    "$IMAGE" >/dev/null
fi

for attempt in {1..15}; do
  if [[ "$(docker container inspect --format '{{.State.Running}}' "$NAME")" == "true" ]]; then
    echo "Proxy is running"
    exit 0
  fi
  sleep 1
done

echo "ERROR: Registry proxy is not running after 15s; inspect with: docker logs --tail 40 $NAME" >&2
exit 1
