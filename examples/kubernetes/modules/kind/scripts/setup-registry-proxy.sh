#!/bin/bash
set -e

IMAGE="${proxy_image}"
NAME="${container_name}"
CACHE_VOL="${cache_volume}"
CERTS_VOL="${certs_volume}"

echo "Setting up global Container Image Registry Proxy..."

docker volume create "$CACHE_VOL" 2>/dev/null || echo "Cache volume exists"
docker volume create "$CERTS_VOL" 2>/dev/null || echo "Certs volume exists"

if docker ps --filter "name=^/$NAME$" --format '{{.Names}}' | grep -q "^$NAME$"; then
  echo "Proxy already running"
  exit 0
fi

if docker ps -a --filter "name=^/$NAME$" --format '{{.Names}}' | grep -q "^$NAME$"; then
  echo "Container exists but is not running → starting it..."
  docker start "$NAME"
else
  echo "Container does not exist → creating and starting new one..."
  docker run -d \
    --name "$NAME" \
    --hostname "$NAME" \
    --restart always \
    -v "$CACHE_VOL:/docker_mirror_cache" \
    -v "$CERTS_VOL:/ca" \
    -e ENABLE_MANIFEST_CACHE=true \
    "$IMAGE"
fi

echo "Waiting for proxy to be healthy..."
for i in {1..15}; do
  if docker inspect "$NAME" --format='{{.State.Running}}' | grep -q "true"; then
    echo "Proxy is up and running!"
    exit 0
  fi
  sleep 1
done

echo "ERROR: Proxy failed to start within 15s"
docker logs "$NAME"
exit 1
