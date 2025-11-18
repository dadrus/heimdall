#!/bin/bash
set -e

IMAGE="${proxy_image}"
NAME="${container_name}"
CACHE_VOL="${cache_volume}"
CERTS_VOL="${certs_volume}"

echo "Setting up global Container Image Registry Proxy..."

# 1. Image
docker pull "$IMAGE" || true

# 2. Volumes
docker volume create "$CACHE_VOL" 2>/dev/null || echo "Cache volume exists"
docker volume create "$CERTS_VOL" 2>/dev/null || echo "Certs volume exists"

# 3. Start container if required
if docker ps --filter "name=^/$NAME$" --format '{{.Names}}' | grep -q "^$NAME$"; then
  echo "Proxy already running"
else
  echo "Starting proxy container..."
  docker run -d \
    --name "$NAME" \
    --hostname "$NAME" \
    --restart always \
    -v "$CACHE_VOL:/docker_mirror_cache" \
    -v "$CERTS_VOL:/ca" \
    -e ENABLE_MANIFEST_CACHE=true \
    "$IMAGE"

  # Wait for 15 secs until container is started
  echo "Waiting for the proxy to start..."
  for i in {1..15}; do
    if docker inspect "$NAME" --format='{{.State.Running}}' | grep -q "true"; then
      echo "Proxy started!"
      break
    fi
    if [ $i -eq 15 ]; then
      echo "ERROR: Proxy failed to start!"
      docker logs "$NAME" || true
      exit 1
    fi
    sleep 1
  done
fi