#!/bin/bash
set -e

CONTAINER="${container}"
NETWORK="${network}"

echo "Attaching $CONTAINER to network $NETWORK..."

# Check if already attached
if docker inspect "$CONTAINER" --format='{{json .NetworkSettings.Networks}}' | grep -q "$NETWORK"; then
  echo "Already attached to $NETWORK"
else
  docker network connect "$NETWORK" "$CONTAINER"
  echo "Attached successfully!"
fi