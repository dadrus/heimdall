#!/bin/bash
set -e

SETUP_URL="http://${proxy_host}:${proxy_port}/setup/systemd"
PROBE_NODE=$(kind get nodes --name "${cluster_name}" | head -1)

echo "Waiting for the proxy: $SETUP_URL (over $PROBE_NODE)..."
timeout 30 bash -c "
  until docker exec \"$PROBE_NODE\" curl -sSf '$SETUP_URL' >/dev/null; do
    echo '  → Not ready. Waiting...'
    sleep 2
  done
"
echo "Proxy is online!"

pids=""
for NODE in $(kind get nodes --name "${cluster_name}"); do
  echo "  → Configuring $NODE..."
  (
      docker exec "$NODE" sh -c "\
        curl -sS '$SETUP_URL' | \
        sed 's|docker\\.service|containerd\\.service|g' | \
        sed '/Environment/ s/$/ \"NO_PROXY=127.0.0.0\\/8,10.0.0.0\\/8,172.16.0.0\\/12,192.168.0.0\\/16\"/' | \
        bash" || exit 1
  ) & pids="$pids $!"
done

for pid in $pids; do
  wait "$pid" || exit 1
done

echo "All nodes successfully configured."