#!/bin/bash

KIND_SUBNET=$(docker network inspect kind -f "{{(index .IPAM.Config 1).Subnet}}")
METALLB_IP_START=$(echo ${KIND_SUBNET} | sed "s@0.0/16@255.200@")
METALLB_IP_END=$(echo ${KIND_SUBNET} | sed "s@0.0/16@255.250@")
METALLB_IP_RANGE="${METALLB_IP_START}-${METALLB_IP_END}"

kubectl apply -f - <<EOF
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: example
  namespace: metallb-system
spec:
  addresses:
  - ${METALLB_IP_RANGE}
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: empty
  namespace: metallb-system
EOF