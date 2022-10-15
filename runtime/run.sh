#!/bin/bash

# Original: https://github.com/tailscale/tailscale/blob/3b55bf93062cc513a38a3dace3f49f48d3654202/docs/k8s/run.sh
# Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

export PATH=$PATH:/tailscale/bin

TS_AUTH_KEY="${TS_AUTH_KEY:-}"
TS_DEST_IP="${TS_DEST_IP:-}"
TS_EXTRA_ARGS="${TS_EXTRA_ARGS:-}"
TS_ACCEPT_DNS="${TS_ACCEPT_DNS:-false}"
TS_KUBE_SECRET="${TS_KUBE_SECRET:-tailscale}"
TS_HOSTNAME="${TS_HOSTNAME:-}"
TSD_EXTRA_ARGS="${TSD_EXTRA_ARGS:-}"


# Set to 'true' to skip leadership election. Only use when testing against one node
#   This is useful on non x86_64 architectures, as the leader-elector image is only provided for that arch
DEBUG_SKIP_LEADER="${DEBUG_SKIP_LEADER:-false}"

set -e
set -x

TAILSCALED_ARGS="--state=kube:${TS_KUBE_SECRET} --socket=/tmp/tailscaled.sock ${TSD_EXTRA_ARGS} --statedir=/tmp/tailscaled"

if [ $(cat /proc/sys/net/ipv4/ip_forward) != 1 ]; then
  echo "IPv4 forwarding (/proc/sys/net/ipv4/ip_forward) needs to be enabled, exiting..."
  exit 1
fi

if [[ ! -d /dev/net ]]; then
  mkdir -p /dev/net
fi

if [[ ! -c /dev/net/tun ]]; then
  mknod /dev/net/tun c 10 200
fi

if [[ "${DEBUG_SKIP_LEADER}" == "true" ]]; then
  echo "CAUTION: Skipping leader election due to DEBUG_SKIP_LEADER==true."
else
  echo "Waiting for leader election..."
  LEADER=false
  while :; do
    CURRENT_LEADER=$(curl http://127.0.0.1:4040 -s -m 2 | jq -r ".name")
    if [[ "${CURRENT_LEADER}" == "$(hostname)" ]]; then
      echo "I am the leader."
      break
    fi
    sleep 1
  done
fi

echo "Starting tailscaled"
tailscaled ${TAILSCALED_ARGS} &
PID=$!

UP_ARGS="--accept-dns=${TS_ACCEPT_DNS}"
if [[ -n "${TS_AUTH_KEY}" ]]; then
  UP_ARGS="--authkey=${TS_AUTH_KEY} ${UP_ARGS}"
fi
if [[ -n "${TS_EXTRA_ARGS}" ]]; then
  UP_ARGS="${UP_ARGS} ${TS_EXTRA_ARGS:-}"
fi
if [[ -n "${TS_HOSTNAME}" ]]; then
  echo "Overriding system hostname using TS_HOSTNAME: ${TS_HOSTNAME}"
  UP_ARGS="--hostname=${TS_HOSTNAME} ${UP_ARGS}"
fi

echo "Running tailscale up"
tailscale --socket=/tmp/tailscaled.sock up ${UP_ARGS}

TS_IP=$(tailscale --socket=/tmp/tailscaled.sock ip -4)
TS_IP_B64=$(echo -n "${TS_IP}" | base64 -w 0)

# Technically can get the service ClusterIP through the <svc-name>_SERVICE_HOST variable
# but no idea how to do that in a sane way in pure Bash, so let's just get it from kube-dns
PROXY_NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
echo "Trying to get the service ClusterIP..."
SVC_IP_RETRIEVED=false
while [[ "${SVC_IP_RETRIEVED}" == "false" ]]; do
  SVC_IP=$(getent hosts ${SVC_NAME}.${SVC_NAMESPACE}.svc | cut -d" " -f1)
  if [[ -n "${SVC_IP}" ]]; then
    SVC_IP_RETRIEVED=true
  else
    sleep 1
  fi
done

apk update && apk add bind-tools caddy
FQDN=$(dig -x "${TS_IP}" +short @100.100.100.100)




# echo "Adding iptables rule for DNAT"
# iptables -t nat -I PREROUTING -d "${TS_IP}" -j DNAT --to-destination "${SVC_IP}"
# iptables -t nat -A POSTROUTING -j MASQUERADE

# PRIMARY_NETWORK_INTERFACE=$(route | grep '^default' | grep -o '[^ ]*$')
# iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o ${PRIMARY_NETWORK_INTERFACE} -j TCPMSS --set-mss 1240   

echo "Updating secret with Tailscale IP"
# patch secret with the tailscale ipv4 address
kubectl patch secret "${TS_KUBE_SECRET}" --namespace "${PROXY_NAMESPACE}" --type=json --patch="[{\"op\":\"replace\",\"path\":\"/data/ts-ip\",\"value\":\"${TS_IP_B64}\"}]"

if [[ ! -z "${TS_DEST_IP}" ]]; then
  echo "Adding iptables rule for DNAT"
  iptables -t nat -I PREROUTING -d "$(tailscale --socket=/tmp/tailscaled.sock ip -4)" -j DNAT --to-destination "${SVC_IP}"
fi


FQDN=${FQDN%?}
echo "FQDN: ${FQDN}"

tailscale --socket=/tmp/tailscaled.sock cert --key-file=key.pem --cert-file=cert.pem ${FQDN}

##make a caddyfile
cat <<EOF > Caddyfile
${FQDN} {
  tls cert.pem key.pem
  reverse_proxy ${SVC_IP}:8077
}
EOF

echo "Starting Caddy"
caddy start --config Caddyfile --adapter caddyfile





wait ${PID}