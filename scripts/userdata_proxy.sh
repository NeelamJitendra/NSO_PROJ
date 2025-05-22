#!/bin/bash
set -eux

apt update
apt install -y haproxy socat

# Get internal IPs of service nodes
# This script assumes the list will be managed via config or updated externally
SERVICE_PORT=5000
SNMP_PORT=6000

cat <<EOF > /etc/haproxy/haproxy.cfg
global
    log /dev/log local0
    maxconn 2048

defaults
    log     global
    mode    tcp
    timeout connect 5s
    timeout client  30s
    timeout server  30s

frontend service_py
    bind *:${SERVICE_PORT}
    default_backend service_nodes

backend service_nodes
    balance roundrobin
    server srv1 10.0.0.11:${SERVICE_PORT} check
    server srv2 10.0.0.12:${SERVICE_PORT} check
    server srv3 10.0.0.13:${SERVICE_PORT} check

frontend snmp_proxy
    bind *:${SNMP_PORT}
    default_backend snmp_nodes

backend snmp_nodes
    balance roundrobin
    server snmp1 10.0.0.11:${SNMP_PORT} check
    server snmp2 10.0.0.12:${SNMP_PORT} check
    server snmp3 10.0.0.13:${SNMP_PORT} check
EOF

systemctl restart haproxy
