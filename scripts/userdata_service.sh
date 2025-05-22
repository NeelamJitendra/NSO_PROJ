#!/bin/bash
set -eux

# Update and install dependencies
apt update
apt install -y python3 python3-pip snmpd

# Enable IP forwarding (optional)
sysctl -w net.ipv4.ip_forward=1

# Deploy the Python service
mkdir -p /opt/service
cat <<EOF > /opt/service/service.py
$(cat service.py)
EOF

pip3 install flask
nohup python3 /opt/service/service.py &

# Configure SNMPd (basic setup)
echo 'rocommunity public' > /etc/snmp/snmpd.conf
systemctl restart snmpd
