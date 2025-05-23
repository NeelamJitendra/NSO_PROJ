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
import flask 
import socket
import time
import random

h_name = socket.gethostname()
IP_addres = socket.gethostbyname(h_name)
app = flask.Flask(__name__)

@app.route('/')
def index():
    host = IP_addres
    client_ip = flask.request.remote_addr
    client_port = str(flask.request.environ.get('REMOTE_PORT'))
    hostname = h_name
    Time= time.strftime("%H:%M:%S")
    rand=str(random.randint(0,100))
    return Time+" "+client_ip + ":" +client_port +" -- " + host+" ("+hostname+") " +rand+"\n"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

pip3 install flask
nohup python3 /opt/service/service.py &

# Configure SNMPd (basic setup)
echo 'rocommunity public' > /etc/snmp/snmpd.conf
systemctl restart snmpd
