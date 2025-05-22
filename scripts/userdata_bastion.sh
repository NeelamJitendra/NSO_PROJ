#!/bin/bash
set -eux

apt update
apt install -y python3 python3-pip net-tools iputils-ping

mkdir -p /opt/bastion
cat <<EOF > /opt/bastion/monitor.py
from flask import Flask, jsonify
import os
import subprocess

app = Flask(__name__)
NODES_FILE = "/opt/bastion/nodes.txt"

@app.route("/status")
def status():
    results = {}
    with open(NODES_FILE) as f:
        for line in f:
            ip = line.strip()
            try:
                subprocess.check_output(["ping", "-c", "1", "-W", "1", ip], stderr=subprocess.DEVNULL)
                results[ip] = "up"
            except subprocess.CalledProcessError:
                results[ip] = "down"
    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
EOF

# Dummy list of internal node IPs (replace/update later)
cat <<EOF > /opt/bastion/nodes.txt
10.0.0.11
10.0.0.12
10.0.0.13
EOF

pip3 install flask
nohup python3 /opt/bastion/monitor.py &
