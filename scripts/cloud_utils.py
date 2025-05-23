import sys
import subprocess
import json
import tempfile

def run(cmd):
    print(f"[RUN] {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def allocate_floating_ip(tag):
    output = subprocess.check_output("openstack floating ip list -f json", shell=True)
    fips = json.loads(output.decode())
    for fip in fips:
        if fip["Port"] is None:
            return fip["Floating IP Address"]
    out = subprocess.check_output("openstack floating ip create ext-net -f value -c floating_ip_address", shell=True)
    return out.decode().strip()

def create_vm(name, image, flavor, net, secgroup, key, userdata, tag, assign_ip=False):
    try:
        imgId = subprocess.check_output(
            f"openstack image list -f json | jq -r '.[] | select(.Name == \"{image}\") | .ID'",
            shell=True
        ).decode().strip()
    except subprocess.CalledProcessError:
        print(f"[-] Error: Image '{image}' not found.")
        sys.exit(1)

    if not imgId:
        print(f"[-] Error: Image ID for '{image}' is empty.")
        sys.exit(1)
    cmd = f"openstack server create --image {imgId} --flavor {flavor} --boot-from-volume 10 --network {net} --security-group {secgroup} --key-name {key} --user-data {userdata} --property tag={tag} --wait {name}"
    run(cmd)
    if assign_ip:
        ip = allocate_floating_ip(tag)
        run(f"openstack server add floating ip {name} {ip}")
        return ip
    return None

def get_required_node_count():
    with open("servers.conf", "r") as f:
        return int(f.read().strip())

def get_current_nodes(tag):
    output = subprocess.check_output("openstack server list --long -f json", shell=True)
    servers = json.loads(output.decode())
    servers = [s for s in servers if tag in s['Name']]
    return [s["Name"] for s in servers if "-srv" in s["Name"]]

def update_haproxy_config(tag, ssh_key_file):
    print("[*] Updating HAProxy config on PROXY node...")
    output = subprocess.check_output("openstack server list --long -f json", shell=True)
    servers = json.loads(output.decode())
    servers = [s for s in servers if tag in s["Name"]]

    proxy_ip = None
    internal_ips = []

    for srv in servers:
        server_info = subprocess.check_output(f"openstack server show {srv['ID']} -f json", shell=True)
        info = json.loads(server_info.decode())
        for net in info['addresses'].split(","):
            ip = net.strip().split("=")[-1]
            if "-proxy" in srv["Name"] and "." in ip:
                proxy_ip = ip
            elif "-srv" in srv["Name"] and ip.startswith("10."):
                internal_ips.append(ip)

    if not proxy_ip:
        print("[-] No PROXY IP found.")
        return
    haproxy_cfg = """
    global
        log /dev/log    local0
        log /dev/log    local1 notice
        chroot /var/lib/haproxy
        stats socket /run/haproxy/admin.sock mode 660 level admin
        stats timeout 30s
        user haproxy
        group haproxy
        daemon
        log /dev/log local0
        maxconn 2048

    defaults
        log     global
        mode    http
        option  httplog
        option  dontlognull
        timeout connect 5000
        timeout client  50000
        timeout server  50000
        errorfile 400 /etc/haproxy/errors/400.http
        errorfile 403 /etc/haproxy/errors/403.http
        errorfile 408 /etc/haproxy/errors/408.http
        errorfile 500 /etc/haproxy/errors/500.http
        errorfile 502 /etc/haproxy/errors/502.http
        errorfile 503 /etc/haproxy/errors/503.http
        errorfile 504 /etc/haproxy/errors/504.http

    frontend service_py
        bind *:5000
        default_backend service_nodes

    backend service_nodes
        balance roundrobin
    """
    for idx, ip in enumerate(internal_ips):
        haproxy_cfg += f"\tserver srv{idx+1} {ip}:5000 check\n"
    haproxy_cfg += """
    frontend snmp_proxy
        bind *:6000
        default_backend snmp_nodes

    backend snmp_nodes
        balance roundrobin
    """
    for idx, ip in enumerate(internal_ips):
        haproxy_cfg += f"\tserver snmp{idx+1} {ip}:6000 check\n"

    with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
        f.write(haproxy_cfg)
        local_cfg_path = f.name

    remote_path = "/tmp/haproxy.cfg"
    subprocess.run(f"scp -o StrictHostKeyChecking=no -i {ssh_key_file} {local_cfg_path} ubuntu@{proxy_ip}:{remote_path}", shell=True, check=True)
    commands = f"""
        sudo mv {remote_path} /etc/haproxy/haproxy.cfg &&
        sudo haproxy -c -f /etc/haproxy/haproxy.cfg &&
        sudo systemctl restart haproxy
    """
    subprocess.run(f"ssh -o StrictHostKeyChecking=no -i {ssh_key_file} ubuntu@{proxy_ip} '{commands}'", shell=True, check=True)
    print("[+] HAProxy config updated.")

def operate_mode(tag, ssh_key, ssh_key_file):
    required = get_required_node_count()
    current = get_current_nodes(tag)
    print(f"[*] Required: {required}, Current: {len(current)}")

    image = "Ubuntu 20.04 Focal Fossa x86_64"
    flavor = "b.1c1gb"
    net = f"{tag}-net"
    secgroup = f"{tag}-secgroup"

    if len(current) < required:
        for i in range(required - len(current)):
            name = f"{tag}-srv{len(current)+i}"
            create_vm(name, image, flavor, net, secgroup, ssh_key, "scripts/userdata_service.sh", tag)
    elif len(current) > required:
        for name in reversed(current[required:]):
            run(f"openstack server delete {name}")

    update_haproxy_config(tag, ssh_key_file)

def install_mode(tag, ssh_key, ssh_key_file):
    image = "Ubuntu 20.04 Focal Fossa x86_64"
    flavor = "b.1c1gb"
    net = f"{tag}-net"
    secgroup = f"{tag}-secgroup"

    print("[*] Deploying BASTION...")
    create_vm(f"{tag}-bastion", image, flavor, net, secgroup, ssh_key, "scripts/userdata_bastion.sh", tag, assign_ip=True)

    print("[*] Deploying PROXY...")
    create_vm(f"{tag}-proxy", image, flavor, net, secgroup, ssh_key, "scripts/userdata_proxy.sh", tag, assign_ip=True)

    print("[*] Deploying SERVICE nodes...")
    for i in range(3):
        create_vm(f"{tag}-srv{i}", image, flavor, net, secgroup, ssh_key, "scripts/userdata_service.sh", tag)

    update_haproxy_config(tag, ssh_key_file)

def cleanup_mode(tag):
    print("[*] Deleting all instances...")
    output = subprocess.check_output("openstack server list -f value -c ID", shell=True)
    for line in output.decode().splitlines():
        run(f"openstack server delete {line}")

    print("[*] Deleting all volumes...")
    output = subprocess.check_output("openstack volume list -f value -c ID", shell=True)
    for line in output.decode().splitlines():
        run(f"openstack volume delete {line}")

    print("[*] Deleting floating IPs...")
    output = subprocess.check_output("openstack floating ip list -f json", shell=True)
    for ip in json.loads(output.decode()):
        if ip["Port"] is None:
            run(f"openstack floating ip delete {ip['ID']}")

    print("[*] Deleting router, subnet, network, and security group...")
    run(f"openstack router remove subnet {tag}-router {tag}-subnet || true")
    run(f"openstack router delete {tag}-router || true")
    run(f"openstack subnet delete {tag}-subnet || true")
    run(f"openstack network delete {tag}-net || true")
    run(f"openstack security group delete {tag}-secgroup || true")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: cloud_utils.py <install|operate|cleanup> <tag> <ssh_key>")
        sys.exit(1)

    mode = sys.argv[1]
    tag = sys.argv[2]
    ssh_key = sys.argv[3]
    ssh_key_file = sys.argv[4]
    if mode == "install":
        install_mode(tag, ssh_key, ssh_key_file)
    elif mode == "operate":
        operate_mode(tag, ssh_key, ssh_key_file)
    elif mode == "cleanup":
        cleanup_mode(tag)
    else:
        print(f"Unknown mode: {mode}")
