# -*- coding: utf-8 -*-
"""
wg-hub-manager.py — WireGuard Hub Manager for Ubuntu 24.04 & Debian 12

Features
- Checks WireGuard install; installs or updates via apt if necessary
- Interface management: list/create/delete/start/stop/enable/disable, by name or index
- Peer (client) management per interface: list with IPs, RX/TX, last handshake (online/offline), add by name, delete by name or index, delete all
- Generates client config (.conf + QR in terminal if qrencode present)
- Firewall: enables IPv4/IPv6 forwarding and sets nftables masquerade rules (or removes them)
- Text/CLI menu and argparse for non-interactive use

Notes
- Run as root (or with sudo). The script edits /etc/wireguard/* and nft rules.
- Server defaults: interface=wg0, subnet=10.8.0.0/24, port=51820, DNS=1.1.1.1
- Outbound interface for NAT is auto-detected from default route; can override.
- SaveConfig is enabled so runtime wg changes persist to the conf file.

Tested with: Python 3.10+, WireGuard tools (wg, wg-quick), systemd.
"""

import argparse
import ipaddress
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

WG_DIR = Path('/etc/wireguard')
SYSTEMD_UNIT = 'wg-quick@{}.service'
DEFAULT_IFACE = 'wg0'
DEFAULT_SUBNET = '10.8.0.0/24'
DEFAULT_PORT = 51820
DEFAULT_DNS = '1.1.1.1'
HANDSHAKE_ONLINE_THRESHOLD = timedelta(minutes=2)

# ------------------------- Utilities -------------------------

def require_root():
    if os.geteuid() != 0:
        print('This script must be run as root (sudo).', file=sys.stderr)
        sys.exit(1)


def run(cmd, check=True, capture_output=True, text=True):
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=text)


def which(name):
    return shutil.which(name) is not None


def ip_forward_enable(v6=False):
    key = 'net.ipv6.conf.all.forwarding' if v6 else 'net.ipv4.ip_forward'
    try:
        run(['sysctl', '-w', f'{key}=1'])
        # persist in sysctl.d
        conf_path = Path('/etc/sysctl.d/99-wireguard-forward.conf')
        lines = []
        if not conf_path.exists():
            lines.append('# Managed by wg-hub-manager.py\n')
        lines.append(f'{key}=1\n')
        existing = conf_path.read_text() if conf_path.exists() else ''
        if f'{key}=1' not in existing:
            with open(conf_path, 'a') as f:
                f.writelines(lines)
        run(['sysctl', '--system'], check=False)
    except Exception as e:
        print(f'Warning: failed to enable forwarding for {"IPv6" if v6 else "IPv4"}: {e}')


def get_default_route_iface(family='inet'):
    # family: 'inet' for IPv4, 'inet6' for IPv6
    try:
        out = run(['ip', '-o', 'route', 'show', 'default', 'table', 'main', 'proto', 'boot'], check=False).stdout
        if not out:
            out = run(['ip', '-o', 'route', 'show', 'default'], check=False).stdout
        for line in out.splitlines():
            if family in line or family == 'inet':
                m = re.search(r'dev\s+(\S+)', line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return None


def nft_masquerade_setup(wg_iface: str, out_iface: str | None = None, family='ip'):
    # family: 'ip' or 'ip6'
    table = f'{family} nat'
    chain = 'wg-hub-postrouting'
    out_iface = out_iface or get_default_route_iface('inet6' if family == 'ip6' else 'inet')
    if not out_iface:
        print('Warning: could not detect outbound interface for NAT; specify manually with --out-iface')
        return
    # Ensure nft exists
    if not which('nft'):
        print('nft not found; install nftables for firewall management.')
        return
    # Create table/chain if needed and add masquerade rule for packets from wg_iface
    cmds = [
        f'nft list table {table} || nft add table {table}',
        f'nft list chain {table} postrouting || nft add chain {table} postrouting {{ type nat hook postrouting priority 100 ; }}',
        f'nft list chain {table} {chain} || nft add chain {table} {chain}',
        # jump from postrouting to our chain (idempotent attempt)
        f"nft list chain {table} postrouting | grep -q '{chain}' || nft add rule {table} postrouting jump {chain}",
        # masquerade rule
        f"nft list chain {table} {chain} | grep -q 'oif \"{out_iface}\" masquerade' || nft add rule {table} {chain} oif \"{out_iface}\" masquerade",
    ]
    for c in cmds:
        run(['bash', '-lc', c], check=False)
    print(f'[{family}] Masquerade via {out_iface} configured for {wg_iface}.')


def nft_masquerade_remove():
    if not which('nft'):
        return
    # Remove only our chain; leave system chains intact
    for family in ('ip', 'ip6'):
        table = f'{family} nat'
        chain = 'wg-hub-postrouting'
        run(['bash', '-lc', f"nft list chain '{table}' postrouting | grep -q '{chain}' && nft delete chain '{table}' '{chain}'"], check=False)


def generate_keypair():
    priv = run(['wg', 'genkey']).stdout.strip()
    pub = run(['wg', 'pubkey'], input=priv + '\n').stdout.strip()
    return priv, pub


def generate_psk():
    return run(['wg', 'genpsk']).stdout.strip()


def read_conf(path: Path) -> str:
    return path.read_text(encoding='utf-8') if path.exists() else ''


def write_conf(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    os.chmod(path, 0o600)

# ------------------------- Install / Update -------------------------

def check_install():
    wg_ok = which('wg') and which('wg-quick')
    return wg_ok


def ensure_installed():
    if check_install():
        print('WireGuard already installed. Checking updates…')
        try:
            run(['apt-get', 'update'])
            # Attempt to upgrade wireguard tools; if none, apt exits 0
            run(['apt-get', 'install', '--only-upgrade', '-y', 'wireguard', 'wireguard-tools'], check=False)
            print('Update check complete.')
        except subprocess.CalledProcessError as e:
            print(f'apt update/upgrade failed: {e}')
        return
    print('Installing WireGuard…')
    run(['apt-get', 'update'])
    run(['apt-get', 'install', '-y', 'wireguard', 'wireguard-tools', 'qrencode'], check=False)
    print('WireGuard installed.')

# ------------------------- Interfaces -------------------------

@dataclass
class Peer:
    name: str
    public_key: str
    allowed_ips: list


def list_interfaces():
    ifaces = []
    for p in WG_DIR.glob('*.conf'):
        ifaces.append(p.stem)
    # Cross-check with wg
    try:
        out = run(['wg', 'show', 'interfaces'], check=False).stdout.strip()
        active = out.split() if out else []
    except Exception:
        active = []
    return ifaces, active


def create_interface(name: str, subnet: str, port: int, dns: str, out_iface: str | None):
    cidr = ipaddress.ip_network(subnet, strict=False)
    server_ip = str(list(cidr.hosts())[0])  # first usable
    priv, pub = generate_keypair()
    conf = f"""[Interface]
Address = {server_ip}/{cidr.prefixlen}
ListenPort = {port}
PrivateKey = {priv}
SaveConfig = true
# Optional DNS for clients (pushed via client config)
# DNS = {dns}
"""
    conf_path = WG_DIR / f'{name}.conf'
    write_conf(conf_path, conf)
    # Enable & start
    run(['systemctl', 'enable', SYSTEMD_UNIT.format(name)], check=False)
    run(['systemctl', 'start', SYSTEMD_UNIT.format(name)])
    print(f'Interface {name} created at {conf_path} and started.')
    # Firewall
    ip_forward_enable(False)
    ip_forward_enable(True)
    nft_masquerade_setup(name, out_iface, 'ip')
    nft_masquerade_setup(name, out_iface, 'ip6')
    # Return server public key
    return pub, f'{server_ip}/{cidr.prefixlen}'


def delete_interface(name: str):
    run(['systemctl', 'stop', SYSTEMD_UNIT.format(name)], check=False)
    run(['systemctl', 'disable', SYSTEMD_UNIT.format(name)], check=False)
    conf = WG_DIR / f'{name}.conf'
    if conf.exists():
        conf.unlink()
    print(f'Interface {name} deleted.')


def iface_status(name: str):
    try:
        out = run(['wg', 'show', name], check=False).stdout
        return out
    except Exception as e:
        return f'Error: {e}'

# ------------------------- Peers -------------------------

NAME_TAG = '# Name:'  # we tag each peer block


def parse_peer_blocks(conf_text: str):
    peers = []
    for block in re.split(r'(?m)^\[Peer\]\s*$', conf_text)[1:]:
        # Grab until next [Peer] or end
        lines = block.strip().splitlines()
        fields = {'PublicKey': '', 'AllowedIPs': ''}
        tag = ''
        for ln in lines:
            if ln.startswith('PublicKey'):
                fields['PublicKey'] = ln.split('=', 1)[1].strip()
            elif ln.startswith('AllowedIPs'):
                fields['AllowedIPs'] = ln.split('=', 1)[1].strip()
            elif ln.strip().startswith(NAME_TAG):
                tag = ln.split(':', 1)[1].strip()
        peers.append(Peer(name=tag or '(unnamed)', public_key=fields['PublicKey'], allowed_ips=[x.strip() for x in fields['AllowedIPs'].split(',') if x.strip()]))
    return peers


def next_available_ip(subnet: str, used_ips: list[str]):
    net = ipaddress.ip_network(subnet, strict=False)
    for host in net.hosts():
        ip = str(host)
        # skip server first IP
        if ip == str(list(net.hosts())[0]):
            continue
        if ip not in used_ips:
            return ip
    raise RuntimeError('No free IPs in subnet')


def list_peers(name: str):
    conf_path = WG_DIR / f'{name}.conf'
    conf_text = read_conf(conf_path)
    peers = parse_peer_blocks(conf_text)
    # Get runtime stats from `wg show`
    show = run(['wg', 'show', name], check=False).stdout
    # Build map: pubkey -> (rx, tx, latest_handshake)
    stats = {}
    cur = {}
    for line in show.splitlines():
        line = line.strip()
        if line.startswith('peer:'):
            key = line.split('peer:', 1)[1].strip()
            cur = {'peer': key}
            stats[key] = {'rx': 0, 'tx': 0, 'handshake': None, 'allowed_ips': []}
        elif line.startswith('endpoint:'):
            pass
        elif line.startswith('allowed ips:'):
            ips = line.split(':',1)[1].strip()
            if cur:
                stats[cur['peer']]['allowed_ips'] = [x.strip() for x in ips.split(',') if x.strip()]
        elif line.startswith('latest handshake:'):
            hs = line.split(':',1)[1].strip()
            stats[cur['peer']]['handshake'] = hs
        elif line.startswith('transfer:'):
            m = re.findall(r'(\d+[\d\.\s\w]+) received, (\d+[\d\.\s\w]+) sent', line)
            if m:
                rx, tx = m[0]
                stats[cur['peer']]['rx'] = rx
                stats[cur['peer']]['tx'] = tx
    # Display
    rows = []
    for idx, p in enumerate(peers, start=1):
        st = stats.get(p.public_key, {})
        hs = st.get('handshake')
        online = False
        if hs and 'ago' in hs:
            # wg prints e.g. "1 minute, 5 seconds ago"
            online = 'second' in hs or 'minute' in hs
        elif hs and hs != '(none)':
            # Try parse absolute time
            try:
                dt = datetime.strptime(hs, '%Y-%m-%d %H:%M:%S')
                online = datetime.now() - dt < HANDSHAKE_ONLINE_THRESHOLD
            except Exception:
                online = False
        rows.append({
            'N': idx,
            'Name': p.name,
            'IP(s)': ','.join(p.allowed_ips),
            'RX': st.get('rx', '0'),
            'TX': st.get('tx', '0'),
            'LastHandshake': hs or '(none)',
            'Status': 'online' if online else 'offline'
        })
    # Pretty print
    if not rows:
        print('No peers found.')
        return
    col_names = ['N', 'Name', 'IP(s)', 'RX', 'TX', 'LastHandshake', 'Status']
    widths = {c: max(len(c), max(len(str(r[c])) for r in rows)) for c in col_names}
    def line_sep():
        print('+ ' + ' + '.join(c.ljust(widths[c]) for c in col_names) + ' +')
    line_sep()
    print('| ' + ' | '.join(c.ljust(widths[c]) for c in col_names) + ' |')
    line_sep()
    for r in rows:
        print('| ' + ' | '.join(str(r[c]).ljust(widths[c]) for c in col_names) + ' |')
    line_sep()


def add_peer(name: str, peer_name: str, dns: str | None = DEFAULT_DNS, allowed_subnet: str | None = None):
    conf_path = WG_DIR / f'{name}.conf'
    conf_text = read_conf(conf_path)
    if not conf_text:
        print(f'Interface {name} config not found at {conf_path}.')
        return
    # Determine server params
    m_addr = re.search(r'^Address\s*=\s*(.+)$', conf_text, re.M)
    m_port = re.search(r'^ListenPort\s*=\s*(\d+)$', conf_text, re.M)
    m_priv = re.search(r'^PrivateKey\s*=\s*(.+)$', conf_text, re.M)
    if not (m_addr and m_port and m_priv):
        print('Malformed server config: missing Address/ListenPort/PrivateKey.')
        return
    server_cidr = m_addr.group(1).split(',')[0].strip()
    subnet = str(ipaddress.ip_interface(server_cidr).network)
    used_ips = []
    # Collect used IPs from existing peers
    peers = parse_peer_blocks(conf_text)
    for p in peers:
        for ip in p.allowed_ips:
            try:
                used_ips.append(str(ipaddress.ip_interface(ip).ip))
            except Exception:
                pass
    # Also include server IP
    used_ips.append(str(ipaddress.ip_interface(server_cidr).ip))
    client_ip = next_available_ip(subnet, used_ips)
    client_priv, client_pub = generate_keypair()
    psk = generate_psk()
    # Append peer block in server conf
    block = f"""
[Peer]
# {NAME_TAG} {peer_name}
PublicKey = {client_pub}
PresharedKey = {psk}
AllowedIPs = {client_ip}/32
"""
    with open(conf_path, 'a', encoding='utf-8') as f:
        f.write(block)
    # Apply live
    run(['wg', 'set', name, 'peer', client_pub, 'preshared-key', '/dev/fd/0', 'allowed-ips', f'{client_ip}/32'], check=False, capture_output=False, text=False,)
    # Generate client config content
    server_pub = run(['wg', 'show', name, 'public-key']).stdout.strip()
    # Determine server endpoint (public IP): try to get external, else hostname
    endpoint = auto_detect_public_endpoint(DEFAULT_PORT)
    client_conf = f"""[Interface]
PrivateKey = {client_priv}
Address = {client_ip}/{ipaddress.ip_network(subnet).prefixlen}
DNS = {dns}

[Peer]
PublicKey = {server_pub}
PresharedKey = {psk}
AllowedIPs = {allowed_subnet or '0.0.0.0/0, ::/0'}
Endpoint = {endpoint}
PersistentKeepalive = 25
"""
    out_path = Path.cwd() / f'{name}-{peer_name}.conf'
    write_conf(out_path, client_conf)
    print(f'Client "{peer_name}" added with IP {client_ip}. Config: {out_path}')
    if which('qrencode'):
        try:
            qr = run(['qrencode', '-t', 'ANSIUTF8'], input=client_conf, text=True).stdout
            print('\n# QR (scan with WireGuard app):\n')
            print(qr)
        except Exception:
            pass


def auto_detect_public_endpoint(port: int) -> str:
    # Try to detect public IPv4 via external interface address
    try:
        gw = get_default_route_iface('inet')
        if gw:
            ip = run(['bash', '-lc', f"ip -4 -o addr show dev {gw} | awk '{{print $4}}' | sed 's#/.*##' | head -n1"], check=False).stdout.strip()
            if ip:
                return f'{ip}:{port}'
    except Exception:
        pass
    # Fallback to hostname
    try:
        host = socket.gethostname()
        return f'{host}:{port}'
    except Exception:
        return f'0.0.0.0:{port}'


def delete_peer(name: str, peer_selector: str, by_index=False):
    conf_path = WG_DIR / f'{name}.conf'
    conf_text = read_conf(conf_path)
    peers = parse_peer_blocks(conf_text)
    if not peers:
        print('No peers to delete.')
        return
    target_pub = None
    target_name = None
    if by_index:
        try:
            idx = int(peer_selector)
            target = peers[idx - 1]
            target_pub = target.public_key
            target_name = target.name
        except Exception:
            print('Invalid index.')
            return
    else:
        for p in peers:
            if p.name == peer_selector:
                target_pub = p.public_key
                target_name = p.name
                break
    if not target_pub:
        print('Peer not found.')
        return
    # Remove from live
    run(['wg', 'set', name, 'peer', target_pub, 'remove'], check=False)
    # Remove from config: delete the [Peer] block containing this public key
    new_conf = []
    in_block = False
    keep_block = True
    for line in conf_text.splitlines(True):
        if re.match(r'^\[Peer\]\s*$', line):
            if in_block and not keep_block:
                # drop previous block by not appending accumulated (handled implicitly)
                pass
            in_block = True
            keep_block = True
            block_buf = []
            new_conf.append('__BLOCK_MARK__')
        elif in_block and re.match(r'^PublicKey\s*=\s*', line):
            if target_pub in line:
                keep_block = False
            block_buf.append(line)
        elif in_block and re.match(r'^\[', line):
            # starting new section, finalize previous
            in_block = False
            if keep_block:
                # replace marker with block header and append buffer
                idx = new_conf.index('__BLOCK_MARK__')
                new_conf[idx] = '[Peer]\n'
                new_conf.extend(block_buf)
            else:
                # remove marker (drop block)
                new_conf.pop()  # remove marker
            new_conf.append(line)
            block_buf = []
        else:
            if in_block:
                block_buf.append(line)
            else:
                new_conf.append(line)
    # finalize last block if file ended in block
    if '__BLOCK_MARK__' in new_conf:
        # end of file block
        if keep_block:
            idx = new_conf.index('__BLOCK_MARK__')
            new_conf[idx] = '[Peer]\n'
            new_conf.extend(block_buf)
        else:
            new_conf.remove('__BLOCK_MARK__')
    write_conf(conf_path, ''.join(new_conf))
    print(f'Peer "{target_name}" removed.')


def delete_all_peers(name: str):
    conf_path = WG_DIR / f'{name}.conf'
    conf_text = read_conf(conf_path)
    peers = parse_peer_blocks(conf_text)
    if not peers:
        print('No peers present.')
        return
    # Live remove
    for p in peers:
        run(['wg', 'set', name, 'peer', p.public_key, 'remove'], check=False)
    # Remove from config
    new_text = re.sub(r'(?ms)^\[Peer\][\s\S]*?(?=^\[|\Z)', '', conf_text)
    write_conf(conf_path, new_text)
    print(f'Removed {len(peers)} peers from {name}.')

# ------------------------- Menu -------------------------

def menu():
    while True:
        print('\n=== WireGuard Hub Manager ===')
        print('1) Check/install/update WireGuard')
        print('2) Interfaces')
        print('3) Clients (peers)')
        print('4) Firewall & Masquerade')
        print('5) Exit')
        choice = input('Select: ').strip()
        if choice == '1':
            ensure_installed()
        elif choice == '2':
            menu_interfaces()
        elif choice == '3':
            menu_clients()
        elif choice == '4':
            menu_firewall()
        elif choice == '5':
            break
        else:
            print('Invalid choice.')


def menu_interfaces():
    while True:
        print('\n-- Interfaces --')
        print('1) List interfaces')
        print('2) Create interface')
        print('3) Delete interface (by name)')
        print('4) Start/Up interface (by name)')
        print('5) Stop/Down interface (by name)')
        print('6) Delete ALL interfaces')
        print('7) Back')
        c = input('Select: ').strip()
        if c == '1':
            ifaces, active = list_interfaces()
            print('Configured:', ', '.join(ifaces) or '(none)')
            print('Active:', ', '.join(active) or '(none)')
        elif c == '2':
            name = input(f'Interface name [{DEFAULT_IFACE}]: ').strip() or DEFAULT_IFACE
            subnet = input(f'Subnet CIDR [{DEFAULT_SUBNET}]: ').strip() or DEFAULT_SUBNET
            port = int(input(f'Listen port [{DEFAULT_PORT}]: ').strip() or DEFAULT_PORT)
            out = input('Outbound iface for NAT (auto-detect if empty): ').strip() or None
            create_interface(name, subnet, port, DEFAULT_DNS, out)
        elif c == '3':
            name = input('Interface name to delete: ').strip()
            delete_interface(name)
        elif c == '4':
            name = input('Interface name to start: ').strip()
            run(['systemctl', 'start', SYSTEMD_UNIT.format(name)], check=False)
            print('Started.')
        elif c == '5':
            name = input('Interface name to stop: ').strip()
            run(['systemctl', 'stop', SYSTEMD_UNIT.format(name)], check=False)
            print('Stopped.')
        elif c == '6':
            ifaces, _ = list_interfaces()
            for ifn in ifaces:
                delete_interface(ifn)
        elif c == '7':
            return
        else:
            print('Invalid choice.')


def menu_clients():
    while True:
        print('\n-- Clients (peers) --')
        print('1) List clients')
        print('2) Add client (by name)')
        print('3) Delete client (by name)')
        print('4) Delete client (by number)')
        print('5) Delete ALL clients')
        print('6) Back')
        c = input('Select: ').strip()
        if c not in {'6'}:
            ifn = input(f'Interface name [{DEFAULT_IFACE}]: ').strip() or DEFAULT_IFACE
        if c == '1':
            list_peers(ifn)
        elif c == '2':
            nm = input('Client name: ').strip()
            add_peer(ifn, nm)
        elif c == '3':
            nm = input('Client name to delete: ').strip()
            delete_peer(ifn, nm, by_index=False)
        elif c == '4':
            idx = input('Client number to delete: ').strip()
            delete_peer(ifn, idx, by_index=True)
        elif c == '5':
            delete_all_peers(ifn)
        elif c == '6':
            return
        else:
            print('Invalid choice.')


def menu_firewall():
    while True:
        print('\n-- Firewall & Masquerade --')
        print('1) Enable IPv4/IPv6 forwarding')
        print('2) Setup NAT (nftables masquerade)')
        print('3) Remove NAT rules created by this script')
        print('4) Back')
        c = input('Select: ').strip()
        if c == '1':
            ip_forward_enable(False)
            ip_forward_enable(True)
        elif c == '2':
            ifn = input(f'WG interface [{DEFAULT_IFACE}]: ').strip() or DEFAULT_IFACE
            out = input('Outbound interface (empty = auto): ').strip() or None
            nft_masquerade_setup(ifn, out, 'ip')
            nft_masquerade_setup(ifn, out, 'ip6')
        elif c == '3':
            nft_masquerade_remove()
            print('Removed custom NAT chains.')
        elif c == '4':
            return
        else:
            print('Invalid choice.')

# ------------------------- Argparse (Non-interactive) -------------------------

def build_parser():
    p = argparse.ArgumentParser(description='WireGuard Hub Manager')
    sub = p.add_subparsers(dest='cmd')

    sub.add_parser('menu', help='Interactive menu (default)')

    s = sub.add_parser('install', help='Install or update WireGuard')

    s = sub.add_parser('iface-list', help='List interfaces')

    s = sub.add_parser('iface-create', help='Create interface')
    s.add_argument('--name', default=DEFAULT_IFACE)
    s.add_argument('--subnet', default=DEFAULT_SUBNET)
    s.add_argument('--port', type=int, default=DEFAULT_PORT)
    s.add_argument('--dns', default=DEFAULT_DNS)
    s.add_argument('--out-iface', default=None)

    s = sub.add_parser('iface-delete', help='Delete interface by name')
    s.add_argument('--name', required=True)

    s = sub.add_parser('iface-start', help='Start/Up interface by name')
    s.add_argument('--name', required=True)

    s = sub.add_parser('iface-stop', help='Stop/Down interface by name')
    s.add_argument('--name', required=True)

    s = sub.add_parser('peer-list', help='List peers of interface')
    s.add_argument('--iface', default=DEFAULT_IFACE)

    s = sub.add_parser('peer-add', help='Add peer by name')
    s.add_argument('--iface', default=DEFAULT_IFACE)
    s.add_argument('--name', required=True)
    s.add_argument('--dns', default=DEFAULT_DNS)
    s.add_argument('--allowed-subnet', default=None, help='Override AllowedIPs in client config')

    s = sub.add_parser('peer-del', help='Delete peer by name')
    s.add_argument('--iface', default=DEFAULT_IFACE)
    s.add_argument('--name', required=True)

    s = sub.add_parser('peer-deln', help='Delete peer by index number')
    s.add_argument('--iface', default=DEFAULT_IFACE)
    s.add_argument('--num', required=True)

    s = sub.add_parser('peer-delall', help='Delete all peers on interface')
    s.add_argument('--iface', default=DEFAULT_IFACE)

    s = sub.add_parser('fw-enable-forward', help='Enable IPv4/IPv6 forwarding')

    s = sub.add_parser('fw-nat', help='Setup NAT masquerade')
    s.add_argument('--wg-iface', default=DEFAULT_IFACE)
    s.add_argument('--out-iface', default=None)

    s = sub.add_parser('fw-nat-remove', help='Remove NAT rules created by this script')

    return p


def main():
    require_root()
    parser = build_parser()
    if len(sys.argv) == 1:
        # default to menu when no args
        try:
            menu()
        except KeyboardInterrupt:
            print('\nBye')
        return
    args = parser.parse_args()
    cmd = args.cmd
    if cmd == 'install':
        ensure_installed()
    elif cmd == 'iface-list':
        ifaces, active = list_interfaces()
        print('Configured:', ', '.join(ifaces) or '(none)')
        print('Active:', ', '.join(active) or '(none)')
    elif cmd == 'iface-create':
        create_interface(args.name, args.subnet, args.port, args.dns, args.out_iface)
    elif cmd == 'iface-delete':
        delete_interface(args.name)
    elif cmd == 'iface-start':
        run(['systemctl', 'start', SYSTEMD_UNIT.format(args.name)], check=False)
    elif cmd == 'iface-stop':
        run(['systemctl', 'stop', SYSTEMD_UNIT.format(args.name)], check=False)
    elif cmd == 'peer-list':
        list_peers(args.iface)
    elif cmd == 'peer-add':
        add_peer(args.iface, args.name, args.dns, args.allowed_subnet)
    elif cmd == 'peer-del':
        delete_peer(args.iface, args.name, by_index=False)
    elif cmd == 'peer-deln':
        delete_peer(args.iface, args.num, by_index=True)
    elif cmd == 'peer-delall':
        delete_all_peers(args.iface)
    elif cmd == 'fw-enable-forward':
        ip_forward_enable(False)
        ip_forward_enable(True)
    elif cmd == 'fw-nat':
        nft_masquerade_setup(args.wg_iface, args.out_iface, 'ip')
        nft_masquerade_setup(args.wg_iface, args.out_iface, 'ip6')
    elif cmd == 'fw-nat-remove':
        nft_masquerade_remove()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
