# library.py

import urllib.parse
import re
import socket
import datetime
from pathlib import Path
from functools import lru_cache
from threading import Lock
import ipaddress
import tldextract
from cachetools import TTLCache

# === Constants ===
REGISTRY_PATH = "../ucanet-registry/ucanet-registry.txt"
MITM_CERTS_DIR = './certs'
WEBSERVER_IP = '192.168.1.13'
CACHE_SIZE = 3500
CACHE_TTL = 600

# === Caches and Locks ===
offline_extract = tldextract.TLDExtract(suffix_list_urls=())
entry_cache = TTLCache(maxsize=CACHE_SIZE, ttl=CACHE_TTL)
entry_lock = Lock()
file_lock = Lock()
pending_lock = Lock()
pending_changes = {}

# === Logging ===
def log_request(handler):
    now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
    print(f"{handler.__class__.__name__[:3]} request {now} ({handler.client_address[0]}:{handler.client_address[1]})")

# === Domain Tools ===
def format_domain(domain_name):
    domain_name = domain_name.lower()
    if domain_name.endswith('.'):
        domain_name = domain_name[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    if all(allowed.match(x) for x in domain_name.split(".")):
        extracted = offline_extract(domain_name)
        if extracted.domain and extracted.suffix:
            return domain_name
    return False

def second_level(domain_name):
    domain_name = format_domain(domain_name)
    if domain_name:
        extracted = offline_extract(domain_name)
        if extracted.subdomain:
            return f"{extracted.domain}.{extracted.suffix}"
    return False

def extract_host(hostname):
    if not hostname:
        return None
    if not urllib.parse.urlparse(hostname).netloc:
        hostname = "http://" + hostname
    return urllib.parse.urlparse(hostname).hostname

def extract_path(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")

# === IP Utilities ===
def format_ip(current_ip):
    if current_ip == "none":
        return "0.0.0.0"
    try:
        return current_ip if type(ipaddress.ip_address(current_ip)) is ipaddress.IPv4Address else False
    except ValueError:
        return False

# === Registry Handling ===
def load_site_registry(path=REGISTRY_PATH):
    registry = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 3:
                hostname, owner, redirect = parts
                registry[hostname.lower()] = (int(owner), redirect)
    return registry

site_registry = load_site_registry()

# === Entry Lookup ===
def find_pending(domain_name):
    with pending_lock:
        for domain_list in pending_changes.values():
            for current_name, current_ip in domain_list.items():
                if current_name == domain_name:
                    return current_ip
    return False

def find_entry(domain_name):
    if not domain_name:
        return False

    domain_name = format_domain(domain_name)
    if not domain_name:
        return False

    if found_pending := find_pending(domain_name):
        return found_pending

    with entry_lock:
        if domain_name in entry_cache:
            return entry_cache[domain_name]

    try:
        with file_lock, open(REGISTRY_PATH, 'r') as registry_file:
            for line in registry_file:
                split_lines = line.strip().split(' ')
                if split_lines[0] == domain_name:
                    with entry_lock:
                        entry_cache[domain_name] = split_lines[2]
                    return split_lines[2]
    except Exception as e:
        print(f"[Registry] Error reading: {e}")

    # Try fallback second-level domain
    if entry := find_entry(second_level(domain_name)):
        with entry_lock:
            entry_cache[domain_name] = entry
        return entry

    return False

# === Header Helpers ===
def copy_response_headers(src_response, dst_handler, allowed_headers=None):
    hop_by_hop = {
        'connection',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'te',
        'trailers',
        'transfer-encoding',
        'upgrade'
    }
    for key, value in src_response.headers.items():
        if key.lower() in hop_by_hop:
            if key.lower() == 'transfer-encoding' and 'chunked' in value.lower():
                dst_handler.send_header(key, value)
        elif not allowed_headers or key.lower() in allowed_headers:
            dst_handler.send_header(key, value)

# === Socket Helpers ===
def recv_until_headers(sock, timeout=2):
    sock.settimeout(timeout)
    data = b''
    try:
        while b'\r\n\r\n' not in data:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
    finally:
        sock.settimeout(None)
    return data

@lru_cache(maxsize=128)
def resolve_redirect(redirect):
    try:
        ipaddress.IPv4Address(redirect)
        return redirect
    except ipaddress.AddressValueError:
        try:
            return socket.gethostbyname(redirect)
        except socket.gaierror:
            print(f"[DNS] Failed to resolve hostname: {redirect}")
            return '8.8.8.8'

# === TLS / SNI Tools ===
def extract_sni(sock):
    try:
        data = sock.recv(4096, socket.MSG_PEEK)
        if len(data) < 5 or data[0] != 0x16:
            return None  # Not a TLS Handshake

        session_id_len = data[43]
        ptr = 44 + session_id_len
        cipher_suites_len = struct.unpack('>H', data[ptr:ptr+2])[0]
        ptr += 2 + cipher_suites_len
        compression_methods_len = data[ptr]
        ptr += 1 + compression_methods_len
        extensions_length = struct.unpack('>H', data[ptr:ptr+2])[0]
        ptr += 2
        end = ptr + extensions_length

        while ptr + 4 <= end:
            ext_type, ext_len = struct.unpack('>HH', data[ptr:ptr+4])
            ptr += 4
            if ext_type == 0x0000:  # SNI
                list_len = struct.unpack('>H', data[ptr:ptr+2])[0]
                name_type = data[ptr+2]
                if name_type != 0x00:
                    return None
                name_len = struct.unpack('>H', data[ptr+3:ptr+5])[0]
                server_name = data[ptr+5:ptr+5+name_len].decode('utf-8', errors='ignore')
                if server_name.startswith('www.'):
                    server_name = server_name[4:]
                return server_name
            ptr += ext_len
        return None
    except Exception:
        return None

def pipe(src, dst, direction, rewrite_hostnames=None):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                print(f"[PIPE {direction}] Connection closed by source.")
                break

            # Rewrite client → server traffic if needed
            if direction == "Client→Server" and rewrite_hostnames:
                ucanet_hostname, real_host = rewrite_hostnames
                data = data.replace(ucanet_hostname.encode(), real_host.encode())

            # Rewrite server → client Location headers (already handled)
            if direction == "Server→Client" and rewrite_hostnames:
                real_host, ucanet_hostname = rewrite_hostnames
                data = re.sub(
                    f"Location: https://{re.escape(real_host)}".encode(),
                    f"Location: https://{ucanet_hostname}".encode(),
                    data,
                    flags=re.IGNORECASE
                )

            #print(f"[PIPE {direction}] Transferring {len(data)} bytes.")
            #if len(data) <= 4096:
                #print(f"[PIPE {direction}] Data snippet (full): {data!r}")
            #else:
                #print(f"[PIPE {direction}] Data snippet (first 100 bytes): {data[:100]!r}")
            if direction == "Server→Client" and rewrite_hostnames:
                real_host, ucanet_hostname = rewrite_hostnames

                # Replace Location header
                data = re.sub(
                    f"Location: https://{re.escape(real_host)}".encode(),
                    f"Location: https://{ucanet_hostname}".encode(),
                    data,
                    flags=re.IGNORECASE
                )

            dst.sendall(data)

    except Exception as e:
        print(f"[PIPE {direction}] Error: {e}")
    finally:
        print(f"[PIPE {direction}] Closing sockets.")
        try: src.close()
        except: pass
        try: dst.close()
        except: pass
