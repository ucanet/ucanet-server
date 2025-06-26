import sys
import time
import urllib
import datetime
import requests
import http.server
import ipaddress
import socket
import ssl
import threading
import socketserver
import struct
import re
from pathlib import Path
from functools import lru_cache

DNS_PORT = 53
WEBSERVER_PORT = 80
WEBSERVER_IP = '127.0.0.1' #change this to your ip address of computer running this script
HTTPS_PORT = 443
MITM_CERTS_DIR = './certs'


def log_request(handler):
    now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
    print(f"{handler.__class__.__name__[:3]} request {now} ({handler.client_address[0]}:{handler.client_address[1]})")

def extract_host(hostname):
    if not hostname:
        return None
    if not urllib.parse.urlparse(hostname).netloc:
        hostname = "http://" + hostname
    return urllib.parse.urlparse(hostname).hostname


def extract_path(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")

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

# Load site policies
def load_site_registry():
    registry = {}
    with open('../ucanet-registry/ucanet-registry.txt') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 3:
                hostname, cert_flag, redirect = parts
                registry[hostname.lower()] = (int(cert_flag), redirect)
    return registry

site_registry = load_site_registry()

##################################
# DNS HANDLER
##################################
class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        query = data[12:]
        domain = ''
        i = 0
        while query[i] != 0:
            length = query[i]
            domain += query[i+1:i+1+length].decode() + '.'
            i += length + 1
        domain = domain[:-1].lower()
        print(f"[DNS] Query for: {domain}")

        if domain in site_registry:
            cert_flag, redirect = site_registry[domain]
            cert_av = Path('certs/' + domain + '.crt')
            if cert_av.is_file():
                print(f"[DNS] MITM site → return proxy IP")
                ip = WEBSERVER_IP  # IP of the machine running HTTPSProxyHandler
            elif redirect == 'protoweb':
                print(f"[DNS] PROTOWEB")
                ip = WEBSERVER_IP  # IP of the machine running HTTPSProxyHandler
                #self.handle_protoweb_request(method='GET')
            else:
                print(f"[DNS] PASS-THROUGH site → resolve real IP")
                ip = resolve_redirect(redirect)  # Do real DNS or custom logic
        else:
            print(f"[DNS] Not in registry, using fallback DNS")
            ip = '8.8.8.8'  # Default fallback

        # Craft DNS response
        response = data[:2] + b'\x81\x80' + data[4:6]*2 + b'\x00\x00\x00\x00' + data[12:]
        response += b'\xc0\x0c' + b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton(ip)
        sock.sendto(response, self.client_address)

#################################
# HTTP HANDLER
#################################
class ProtowebHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        log_request(self)
        host = extract_host(self.headers.get('Host'))

        if not host:
            self.send_error(400, "Bad Host")
            return

        # Protoweb handling only
        proto_url = f"http://{host}{extract_path(self.path)}"

        try:
            response = requests.get(
                proto_url,
                stream=True,
                allow_redirects=False,
                headers=self.headers,
                proxies={'http': 'http://wayback.protoweb.org:7851'}
            )

            self.send_response_only(response.status_code)

            for h, v in response.headers.items():
                if h.lower() != "transfer-encoding":
                    self.send_header(h, v)

            self.end_headers()
            self.wfile.write(response.content)

        except Exception as e:
            self.send_error(502, f"Error fetching from protoweb: {e}")

    def do_POST(self):
        log_request(self)
        host = extract_host(self.headers.get('Host'))

        if not host:
            self.send_error(400, "Bad Host")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        proto_url = f"http://{host}{extract_path(self.path)}"

        try:
            response = requests.post(
                proto_url,
                data=body,
                stream=True,
                allow_redirects=False,
                headers=self.headers,
                proxies={'http': 'http://wayback.protoweb.org:7851'}
            )

            self.send_response_only(response.status_code)

            for h, v in response.headers.items():
                if h.lower() != "transfer-encoding":
                    self.send_header(h, v)

            self.end_headers()
            self.wfile.write(response.content)

        except Exception as e:
            self.send_error(502, f"Error posting to protoweb: {e}")


##################################
# HTTPS MITM PROXY
##################################
class HTTPSProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print("[DEBUG] HTTPS handler received a connection")
        client = self.request
        sni = extract_sni(client)
        if not sni:
            print("[HTTPS] Failed to extract SNI")
            client.close()
            return

        cert_flag, real_host = site_registry.get(sni.lower(), (1, sni))
        print(f"[HTTPS] {sni} → ({'MITM' if cert_flag else 'PASS'}) {real_host}")

        cert_av = Path('certs/' + sni + '.crt')
        #if cert_flag > 0:
        if cert_av.is_file():
            print(f"[DEBUG] SNI: {sni}, Backend: {real_host}")
            self.mitm_tls(client, real_host, sni)
        else:
            self.pass_through(client, real_host)


    def mitm_tls(self, client_sock, backend_host, cert_host):
        try:
            import re  # Ensure this is imported

            print(f"[MITM] Using backend_host={backend_host}, cert_host={cert_host}")
            certfile = f"{MITM_CERTS_DIR}/{cert_host}.crt"
            keyfile = f"{MITM_CERTS_DIR}/{cert_host}.key"
            print(f"[MITM] Loading certfile={certfile}, keyfile={keyfile}")

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            print("[MITM] SSL context created and cert loaded")

            tls_client = context.wrap_socket(client_sock, server_side=True)
            print("[MITM] TLS client socket wrapped")

            backend_conn = socket.create_connection((backend_host, 443))
            print(f"[MITM] Connected to backend {backend_host}:443")

            tls_server = ssl.create_default_context().wrap_socket(
                backend_conn, server_hostname=backend_host
            )
            print("[MITM] TLS server socket wrapped")

            # 1. Read and modify the first request (like before)
            initial_request = tls_client.recv(8192)
            if not initial_request:
                raise Exception("No data received from client")

            # Modify Host header
            # Build regex string dynamically, then encode
            host_pattern = f"Host:\\s*{re.escape(cert_host)}".encode()
            replacement = f"Host: {backend_host}".encode()

            modified_request = re.sub(
                host_pattern,
                replacement,
                initial_request,
                flags=re.IGNORECASE
            )

            print(f"[MITM] Replacing Host: {cert_host} → {backend_host}")
            #print(f"[MITM] Original request: {initial_request[:200]!r}")
            #print(f"[MITM] Modified request: {modified_request[:200]!r}")

            # Send to backend
            tls_server.sendall(modified_request)

            # 2. Pipe remaining traffic normally
            threading.Thread(
                target=pipe,
                args=(tls_client, tls_server, "Client→Server"),
                kwargs={'rewrite_hostnames': (cert_host, backend_host)}
            ).start()

            threading.Thread(
                target=pipe,
                args=(tls_server, tls_client, "Server→Client"),
                kwargs={'rewrite_hostnames': (backend_host, cert_host)}
            ).start()

        except Exception as e:
            print(f"[MITM] Error: {e}")
            client_sock.close()

    def pass_through(self, client_sock, hostname):
        try:
            # hostname is actual hostname (not IP!) for SNI to work
            ip = socket.gethostbyname(hostname)
            print(f"[debug] passing through: {hostname}")
            server_sock = socket.create_connection((ip, 443))
            threading.Thread(target=pipe, args=(client_sock, server_sock)).start()
            threading.Thread(target=pipe, args=(server_sock, client_sock)).start()
        except Exception as e:
            print(f"[PASS] Error: {e}")
            client_sock.close()

def pipe(src, dst, direction, rewrite_hostnames=None):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                print(f"[PIPE {direction}] Connection closed by source.")
                break

            # Rewrite client → server traffic if needed
            if direction == "Client→Server" and rewrite_hostnames:
                fake_host, real_host = rewrite_hostnames
                data = data.replace(fake_host.encode(), real_host.encode())

            # Rewrite server → client Location headers (already handled)
            if direction == "Server→Client" and rewrite_hostnames:
                real_host, fake_host = rewrite_hostnames
                data = re.sub(
                    f"Location: https://{re.escape(real_host)}".encode(),
                    f"Location: https://{fake_host}".encode(),
                    data,
                    flags=re.IGNORECASE
                )

            #print(f"[PIPE {direction}] Transferring {len(data)} bytes.")
            #if len(data) <= 4096:
                #print(f"[PIPE {direction}] Data snippet (full): {data!r}")
            #else:
                #print(f"[PIPE {direction}] Data snippet (first 100 bytes): {data[:100]!r}")
            if direction == "Server→Client" and rewrite_hostnames:
                real_host, fake_host = rewrite_hostnames

                # Replace Location header
                data = re.sub(
                    f"Location: https://{re.escape(real_host)}".encode(),
                    f"Location: https://{fake_host}".encode(),
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


@lru_cache(maxsize=128)
def resolve_redirect(redirect):
    try:
        ipaddress.IPv4Address(redirect)
        return redirect  # Already a valid IP
    except ipaddress.AddressValueError:
        try:
            return socket.gethostbyname(redirect)
        except socket.gaierror:
            print(f"[DNS] Failed to resolve hostname: {redirect}")
            return '8.8.8.8'  # Fallback

##################################
# TLS SNI PARSER
##################################
def extract_sni(sock):
    try:
        data = sock.recv(4096, socket.MSG_PEEK)
        if len(data) < 5 or data[0] != 0x16:
            return None  # Not a TLS Handshake

        # Parse TLS record header
        _, version, length = struct.unpack('>BHH', data[:5])
        if len(data) < 5 + length:
            return None  # Not enough data

        # Move to Handshake message
        handshake_type = data[5]
        if handshake_type != 0x01:
            return None  # Not a ClientHello

        # Extract lengths to reach extensions
        session_id_len = data[43]
        ptr = 44 + session_id_len

        if ptr + 2 > len(data):
            return None  # Not enough space for cipher suites length

        cipher_suites_len = struct.unpack('>H', data[ptr:ptr+2])[0]
        ptr += 2 + cipher_suites_len

        if ptr >= len(data):
            return None

        compression_methods_len = data[ptr]
        ptr += 1 + compression_methods_len

        if ptr + 2 > len(data):
            return None

        extensions_length = struct.unpack('>H', data[ptr:ptr+2])[0]
        ptr += 2
        end = ptr + extensions_length

        while ptr + 4 <= end:
            ext_type, ext_len = struct.unpack('>HH', data[ptr:ptr+4])
            ptr += 4

            if ext_type == 0x0000:  # SNI
                # SNI format: [list_length][name_type][name_len][name]
                list_len = struct.unpack('>H', data[ptr:ptr+2])[0]
                name_type = data[ptr+2]
                if name_type != 0x00:
                    return None  # Only host_name is valid
                name_len = struct.unpack('>H', data[ptr+3:ptr+5])[0]
                server_name = data[ptr+5:ptr+5+name_len].decode('utf-8', errors='ignore')
                if server_name.startswith('www.'):
                    server_name = server_name[4:]
                return server_name

            ptr += ext_len

        return "unknown.local"

    except Exception as e:
        return None


##################################
# START SERVERS
##################################
def start_dns_server():
    with socketserver.UDPServer(('', DNS_PORT), DNSHandler) as server:
        print(f"[DNS] Server running on port {DNS_PORT}")
        server.serve_forever()

def start_protoweb_server():
    with http.server.ThreadingHTTPServer((WEBSERVER_IP, WEBSERVER_PORT), ProtowebHandler) as server:
        print(f"[ProtoWeb] HTTP server running on {WEBSERVER_IP}:{WEBSERVER_PORT}")
        server.serve_forever()

def start_https_server():
    with socketserver.TCPServer(('', HTTPS_PORT), HTTPSProxyHandler) as server:
        print(f"[HTTPS] Proxy running on port {HTTPS_PORT}")
        server.serve_forever()

if __name__ == '__main__':
    threading.Thread(target=start_dns_server).start()
    threading.Thread(target=start_protoweb_server).start()
    threading.Thread(target=start_https_server).start()
