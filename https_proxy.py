import socket
import ssl
import threading
import re
import struct
import ipaddress
from pathlib import Path
import socketserver
import time

from library import (
    pipe,
    resolve_redirect,
    site_registry,
    is_internal_domain
)

HTTPS_PORT = 443
MITM_CERTS_DIR = './certs'


class HTTPSProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print("[DEBUG] HTTPS handler received a connection")
        client = self.request
        sni = extract_sni(client)

        if not sni:
            print("[HTTPS] Failed to extract SNI")
            client.close()
            return

        if not is_internal_domain(sni, site_registry):
            print(f"[HTTPS] BLOCKED: {sni} is not an internal domain")
            self.request.close()  # Close connection silently
            return

        owner, real_host = site_registry.get(sni.lower(), (1, sni))
        cert_av = Path(f'{MITM_CERTS_DIR}/{sni}.crt')
        print(f"[HTTPS] {sni} → ({'MITM' if cert_av.is_file() else 'PASS'}) {real_host}")

        if cert_av.is_file():
            self.mitm_tls(client, real_host, sni)
        else:
            self.pass_through(client, real_host)

    @staticmethod
    def try_tls_connection(backend_host, retries=2, delay=0.5):
        for attempt in range(1, retries + 1):
            try:
                print(f"[MITM] Attempt {attempt}: Connecting to backend {backend_host}")
                conn = socket.create_connection((backend_host, 443), timeout=5)
                tls_conn = ssl.create_default_context().wrap_socket(
                    conn, server_hostname=backend_host
                )
                print(f"[MITM] Backend TLS connection successful on attempt {attempt}")
                return tls_conn
            except Exception as e:
                print(f"[MITM] TLS connection failed (attempt {attempt}): {e}")
                time.sleep(delay)
        print("[MITM] All TLS connection attempts failed.")
        return None

    def mitm_tls(self, client_sock, backend_host, cert_host):
        try:
            certfile = f"{MITM_CERTS_DIR}/{cert_host}.crt"
            keyfile = f"{MITM_CERTS_DIR}/{cert_host}.key"

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)

            tls_client = context.wrap_socket(client_sock, server_side=True)
            backend_conn = self.try_tls_connection(backend_host)
            if not backend_conn:
                client_sock.close()
                return

            tls_client.settimeout(5)
            try:
                initial_request = tls_client.recv(8192)
            except socket.timeout:
                print("[MITM] Client did not send in time.")
                client_sock.close()
                return

            if not initial_request:
                raise Exception("Empty request from client")

            # Rewrite Host header
            host_pattern = f"Host:\\s*{re.escape(cert_host)}".encode()
            replacement = f"Host: {backend_host}".encode()
            modified_request = re.sub(host_pattern, replacement, initial_request, flags=re.IGNORECASE)

            backend_conn.sendall(modified_request)

            threading.Thread(
                target=pipe, args=(tls_client, backend_conn, "Client→Server"),
                kwargs={'rewrite_hostnames': (cert_host, backend_host)}
            ).start()

            threading.Thread(
                target=pipe, args=(backend_conn, tls_client, "Server→Client"),
                kwargs={'rewrite_hostnames': (backend_host, cert_host)}
            ).start()

        except Exception as e:
            print(f"[MITM] Error: {e}")
            client_sock.close()

    def pass_through(self, client_sock, hostname):
        try:
            ip = socket.gethostbyname(hostname)
            server_sock = socket.create_connection((ip, 443))
            threading.Thread(target=pipe, args=(client_sock, server_sock, "Client→Server")).start()
            threading.Thread(target=pipe, args=(server_sock, client_sock, "Server→Client")).start()
        except Exception as e:
            print(f"[PASS] Error: {e}")
            client_sock.close()


def extract_sni(sock):
    try:
        data = sock.recv(4096, socket.MSG_PEEK)
        if len(data) < 5 or data[0] != 0x16:
            return None

        _, version, length = struct.unpack('>BHH', data[:5])
        if len(data) < 5 + length:
            return None

        handshake_type = data[5]
        if handshake_type != 0x01:
            return None

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

            if ext_type == 0x0000:
                list_len = struct.unpack('>H', data[ptr:ptr+2])[0]
                name_type = data[ptr+2]
                if name_type != 0x00:
                    return None
                name_len = struct.unpack('>H', data[ptr+3:ptr+5])[0]
                server_name = data[ptr+5:ptr+5+name_len].decode('utf-8', errors='ignore')
                return server_name[4:] if server_name.startswith('www.') else server_name

            ptr += ext_len

        return "unknown.local"

    except Exception:
        return None


def start_https_server():
    with socketserver.ThreadingTCPServer(('', HTTPS_PORT), HTTPSProxyHandler) as server:
        print(f"[HTTPS] Proxy running on port {HTTPS_PORT}")
        server.serve_forever()
