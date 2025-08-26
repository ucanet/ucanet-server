import socket
import socketserver
from pathlib import Path

from library import (
    site_registry,
    WEBSERVER_IP,
    REGISTRY_PATH,
    resolve_redirect
)

DNS_PORT = 53


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
        domain = domain[4:] if domain.lower().startswith("www.") else domain

        print(f"[DNS] Query for: {domain}")

        if domain in site_registry:
            owner, redirect = site_registry[domain]
            cert_av = Path(f'certs/{domain}.crt')
            if cert_av.is_file() or redirect == 'protoweb':
                print(f"[DNS] MITM site or PROTOWEB → return proxy IP")
                ip = WEBSERVER_IP
            else:
                print(f"[DNS] PASS-THROUGH site → resolve real IP")
                ip = resolve_redirect(redirect)
        else:
            print(f"[DNS] {domain} Not in registry, sending NXDOMAIN")
            response = self.build_nxdomain(data)
            sock.sendto(response, self.client_address)
            return

        # Send DNS response
        response = self.build_response(data, ip)
        sock.sendto(response, self.client_address)

    def build_nxdomain(self, data):
        return data[:2] + b'\x81\x83' + data[4:6] + b'\x00\x00\x00\x00\x00\x00' + data[12:]

    def build_response(self, data, ip):
        response = data[:2] + b'\x81\x80' + data[4:6]*2 + b'\x00\x00\x00\x00' + data[12:]
        response += b'\xc0\x0c' + b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton(ip)
        return response


def start_dns_server():
    with socketserver.UDPServer(('', DNS_PORT), DNSHandler) as server:
        print(f"[DNS] Server running on port {DNS_PORT}")
        server.serve_forever()
