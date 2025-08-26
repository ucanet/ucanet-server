import http.server
import urllib.parse
import time
import requests

from library import (
    log_request,
    site_registry,
    extract_host,
    extract_path,
    find_entry,
    is_internal_domain,
    copy_response_headers,
)

WEBSERVER_IP = '192.168.1.13'  # Should match the one in library.py
WEBSERVER_PORT = 80


class WebHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        log_request(self)

        host_name = extract_host(self.headers.get('Host'))
        if not is_internal_domain(host_name, site_registry):
            print(f"[HTTP] BLOCKED: {host_name} is not an internal domain")
            self.send_error(403, "Forbidden: External domain access denied")
            return

        entry = find_entry(host_name)

        print(f"[DEBUG] Raw Host Header: {self.headers.get('Host')}")
        print(f"[DEBUG] Extracted Host: {host_name}")
        print(f"[DEBUG] Entry returned by find_entry(): {entry}")

        if host_name and entry == "protoweb":
            return self.proxy_to_protoweb("GET")

        target_url = (
            f"https://{entry}{extract_path(self.path)}"
            if entry != "protoweb"
            else f"http://{entry}{extract_path(self.path)}"
        )

        print(f"[DEBUG] target_url: {target_url}")
        client_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in {
                'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
                'te', 'trailers', 'transfer-encoding', 'upgrade'
            }
        }
        client_headers['Host'] = entry
        client_headers['Referer'] = f"http://{entry}/"

        try:
            start_time = time.time()
            response = requests.get(
                target_url,
                stream=True,
                allow_redirects=False,
                headers=client_headers,
                timeout=10
            )
            print(f"[DEBUG] Upstream response status: {response.status_code} "
                  f"(time: {time.time() - start_time:.2f}s)")
        except requests.RequestException as e:
            print(f"[ERROR] Upstream request failed: {e}")
            self.send_error(502, f"Bad Gateway: {e}")
            return

        self.send_response_only(response.status_code)
        copy_response_headers(response, self)
        self.end_headers()

        # Don't write body for 204 or 304 responses
        if response.status_code in (204, 304):
            return


        try:
            for chunk in response.iter_content(chunk_size=4096):
                if chunk:
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except Exception as e:
            print(f"[ERROR] While streaming to client: {e}")

    def do_POST(self):
        log_request(self)

        host_name = extract_host(self.headers.get('Host'))
        entry = find_entry(host_name)

        if host_name and entry == "protoweb":
            return self.proxy_to_protoweb("POST")

        self.send_error(403, "Forbidden")

    def proxy_to_protoweb(self, method):
        proto_url = f"http://{self.headers['Host']}{extract_path(self.path)}"
        proxies = {'http': 'http://wayback.protoweb.org:7851'}

        try:
            if method == 'GET':
                response = requests.get(
                    proto_url, stream=True, allow_redirects=False,
                    headers=self.headers, proxies=proxies
                )
            elif method == 'POST':
                content_len = int(self.headers.get('Content-Length', 0))
                post_body = self.rfile.read(content_len)
                response = requests.post(
                    proto_url, stream=True, allow_redirects=False,
                    headers=self.headers, proxies=proxies, data=post_body
                )
            else:
                self.send_error(405, "Method Not Allowed")
                return
        except requests.RequestException as e:
            self.send_error(502, f"Protoweb Error: {e}")
            return

        self.send_response_only(response.status_code)
        copy_response_headers(response, self)
        self.end_headers()

        try:
            for chunk in response.iter_content(chunk_size=4096):
                if chunk:
                    self.wfile.write(chunk)
        except Exception as e:
            print(f"[ERROR] While streaming Protoweb response: {e}")


def start_http_server():
    with http.server.ThreadingHTTPServer((WEBSERVER_IP, WEBSERVER_PORT), WebHTTPHandler) as server:
        print(f"[HTTP] HTTP server running on {WEBSERVER_IP}:{WEBSERVER_PORT}")
        server.serve_forever()
