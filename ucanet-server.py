import threading
import time
from dns_server import start_dns_server
from http_server import start_http_server
from https_proxy import start_https_server
from library import init_library()

def main():
    init_library()
    print("[INIT] Starting DNS, HTTP, and HTTPS servers...")

    threading.Thread(target=start_dns_server, daemon=True).start()
    threading.Thread(target=start_http_server, daemon=True).start()
    threading.Thread(target=start_https_server, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[EXIT] Shutting down servers.")

if __name__ == '__main__':
    main()
