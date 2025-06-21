
<p align="center">
  <img src="logo.png" alt="ucanet logo" width="180"/>
</p>

<h1 align="center">ucanet-server</h1>

An alt-root DNS and HTTP server for the [ucanet](https://ucanet.net) network — a web infrastructure designed from scratch for retro computers, disconnected networks, and a clean break from the modern internet.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Features](#features)
- [Requirements](#requirements)
- [Setup](#setup)
- [Domain Registry](#domain-registry)
- [License](#license)
- [Related Projects](#related-projects)

---

## Overview

**ucanet-server** is a fully local server that handles:

- DNS resolution (UDP/TCP)
- Web proxying (HTTP only)
- Neocities and Protoweb integration
- An alternative to the modern internet

It serves only domains found in the [ucanet-registry](https://github.com/ucanet/ucanet-registry) and **does not access or resolve the real web**.

This is the backbone of the ucanet network.

---

## How It Works

1. DNS queries (e.g. `example.com`) are handled by this server.
2. The domain registry syncs from the GitHub repository.
3. If found:
   - It returns the matching IP address.
   - If the entry is `protoweb`, it proxies the request via the Protoweb Wayback proxy.
4. If not found:
   - It defaults to `ucanet.net` or returns 0.0.0.0.

Domains can point to:
- an IP address
- a Neocities website
- the keyword `protoweb` (for archived pages)

---

## Features

- Alternative DNS server (UDP + TCP)
- HTTP proxy
- Neocities support (`username.neocities.org`)
- Protoweb integration via `wayback.protoweb.org`
- Domain registry that syncs with GitHub repository
- Can run offline

---

## Requirements

- Python 3.8 or newer

Python libraries:
```bash
pip install dnslib tldextract cachetools apscheduler gitpython requests
```

## Setup
1. Clone the repo
```bash
git clone https://github.com/ucanet/ucanet-server.git
cd ucanet-server
```
2. Edit the config
```python
SERVER_IP = '127.0.0.1'       # Your machine’s IP
SERVER_PORT = 53              # Main DNS port
ALTERNATE_PORT = 5453         # Optional second DNS port
WEBSERVER_IP = '127.0.0.1'    # Used for HTTP requests
WEBSERVER_PORT = 80           # HTTP port
``` 
4. In `ucanetlib.py`, set your Git credentials (optional for bots):
```python
GIT_USERNAME = "your_username"
GIT_PASSWORD = "your_token"
``` 
5. Run the server
```bash
python ucanet-server.py
```
## Domain Registry
The domain registry is stored in this repo:
[Ucanet Domain Registry](https://github.com/ucanet/ucanet-registry)

## License
Licensed under the [AGPL-3.0 license](https://github.com/ucanet/ucanet-server#AGPL-3.0-1-ov-file).

## Related Projects

 - [TheOldNet](https://theoldnet.com), a deep dive into the Internet Archive made accesisble over an HTTP Proxy.
 -  [Vespernet](https://vespernet.net), a project that started out as a fork of ucanet, with the same goal of separating the modern web from the retro web.
 - [ProtoWeb](https://protoweb.org/), a refined archive of retro websites with added functionality and a growing community.
 - [ucanet/ucanet-registry](https://github.com/ucanet/ucanet-registry) The domain registry for ucanet.
 - [ucanet/ucanet-discord-bot](https://github.com/ucanet/ucanet-discord-bot) A discord bot for managing ucanet domains.
 - [ucanet/ucanet-python-lib](https://github.com/ucanet/ucanet-python-lib) A small library for interacting with the ucanet registry.