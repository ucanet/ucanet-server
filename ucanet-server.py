"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""
import sys
import time
import struct
import urllib
import argparse
import datetime
import requests
import threading
import traceback
import http.server
import socketserver
from dnslib import *
from ucanetlib import *

SERVER_IP = '127.0.0.1' # Change to your local IP Address.
SERVER_PORT = 53
NEOCITIES_IP = '127.0.0.1' # Change this to the IP that serves Neocities sites
NEOCITIES_PORT = 80

def log_request(handler_object):
	current_time = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
	print("%s request %s (%s %s)" % (handler_object.__class__.__name__[:3], current_time, handler_object.client_address[0], handler_object.client_address[1]))
	
def dns_response(data):
	dns_request = DNSRecord.parse(data)
	dns_reply = DNSRecord(DNSHeader(id = dns_request.header.id, qr = 1, aa = 1, ra = 1), q = dns_request.q)	
	query_name = str(dns_reply.q.qname)
	
	if ip_address := find_entry(query_name[0:-1]):
		if formatted_ip := format_ip(ip_address):
			dns_reply.add_answer(*RR.fromZone(f'{query_name} 60 A {formatted_ip} MX {formatted_ip}'))
		else:
			dns_reply.add_answer(*RR.fromZone(f'{query_name} 60 A {NEOCITIES_IP}'))
			
	return dns_reply.pack()

class BaseRequestHandler(socketserver.BaseRequestHandler):
	def get_data(self):
		raise NotImplementedError

	def send_data(self, data):
		raise NotImplementedError

	def handle(self):
		log_request(self)
		
		try:
			self.send_data(dns_response(self.get_data()))
		except Exception:
			traceback.print_exc(file = sys.stderr)

class TCPRequestHandler(BaseRequestHandler):
	def get_data(self):
		request_data = self.request.recv(8192)
		request_size = struct.unpack('>H', request_data[:2])[0]
		if request_size < len(request_data) - 2:
			raise Exception("Wrong size of TCP packet")
		elif request_size > len(request_data) - 2:
			raise Exception("Too big TCP packet")
		return request_data[2:]

	def send_data(self, data):
		data_size = struct.pack('>H', len(data))
		return self.request.sendall(data_size + data)

class UDPRequestHandler(BaseRequestHandler):
	def get_data(self):
		return self.request[0]

	def send_data(self, data):
		return self.request[1].sendto(data, self.client_address)

class NeoHTTPHandler(http.server.BaseHTTPRequestHandler):
	def do_GET(self):
		log_request(self)
		
		host_name = self.headers.get('Host')
		neo_site = find_entry(host_name)
		
		if neo_site and not format_ip(neo_site):	
			neo_site = "https://%s.neocities.org%s" % (neo_site, self.path)
		else:
			neo_site = "https://ucanet.net%s" % (self.path)
			
		request_response = requests.get(neo_site, stream = True, allow_redirects=False)

		if request_response.status_code == 404:
			self.send_error(404, "404 Not Found")
			return
		elif request_response.status_code == 301:
			request_location = request_response.headers.get('location') or request_response.headers.get('Location')
			self.send_response(301)
			self.send_header('Location', "http://%s%s" % (host_name or "ucanet.net", urllib.parse.urlparse(request_location).path))
			self.end_headers()
			return
		else:
			self.send_response_only(200)

		for current_header, current_value in request_response.headers.items():
			if current_header.lower() == "content-type":
				self.send_header(current_header, current_value)
			else:
				continue

		self.end_headers()
		self.wfile.write(request_response.content)	
    
def server_init():
	server_list = []
	server_list.append(socketserver.ThreadingUDPServer((SERVER_IP, SERVER_PORT), UDPRequestHandler))
	server_list.append(socketserver.ThreadingTCPServer((SERVER_IP, SERVER_PORT), TCPRequestHandler))
	server_list.append(http.server.ThreadingHTTPServer((NEOCITIES_IP, NEOCITIES_PORT), NeoHTTPHandler))
    
	for current_server in server_list:
		server_thread = threading.Thread(target = current_server.serve_forever)
		server_thread.daemon = True
		server_thread.start()
		print("%s server loop running in thread: %s" % (current_server.RequestHandlerClass.__name__[:3], server_thread.name))

	try:
		while True:
			time.sleep(1)
			sys.stderr.flush()
			sys.stdout.flush()

	except KeyboardInterrupt:
		pass
	finally:
		for current_server in server_list:
			current_server.shutdown()

server_init()
