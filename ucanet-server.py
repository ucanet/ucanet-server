"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""
import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
from dnslib import *
from ucanetlib import *

SERVER_IP = '127.0.0.1' # Change to your local IP Address.
SERVER_PORT = 53

def dns_response(data):
	request = DNSRecord.parse(data)
	reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)	
	query_name = str(request.q.qname)
	
	if ip_address := find_entry(query_name[0:-1]):
		reply.add_answer(*RR.fromZone(f'{query_name} 60 A {ip_address} MX {ip_address}'))

	return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):
	def get_data(self):
		raise NotImplementedError

	def send_data(self, data):
		raise NotImplementedError

	def handle(self):
		now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
		print("%s request %s (%s %s)" % (self.__class__.__name__[:3], now, self.client_address[0],
											   self.client_address[1]))
		try:
			self.send_data(dns_response(self.get_data()))
		except Exception:
			traceback.print_exc(file=sys.stderr)

class TCPRequestHandler(BaseRequestHandler):
	def get_data(self):
		data = self.request.recv(8192)
		sz = struct.unpack('>H', data[:2])[0]
		if sz < len(data) - 2:
			raise Exception("Wrong size of TCP packet")
		elif sz > len(data) - 2:
			raise Exception("Too big TCP packet")
		return data[2:]

	def send_data(self, data):
		sz = struct.pack('>H', len(data))
		return self.request.sendall(sz + data)

class UDPRequestHandler(BaseRequestHandler):
	def get_data(self):
		return self.request[0]

	def send_data(self, data):
		return self.request[1].sendto(data, self.client_address)

def main():
	print("Starting nameserver...")
	
	servers = []
	servers.append(socketserver.ThreadingUDPServer((SERVER_IP, SERVER_PORT), UDPRequestHandler))
	servers.append(socketserver.ThreadingTCPServer((SERVER_IP, SERVER_PORT), TCPRequestHandler))

	for s in servers:
		thread = threading.Thread(target=s.serve_forever)
		thread.daemon = True
		thread.start()
		print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

	try:
		while 1:
			time.sleep(1)
			sys.stderr.flush()
			sys.stdout.flush()

	except KeyboardInterrupt:
		pass
	finally:
		for s in servers:
			s.shutdown()

if __name__ == '__main__':
	main()
