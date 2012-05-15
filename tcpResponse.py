#!/usr/bin/python
# -*- coding: utf-8 -*-

from scapy.all import *
import re

ADRESSE_IP = "192.168.1.42"

_FTP = 'ftp'
_SSH = 'ssh'
_SMTP = 'smtp'
_HTTP = 'http'
_IMAP = 'imap'
_HTTP_200 = "200"
_HTTP_400 = "400"
_HTTP_404 = "404"

reg_httpGetRoot = re.compile(r"GET / HTTP(.*)")
reg_httpGetDefault = re.compile(r"GET /(.*) HTTP(.*)")

class TcpService:
	def __init__(self, portNumber, header):
		self.port = portNumber
		self.header = header

tcpServices = dict()
tcpServices[_FTP] = TcpService(21,"220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n")
tcpServices[_SSH] = TcpService(22,"SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1\r\n")
tcpServices[_SMTP] = TcpService(25,"220 192.168.1.42 ESMTP Postfix (2.0.13) (Debian Linux)\r\n")
tcpServices[_HTTP_200] = TcpService(80,"HTTP/1.0 200 ok\r\nServer: Apache/2.0.46 (Unix) (Debian/Linux)\r\nContent-type: text/html\r\n\r\n<html><body><h1>It works!</h1>\r\n<p>This is the default web page for this server.</p>\r\n<p>The web server software is running but no content has been added, yet.</p>\r\n</body></html>\r\n")
tcpServices[_HTTP_400] = TcpService(80,"HTTP/1.0 404 Not Found \r\nServer: Apache/2.0.46 (Unix) (Debian/Linux)\r\nContent-type: text/html\r\n\r\n")
tcpServices[_HTTP_404] = TcpService(80,"HTTP/1.0 400 Bad Request \r\nServer: Apache/2.0.46 (Unix) (Debian/Linux)\r\nContent-type: text/html\r\n\r\n")
tcpServices[_IMAP] = TcpService(143,'* OK 192.168.1.42 Cyrus IMAP v2.3.2-Debian-2.3.2 server ready\r\n')

def sendPaquet(trame, link):
	if trame.type == 2048:
		del(trame['IP'].chksum)
		if trame['IP'].proto == 6:
			del(trame['TCP'].chksum)
	os.write(link, str(trame))

def ackAndSend(trame, proto, ADRESSE_MAC, link):
	clientMacAdress = trame.src
	clientIpAdress = trame['IP'].src
	print "Receiving TCP ACK segment from %s@%s on port %d"%(clientIpAdress,clientMacAdress,trame['TCP'].dport)
	size = trame['IP'].len - (trame['IP'].ihl*4 + trame['TCP'].dataofs*4 )
	ackValue = int(trame['TCP'].seq)+size
			
	response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
	response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='PA',seq=int(trame['TCP'].ack),ack=ackValue)/tcpServices[proto].header
	sendPaquet(response,link)
			
	response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
	response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='FA',seq=int(trame['TCP'].ack)+len(tcpServices[proto].header),ack=ackValue)
	sendPaquet(response,link)

def getAndSend(trame, proto, ADRESSE_MAC, link):
# Receive PUSH flag : Http request.
	clientMacAdress = trame.src
	clientIpAdress = trame['IP'].src
	print "Receiving TCP PUSH segment from %s@%s on port %d"%(clientIpAdress,clientMacAdress, trame['TCP'].dport)
	size = trame['IP'].len - (trame['IP'].ihl*4 + trame['TCP'].dataofs*4 )
	request = trame.sprintf('%TCP.payload%')[:size]
	response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
	response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='A',seq=int(trame['TCP'].ack),ack=int(trame['TCP'].seq)+size)
	sendPaquet(response,link)

	result = reg_httpGetRoot.search(request)
	if(result):
		response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
		response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='PA',seq=int(trame['TCP'].ack),ack=int(trame['TCP'].seq)+size)/tcpServices[_HTTP_200].header
		sendPaquet(response,link)

		response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
		response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='FA',seq=int(trame['TCP'].ack)+len(tcpServices[_HTTP_200].header),ack=int(trame['TCP'].seq)+1)
		sendPaquet(response,link)
	else:
		result = reg_httpGetDefault.search(request)
		if(result):
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='PA',seq=int(trame['TCP'].ack),ack=int(trame['TCP'].seq)+size)/tcpServices[_HTTP_404].header
			sendPaquet(response,link)

			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='FA',seq=int(trame['TCP'].ack)+len(tcpServices[_HTTP_404].header),ack=int(trame['TCP'].seq)+1)
			sendPaquet(response,link)
		else:
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='PA',seq=int(trame['TCP'].ack),ack=int(trame['TCP'].seq)+size)/tcpServices[_HTTP_400].header
			sendPaquet(response,link)

			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='FA',seq=int(trame['TCP'].ack)+len(tcpServices[_HTTP_400].header),ack=int(trame['TCP'].seq)+1)
			sendPaquet(response,link)		
	
