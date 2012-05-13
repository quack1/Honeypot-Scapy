#!/usr/bin/python
# -*- coding: utf-8 -*-

#-----------------------------
#				Imports
#-----------------------------
import commands
import fcntl
import os
import os.path
import random
import struct
import time
import threading
from scapy.all import *

#-----------------------------
#			Constantes
#-----------------------------
INTERFACE_NAME = "TAP_INTER"
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
ADRESSE_IP = "192.168.1.42"
ADRESSE_MAC = ""
_ARP = 'arp'
_ICMP = 'icmp'
_TCP = 'tcp'
_SSH = 'ssh'
_HTTP = 'http'
_TCP_NULL = 'tcp_null'
_NULL = 'nil'
_SSH_HEADER = "ssh-1.99-2.2.0\r\n"
_HTTP_HEADER = "HTTP/1.0 200 ok\r\nServer: Apache/2.0.46 (Unix) (Debian/Linux)\r\nContent-type: text/html\r\n\r\n"
_LOG_DIR = "./log/"

#-----------------------------
#			 Fonctions
#-----------------------------
def getMacAdress():
	return commands.getoutput("ip -o link show %s"%INTERFACE_NAME).split(' ')[-3]
def getTrameType(trame):
	if hex(trame.type) == '0x806' and trame.dst.upper() == "FF:FF:FF:FF:FF:FF" :
		return _ARP
	if trame.type == 2048 and trame['IP'].proto == 1 and trame['IP']['ICMP'].type == 8 : 
		return _ICMP
	if trame.type == 2048 and trame['IP'].proto == 6 and trame['TCP'].dport == 22:
		return _SSH
	if trame.type == 2048 and trame['IP'].proto == 6 and trame['TCP'].dport == 80:
		return _HTTP
	if trame.type == 2048 and trame['IP'].proto == 6 :
		return _TCP_NULL			
	return _NULL
def attackAttacker(ipAdress, macAdress):
	if not os.path.exists(_LOG_DIR):
		os.mkdir(_LOG_DIR)
	fd = file(_LOG_DIR + time.strftime('%y_%m_%d__%H_%M_%s',time.localtime()) , 'a')
	fd.write("Receive requests from %s (Mac adress : %s).\n\nResults of nmap : "%(ipAdress, macAdress))
	fd.write("%s"%commands.getoutput("nmap -sV %s"%ipAdress))
	fd.close()

visitors = []

#-----------------------------
#		Début du script
#-----------------------------
link = os.open("/dev/net/tun", os.O_RDWR)
interface = fcntl.ioctl(link, TUNSETIFF, struct.pack('16sH', INTERFACE_NAME, IFF_TAP | IFF_NO_PI))
print "Interface %s"%interface[:16].strip('\x00')

saisie = raw_input("Waiting for interface configuration...")

ADRESSE_MAC = getMacAdress()
print "Mac Adress : %s"%ADRESSE_MAC
runAgain = 1

while runAgain:
	packet = os.read(link, 2048)
	trame = Ether(packet)
	clientMacAdress = trame.src
	trameType = getTrameType(trame)
	
	if trame.type == 2048 and trame['IP'].src not in visitors:
		clientIpAdress = trame['IP'].src
		visitors.append(clientIpAdress)
		threading.Thread(target=attackAttacker,args=(clientIpAdress,clientMacAdress,)).start()
	
	if trameType == _ARP:
		# Receive an ARP request : send an ARP response
		clientIpAdress=trame['ARP'].psrc
		print "Receiving ARP request from %s@%s"%(clientIpAdress,clientMacAdress)
		response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/ARP(op='is-at',hwsrc=ADRESSE_MAC,psrc=ADRESSE_IP,hwdst=clientMacAdress,pdst=clientIpAdress)
		os.write(link, str(response))
		
		
	elif trameType == _ICMP:
		# Receive an ICMP echo-request : send an ICMP echo-reply
		clientIpAdress = trame['IP'].src
		print "Receiving ICMP request from %s@%s"%(clientIpAdress,clientMacAdress)
		response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)/ICMP(type='echo-reply',code=0,id=trame['ICMP'].id,seq=trame['ICMP'].seq)
		os.write(link, str(response))
		
		
	elif trameType == _SSH:
		# Receive a TCP segment, on port 22
		clientIpAdress = trame['IP'].src
		
		if trame.sprintf('%TCP.flags%') == 'S':
			# Receive SYN flag : send SYN/ACK
			print "Receiving TCP SYN request from %s@%s on SSH port 22"%(clientIpAdress,clientMacAdress)
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=22,flags='SA',seq=random.randint(1,45536),ack=int(trame['TCP'].seq)+1)
			os.write(link, str(response))
			
		elif trame.sprintf('%TCP.flags%') == 'A':
			# Receive ACK flag : Send server banner, and then stop connexion
			print "Receiving TCP ACK segment from %s@%s on SSH port 22"%(clientIpAdress,clientMacAdress)
			size = trame['IP'].len - (trame['IP'].ihl*4 + trame['TCP'].dataofs*4 )
			ackValue = int(trame['TCP'].seq)+size
			
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=22,flags='PA',seq=int(trame['TCP'].ack),ack=ackValue)/_SSH_HEADER
			os.write(link, str(response))
			
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=22,flags='FA',seq=int(trame['TCP'].ack)+len(_SSH_HEADER),ack=ackValue)
			os.write(link, str(response))
			
		elif 'F' in trame.sprintf('%TCP.flags%'):
			# Receive FIN flag : send FIN/ACK
			print "Receiving TCP FIN request from %s@%s on SSH port 22"%(clientIpAdress,clientMacAdress)
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=22,flags='FA',seq=int(trame['TCP'].ack),ack=int(trame['TCP'].seq)+1)
			os.write(link, str(response))
			

	elif trameType == _HTTP:
		# Receive a TCP segment, on port 80
		clientIpAdress = trame['IP'].src
		print "Receiving TCP on port 80,http"
		
		if trame.sprintf('%TCP.flags%') == 'S':
			# Receive SYN flag : send SYN/ACK
			print "Receiving TCP SYN request from %s@%s on HTTP port 80"%(clientIpAdress,clientMacAdress)
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=80,flags='SA',seq=random.randint(1,45536),ack=int(trame['TCP'].seq)+1)
			os.write(link, str(response))
			
		elif trame.sprintf('%TCP.flags%') == 'A':
			# Receive ACK flag.
			print "Receiving TCP ACK segment from %s@%s on HTTP port 80"%(clientIpAdress,clientMacAdress)
			size = trame['IP'].len - (trame['IP'].ihl*4 + trame['TCP'].dataofs*4 )
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=80,flags='PA',seq=int(trame['TCP'].ack),ack=int(trame['TCP'].seq)+size)
			os.write(link, str(response))
			
		elif "P" in trame.sprintf('%TCP.flags%') :
			# Receive PUSH flag : Http request.
			print "Receiving TCP ACK segment from %s@%s on HTTP port 80"%(clientIpAdress,clientMacAdress)
			size = trame['IP'].len - (trame['IP'].ihl*4 + trame['TCP'].dataofs*4 )
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=80,flags='A',seq=int(trame['TCP'].ack),ack=int(trame['TCP'].seq)+size)
			os.write(link, str(response))

			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=80,flags='PA',seq=int(trame['TCP'].ack),ack=int(trame['TCP'].seq)+size)/_HTTP_HEADER
			os.write(link, str(response))

			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=80,flags='FA',seq=int(trame['TCP'].ack)+len(_HTTP_HEADER),ack=int(trame['TCP'].seq)+1)
			os.write(link, str(response))
			
			
	elif trameType == _TCP_NULL:
		# Receive a TCP segment, on an unsupported port : send a Reset-Ack segment
		clientIpAdress = trame['IP'].src
		print "Receiving TCP Syn request from %s@%s on an unsupported port %d"%(clientIpAdress,clientMacAdress,trame['TCP'].dport)
		response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='RA',ack=int(trame['TCP'].seq)+1)
		os.write(link, str(response))
		
		
	elif trameType == _NULL:
		print "Not yet supported"
	
	
