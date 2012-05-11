#!/usr/bin/python
# -*- coding: utf-8 -*-

#-----------------------------
#				Imports
#-----------------------------
import commands
import fcntl
import os
import random
import struct
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
		print "Receiving TCP on port 22,ssh (flags : %s)"%trame['TCP'].flags
		
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
			response = response/TCP(dport=trame['TCP'].sport,sport=22,flags='PA',seq=int(trame['TCP'].ack),ack=ackValue)/"ssh-1.99-2.2.0\r\n"
			os.write(link, str(response))
			
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=22,flags='FA',seq=int(trame['TCP'].ack)+len(_SSH_HEADER),ack=ackValue)
			os.write(link, str(response))
					
			
	elif trameType == _HTTP:
		# Receive a TCP segment, on port 80
		continue
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
			
			
	elif trameType == _TCP_NULL:
		# Receive a TCP segment, on an unsupported port : send a Reset-Ack segment
		clientIpAdress = trame['IP'].src
		print "Receiving TCP Syn request from %s@%s on an unsupported port %d"%(clientIpAdress,clientMacAdress,trame['TCP'].dport)
		response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='RA',ack=int(trame['TCP'].seq)+1)
		os.write(link, str(response))
		
		
	elif trameType == _NULL:
		print "Not yet supported"
	
	
