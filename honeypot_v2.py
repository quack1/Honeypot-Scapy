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
ADRESSE_IP = "172.16.229.42"
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
	if(ARP in trame):
		# Receive an ARP request : send an ARP response
		clientIpAdress=trame['ARP'].psrc
		print "Receiving ARP request from %s@%s"%(clientIpAdress,clientMacAdress)
		response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/ARP(op='is-at', hwsrc=ADRESSE_MAC, psrc=ADRESSE_IP, hwdst=clientMacAdress, pdst=clientIpAdress)
		os.write(link, str(response))
	elif(ICMP in trame):
		# Receive an ICMP echo-request : send an ICMP echo-reply
		clientIpAdress=trame['IP'].src
		print "Receiving ICMP request from %s@%s"%(clientIpAdress,clientMacAdress)
		response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)/ICMP(type='echo-reply',code=0,id=trame['ICMP'].id,seq=trame['ICMP'].seq)
		del response[ICMP].chksum
		del response[IP].chksum
		os.write(link, str(response))
	else:
		print "Not yet supported"
	
	
