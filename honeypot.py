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
import re
import struct
import time
import threading
import tcpResponse
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
_TCP_NULL = 'tcp_null'
_NULL = 'nil'
_FTP = 'ftp'
_SSH = 'ssh'
_SMTP = 'smtp'
_HTTP = 'http'
_IMAP = 'imap'

_LOG_DIR = "./log/"

reg_httpGetRoot = re.compile(r"GET / HTTP(.*)")
reg_httpGetDefault = re.compile(r"GET /(.*) HTTP(.*)")

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
	if trame.type == 2048 and trame['IP'].proto == 6 and trame['TCP'].dport == 25:
		return _SMTP
	if trame.type == 2048 and trame['IP'].proto == 6 and trame['TCP'].dport == 80:
		return _HTTP
	if trame.type == 2048 and trame['IP'].proto == 6 and trame['TCP'].dport == 143:
		return _IMAP
	if trame.type == 2048 and trame['IP'].proto == 6 and trame['TCP'].dport == 21:
		return _FTP
	if trame.type == 2048 and trame['IP'].proto == 6 :
		return _TCP_NULL			
	return _NULL 
	
def sendPaquet(trame):
	if trame.type == 2048:
		del(trame['IP'].chksum)
		if trame['IP'].proto == 6:
			del(trame['TCP'].chksum)
	os.write(link, str(trame))
	
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
		sendPaquet(response)
		
		
	elif trameType == _ICMP:
		# Receive an ICMP echo-request : send an ICMP echo-reply
		clientIpAdress = trame['IP'].src
		print "Receiving ICMP request from %s@%s"%(clientIpAdress,clientMacAdress)
		response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)/ICMP(type='echo-reply',code=0,id=trame['ICMP'].id,seq=trame['ICMP'].seq)
		sendPaquet(response)
		
		
	elif trameType in (_FTP, _SSH, 	_SMTP, _HTTP, _IMAP):
		clientIpAdress = trame['IP'].src
		
		if trame.sprintf('%TCP.flags%') == 'S':
			# Receive SYN flag : send SYN/ACK
			print "Receiving TCP SYN request from %s@%s on port %s"%(clientIpAdress,clientMacAdress, trame['TCP'].dport)
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='SA',seq=random.randint(1,45536),ack=int(trame['TCP'].seq)+1)
			sendPaquet(response)
					
		elif trame.sprintf('%TCP.flags%') == 'A':
			if trameType in (_SSH, _SMTP, _IMAP, _FTP):
				tcpResponse.ackAndSend(trame, trameType)
			elif trameType in(_HTTP):
				tcpReponse.getAndSend(trame, trameType)
							
		elif trame.sprintf('%TCP.flags%') == "FA":
			# Receive FIN flag : send FIN/ACK
			print "Receiving TCP FIN-ACK request from %s@%s on port %s"%(clientIpAdress,clientMacAdress, trame['TCP'].dport)
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='A',seq=int(trame['TCP'].ack),ack=int(trame['TCP'].seq)+1)
			sendPaquet(response)
							
		elif 'F' in trame.sprintf('%TCP.flags%'):
			# Receive FIN flag : send FIN/ACK
			print "Receiving TCP FIN request from %s@%s on port %s"%(clientIpAdress,clientMacAdress, trame['TCP'].dport)
			response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)
			response = response/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='FA',seq=int(trame['TCP'].ack),ack=int(trame['TCP'].seq)+1)
			sendPaquet(response)
					
	
	elif trameType == _TCP_NULL:
		# Receive a TCP segment, on an unsupported port : send a Reset-Ack segment
		clientIpAdress = trame['IP'].src
		print "Receiving TCP Syn request from %s@%s on an unsupported port %d"%(clientIpAdress,clientMacAdress,trame['TCP'].dport)
		response = Ether(src=ADRESSE_MAC,dst=clientMacAdress)/IP(src=ADRESSE_IP,dst=clientIpAdress)/TCP(dport=trame['TCP'].sport,sport=trame['TCP'].dport,flags='RA',ack=int(trame['TCP'].seq)+1)
		sendPaquet(response)

		
	elif trameType == _NULL:
		print "Not yet supported"
	
