#!/usr/bin/python

# marco.py
#  Sends arp requests to the entire network range searching for the first response.
#  Creates a second thread to monitor for responses to allow the sending thread to just spew packets.
#  The whole point is to find a valid IP when on a completely quiet network segment without DHCP
#  or any other means to find a valid address.  
#  I couldn't seem to figure out how to get nmap to do an arp sweep on a network range that I didn't have 
#  an IP/interface associated with.  
# Requires: 
#  ipaddr (http://code.google.com/p/ipaddr-py/) and of course scapy (http://www.secdev.org/projects/scapy/)

import ipaddr
import sys
import logging
import getopt
import time

from scapy import *
from threading import Thread

class ArpMonitorThread(Thread):
	def __init__(self, map):
		Thread.__init__(self)
		self.map = map
		self.found = []

	def arp_callback(self, pkt):
		if pkt[ARP].op == 2:
			if pkt[ARP].psrc not in self.found:
				print pkt[ARP].sprintf("%psrc% (%hwsrc%)")
				self.found.append(pkt[ARP].psrc)

			if self.map == False:
				sys.exit(0)

	def run(self):
		sniff(filter='(arp) and (not ether dst host ff:ff:ff:ff:ff:ff)', store=0, prn=self.arp_callback)

def usage():
	print "python marco.py [-i <iface>] [-n <network/range>] [-t <timeout>] [-s <saddr>] [-c <count>] [-m] [-h]"
	print "\tiface: network interface to send and listen on. (default: lo)"
	print "\tnetwork/range: network to scan in CIDR notation. (default: 127.0.0.1)"
	print "\ttimeout: how long to wait for responses after sending. (default: 0)"
	print "\tsaddr: source address to originate the arp packets from. (default: 127.0.0.1)"
	print "\tcount: number of times to send the packets (default: 1)"
	print "\t-m: Find all hosts on the network not just the first response (default: disabled)"
	sys.exit(0)

# Defaults
network = '127.0.0.1'
saddr = '127.0.0.1'
iface = 'lo'
count = 1
map = False
timeout = 0

# Parse our arguments
try:
	opts, args = getopt.gnu_getopt(sys.argv[1:], 'i:n:t:s:c:hm', ['interface=', 'network=', 'timeout=', 'saddr=', 'count='])
except getopt.GetoptError, err:
	usage()
	
for o, a in opts:
	if o in ('-i', '--interface') :
		iface = a
	elif o in ('-n', '--network'):
		network = a
	elif o in ('-t', '--timeout'):
		timeout = int(a)
	elif o in ('-s', '--saddr'):
		saddr = a
	elif o in ('-c', '--count'):
		count = (int(a) if (int(a) > 0) else 1) 
	elif o == '-m':
		map = True
	else:
		usage()

# Start the response monitor first
ArpMonitorThread(map).start()

# Create our packet list
pkts = []
for ip in ipaddr.IPv4(network):
	pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(psrc=saddr, pdst=ip))

# Send our packets
for i in range(1, count): 
	sendp(pkts, verbose=0, iface=iface)

# Sleep to make sure we get everything
time.sleep(timeout)

# All packets have been sent
sys.exit(0)
