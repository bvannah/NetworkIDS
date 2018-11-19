#!/usr/bin/env python3
"""
This uses python3.6 and scapy2.4.0. My data structure of choice is the 
dictionary called SYNSenders.
SYNSenders is a dictionary containing the IP addresses of each person receiving
 SYN+ACK packets or sending ACK packets. The value of each dictionary IP item
 is a tuple of (# of SYN packets sent, # of SYN + ACK packets received)
"""

import sys
from scapy.all import *
SYNSenders={}
pcap=sys.argv[1]
for packet in PcapReader(pcap):
    if (packet.getlayer(IP)== None): #if it's not an IP packet, skip it
        continue
    flags=packet.sprintf('%TCP.flags%')
    rec=packet.getlayer(IP).dst#recipient IP address
    sen=packet.getlayer(IP).src#sender IP address
    if(flags == 'S'):
        if sen in SYNSenders: #IP address already listed, so just update values
            SYNSenders[sen]=(SYNSenders[sen][0]+1, SYNSenders[sen][1])
        else:
            SYNSenders[sen]=(1,0)
    if(flags == 'SA'):
        if rec in SYNSenders:
            SYNSenders[rec]=(SYNSenders[rec][0], SYNSenders[rec][1]+1)
        else:
            SYNSenders[rec]=(0,1)
            
shortlist=[]
for ip in SYNSenders:
    if((SYNSenders[ip][0] >= SYNSenders[ip][1]*3) & (SYNSenders[ip][0] > 1)):
        shortlist.append(ip)
        sys.stdout.write(ip + "\n")
