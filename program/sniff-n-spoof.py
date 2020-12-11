#!/usr/bin/python3

from scapy.all import *

def spoof_reply(pkt):
    if(pkt[2].type == 8):
        print("Creating spoof packet...")

        dst = pkt[1].dst
        src = pkt[1].src
        ttl = pkt[1].ttl
        id_IP = pkt[1].id

        seq = pkt[2].seq
        id_ICMP = pkt[2].id

        '''
        If we want to add the load to the ICMP packet
        #load = pkt[3].load
        #reply = Ether(src=pkt[0].dst, dst=pkt[0].src, type=pkt[0].type)/IP(id=id_IP, ttl=ttl,src=dst, dst=src)/ICMP(type=0, code=0, id=id_ICMP, seq=seq)/load
        '''
    
        reply = Ether(src=pkt[0].dst, dst=pkt[0].src, type=pkt[0].type)/IP(id=id_IP, ttl=ttl,src=dst, dst=src)/ICMP(type=0, code=0, id=id_ICMP, seq=seq)

        # contruct the packet with a new checksum for the IP header
        del reply[IP].chksum

        # contruct the packet with a new checksum for the ICMP packet
        del reply[ICMP].chksum

        raw_bytes = reply.build()
        reply[IP].chksum = Ether(raw_bytes)[IP].chksum
        reply[ICMP].chksum = Ether(raw_bytes)[ICMP].chksum

        reply.show2()
        sendp(reply, iface="ens18")

if __name__=="__main__":

    # define the network interface
    iface = "ens18"

    # filter for only ICMP trafic
    filter = "icmp"

    # start sniffing
    sniff(iface=iface, prn=spoof_reply, filter=filter)