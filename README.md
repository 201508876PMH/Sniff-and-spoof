# Sniff-and-spoof
The objective of this project is to spoof IP packets with an arbitrary source IP address. We will spoof ICMP echo reply packets for all hosts in the same local network, as a way to confuse a system administrator attempting to diagnose the network conditions. We will write a sniffer program that listens for ICMP echo request packets (as those generated by the ping tool) and spoofs a response back to the originating host. In other words, whenever the sniffer detects an ICMP echo request from A to B in the local network, it should immediately reply a spoofed ICMP echo reply from B to A.

Furthermore we will collect evidence of the malicious behavior through Wireshark and screenshots of replies received by the ping program running in the originating host.


# Results
#### Pinging the target machine

Picture of our program running in the background and us pinging the target machine.<br />

<img src="https://i.imgur.com/V0Crz8y.png" width="800">

#### Program output

Picture of our program output. We send back an Echo-reply of type 0, but could also spoof the system administrator by sending back a type 3 "Destination Unreachable" or a type 11 "Time exceeded".<br />

<img src="https://i.imgur.com/EWdkt9C.png" width="800">

#### WireShark image 

Picture of WireShark sniffing ICMP Echo-ping and ICMP Echo-reply. Where the Echo-reply packet is sent back from our program<br />
<img src="https://i.imgur.com/Uq6cX39.png" width="800">


## Prereqs for running ##
- pip install Scapy
- Disable pings on the machine to asure our program is hit
  - For windows: `netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=block`
  - For linux: `echo"1" > /proc/sys/net/ipv4/icmp_echo_ignore_all`
