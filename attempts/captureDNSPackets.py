import os
from scapy.all import *

# os.system("tcpdump -i wlo1 port 53 -c 150 -w dnsPacket.pcap")
a = rdpcap("dnsPacket.pcap")
for session in a.sessions():
    print(session)

    print("More information on that: ")
    # for packet in session:
    #     print(packet)