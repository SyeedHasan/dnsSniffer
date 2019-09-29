import os
from scapy.all import *

os.system('sudo tshark -c 15 -f "udp port 53" -Y "dns.qry.type == 1 and dns.flags.response == 0"')
# ! Important Command : tshark -f "udp port 53" -Y "dns.qry.type == A and dns.flags.response == 0" -c 50 -w udpOutput.pcap

fileOp = rdpcap('udpOutput.pcap')
print(fileOp.dns)