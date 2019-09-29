import os
from scapy.all import *
a = ""

# ! Get running interfaces
# os.system("tcpdump -D > interfaces.txt")

# ! Only capture 5 packets, write it to the PCAP file and pipe it to TXT
# os.system("tcpdump -c 5 -w tcpDumpOp.pcap > a.txt")

# ! Read 100 packets and dump in PCAP file
# os.system("tcpdump -c 100 -w majorDump.pcap")

# ! Read the PCAP file for stats
captureFile = "tcpDumpOp.pcap"
captureFile2 = "majorDump.pcap"
data = rdpcap(captureFile)
data2 = rdpcap(captureFile2)

sessions = data2.sessions()
for session in sessions:
    http_payload = ""
    for packet in sessions[session]:
        try:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                print()
                print("A New Packet: ")
                print()
                print(packet[TCP].host)
        except:
            pass