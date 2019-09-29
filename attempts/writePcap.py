
from scapy.all import *
from scapy.utils import PcapWriter

savedPkt = PcapWriter("appendedPcap.pcap", append=True, sync=True)
def savePackets(pkt):
    savedPkt.write(pkt)


def main():
    sniff(count=10, prn=savePackets)
    readPkts = rdpcap("appendedPcap.pcap")
    print(readPkts)

main()