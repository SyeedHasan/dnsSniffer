# EBRYX ASSESSMENT PART -- 2
# Please check the file with this assessment for the explanation and hijacking explanation

# title           : sniffDNS.py
# description     : Script to sniff DNS packets for NXDomains
# author          : Syed Hasan
# date            : Sept 27 2019
# usage           : sudo python3 sniffDNS.py
# python_version  : 3.X

# Information     :

# The program is designed such that the sniff function continues until stopped explicitly
# OR 500 PACKETS ARE OBTAINED. YOU CAN REMOVE THE LIMIT FROM THE SNIFF FUNCTION BY
# REMOVING THE COUNT ARGUMENT 
# If you wish to stop the running the program, please quite it using CTRL+C

# The program outputs all QUERIES, RESPONSEs, AND NX DOMAIN RESPONSES to the STDOUT
# It  appends the NX DOMAIN responses to the JSON file only
# If you wish to view all traffic, check the PCAP file attached

# ==============================================================================

# Library imports
import json, sys, subprocess

try:
    from scapy.all import *
    from scapy.utils import PcapWriter

except ImportError:
    print("Please install scapy using pip install scapy")
    print("If you've installed it, please see if any other error might be present in the import")
    sys.exit(1)

def savePackets(pktDict):
    '''Saves Packet Information'''
    
    try:
        with open('nxPackets.json', 'a+', encoding='utf-8') as f:
            json.dump(pktDict, f, ensure_ascii=False, indent=4, separators=(',', ': '))

        print("NXDOMAIN: A packet was written to the file...")                        
    except:
        print("An unidentified error has occured during I/O operations.")

def sniffPkts():
    '''Sniffs on port 53 (DNS traffic) and handles the callback function'''

    def dissectPkts(pkt):
        '''Callback to handle each packet from the traffic'''
        protocol = ''
        warnings = []
        nameServers = []
        nxDomainPackets = {}

        try:
            if (pkt[DNS]):
                pass
        except IndexError: #Specified layer wasn't found
            print("Packet doesn't contain the desired layer. Continuing...")    

        # DNS Reuqest - Query or Response
        dnsReq = pkt.getlayer(DNS)

        # It's a DNS query!
        if dnsReq.qr == 0:
            print("Query: ", pkt.summary())

        # It's a DNS Response - which we need
        elif dnsReq.qr == 1:
            # Indicates a "no name" from the response of the query    
            if ((dnsReq.rcode == 3)):
                # Get response code
                respCode = dnsReq.get_field('rcode')
                nxDomainPackets['rcode'] = respCode.i2repr(dnsReq, dnsReq.rcode)

                # Get query
                if (pkt.haslayer(DNSQR)):
                    qr = pkt.getlayer(DNSQR)
                    qname = qr.qname.decode('utf-8')
                    qtype_field = qr.get_field('qtype')
                    qclass_field = qr.get_field('qclass')
                    
                    nxDomainPackets['Query'] = {
                        'Name': qname,
                        'Type': qtype_field.i2repr(qr, qr.qtype), 
                            # Helper function to convert value to symbolic value
                        'Class': qclass_field.i2repr(qr, qr.qclass)
                    }
                
                # Get protocol
                # nxDomainPackets['Protocol'] = 'UDP' if pkt.haslayer(UDP) else 'TCP'
                if (pkt.haslayer(UDP)):
                    protocol = 'UDP'
                elif (pkt.haslayer(TCP)):
                    protocol = 'TCP'
                else:
                    protocol = 'Incorrect Protocol!'
                
                nxDomainPackets['Protocol'] = protocol


                # Get destination port
                nxDomainPackets['Dest. Port'] = pkt[IP].dport

                #Get Auth. Name Servers
                for i in range(0, dnsReq.nscount):
                    authNmSv = dnsReq.ns[i]
                    # Extract Primary Name Server
                    primaryNmSv = authNmSv.mname
                    # Append it to auth name server for given domain
                    nameServers.append(primaryNmSv.decode('utf-8'))

                nxDomainPackets['AuthNameSv'] = nameServers

                # Identifying whether the request is malicious or not
                # Lookup
                res = subprocess.call(f'nslookup {qname}', shell=True, stdout=subprocess.DEVNULL)
                if res == 0:
                    warnings.append('Possible Hijacking!')
                else: #Properly idetified an NXDOMAIN
                    warnings.append('None')

                # Test through DNS traceroutes as well...

                nxDomainPackets['Warnings'] = warnings

                # Save packets to a JSON file
                savePackets(nxDomainPackets)
            # Indicates a different type of response
            else:
                print("Normal Response: ", pkt.summary())

        else:
            # Indicates a normal DNS query or response
            print(pkt.summary())

        # Save packet to PCAP file
        dnsTraffic.write(pkt)

    try:     
        # Setup the PCAP file for packet capture
        # New session for each time you run the program...
        dnsTraffic = PcapWriter("all-dns-traffic.pcap", sync=True) #append=True for append
        
        sniff(filter="port 53", count=500, prn=dissectPkts)

    except PermissionError:
        print("Unfortunately, you need SUDO priviliges or ROOT user priviliges to run the program.")
        print("Try: sudo python3 sniffDNS.py")
        sys.exit(1)

def main():
    '''Main function to handle sniffing and file handling'''
    sniffPkts()

if __name__ == "__main__":
    main()