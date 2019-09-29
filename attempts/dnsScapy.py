from scapy.all import *

# ? https://thepacketgeek.com/scapy-p-09-scapy-and-dns/
# ? https://theitgeekchronicles.files.wordpress.com/2012/05/scapyguide1.pdf

# sr1(IP(dst="10.1.99.2")/UDP()/DNS(rd=1,qd=DNSQR(qname="citrix.com",qtype= "NS")))

count = 0
def dissectPkt(pkt):
    # ! IMPORTANT: GOT ME THE SUMMARIZED FORM OF MY REQUEST!
    # print(ls(pkt[DNSQR]))
    # try:
        # print(pkt[DNS].rcode)
        # ! NXDomain Identifier
        # if(pkt[DNS].rcode == 3):
        #     print("There's a problem with this request!")
        #     print(pkt.summary())
        #     print()
            # print()
    # except:
    #     pass

    # try:
        # ls(pkt[IP])
    # ! Decode Packet! using decode utf 8
    dstIP = pkt[IP].dst
    b = pkt[DNSQR].qname
    b = str(b.decode('utf-8'))
    # ans, unans = traceroute(b, l4=UDP(sport=RandShort()) / DNS())
    # ans, unans = traceroute(b, dport=53)
    # ans, unans = traceroute('192.167.1.1', l4=UDP()/DNS())
    # ans, unans = traceroute(l4=UDP(sport=RandShort()) / DNS(qd=DNSQR(qname=b)))
    # print(unans)
    # print("ANS: ", ans)
    # print()
    # print()
    # ans,unans=traceroute('8.8.8.8', l4=UDP(sport=RandShort())/ DNS(qd=DNSQR(qname='www.facebook.com')))
    # print(unans)
    # print("ANS: ", ans)
    # print()
    ans, unans = traceroute("4.2.2.1",l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname="thesprawl.org")))
        # ! DNS Traceroutes
        # ls(pkt)
        # ! AUTH NAME SERVER!!!!!!!!
        # dnsList = [b'a.root-servers.net.', b'a.gtld-servers.net.']
        # if(pkt[DNS].nscount != 0):
        # ls(pkt[IP])
        # if (pkt[DNS].rcode == 3):
        #     for i in range(0, pkt[DNS].nscount):
        #         print("Auth. Name Server: " + str(pkt[DNS].ns[i].mname))

            # ls(pkt[DNS])
            # print(pkt[DNS].ns[0].mname)
            # dnsList.append(pkt[DNS].ns[0].mname)
            # print(dnsList)
            # if (pkt[DNS].ns[0].mname in dnsList):
            #     print("Wtf!")
            
            # # ? Refresh < 1700 > 7200
            # print(pkt[DNS].ns[0].refresh)

            # # ? Retry 600-3600 - should be less than refresh
            # print(pkt[DNS].ns[0].retry)


            # print(pkt[DNS].ns[0].minimum)
            # print(pkt[DNS].ns[0].expire)
            
        # ! AUTH NAME SERVER!!!!!!!!
        # ! GET auth name servers
        # for i in range (0,pkt[DNS].ancount):
        #     print("Domain = " + str(ls(pkt[DNS].an[i])))   
        # print(pkt[DNSQR].qname)
        # a = split(pkt[DNSQR].qname, "'")
        # print(a)
        # a = sr1(IP() / UDP() / DNS(rd=1, qd=DNSQR(qname=f"{pkt[DNSQR].qname}", qtype="NS")))
        # print(a)
        # print(ls(pkt[DNS]))
        # print(ls(pkt[IP]))
        #! Get the TTL
        # print(pkt[IP].ttl)
        # if (pkt[DNS].qr == 1):
        #     print(pkt.summary())
        #     print("Num of responses: ", pkt[DNS].ancount)
        #     # print("Authentic Data: " + pkt[DNS].ad)
        #     # print(ls(pkt[DNSQR]))
        #     qr = pkt.getlayer(DNSQR)  # DNS query
        #     print("Query Name: " + str(qr.qname))
        #     qtype_field = qr.get_field('qtype')
        #     qclass_field = qr.get_field('qclass')
        #     print("Query Type: " + str(qtype_field.i2repr(qr, qr.qtype)))
        #     print("Query Class: " + str(qclass_field.i2repr(qr, qr.qclass)))
        #     if (pkt.haslayer(DNSRR)):
        #         print("I have DNSRR!")

    # if (pkt.haslayer(UDP)):
    #     print("Protocol: UDP")
    # except:
    #     pass
    # ls(pkt)
    # print()
    try:
        # ls(pkt)
        a = 5/0
        print()
        print()
        print("THE DESTINATION ADDRESS IS:", pkt[2].dport)
        if (pkt[UDP]):
            print("TRANSPORT PROTOCOL: UDP")
            print()
            print("Presenting: UDP PACKET:")
            # print(ls(pkt[UDP]))
            print(pkt[UDP].qd.qname)
            print()
            print()
        elif (pkt[TCP]):
            print("ONEEEEEEEEEEEEEEEE TCP!!!!!!!!!!!!1 -----------")      
    except:
        pass

import subprocess
q = 'fb.wcom'
# sniff(filter="port 53", count=1, prn=dissectPkt)
# a = os.system(f'nslookup {q}')
res = subprocess.call(f'nslookup {q}', shell=True)

print(res)
# a = os.system('ping www.fb.com -c 5')
if res == 0:
    print('n n server is up n n')
else:
    print('server is down')

# ! Returns IMPORTANT DATA FROM DNS QUERY!
def dns_sniff_v2(pkt):
    if IP in pkt:
        if pkt.haslayer(DNS):
            dns = pkt.getlayer(DNS)
            pkt_time = pkt.sprintf('%sent.time%')

            if pkt.haslayer(DNSQR):
                qr = pkt.getlayer(DNSQR)  # DNS query
                qtype_field = qr.get_field('qtype')
                qclass_field = qr.get_field('qclass')
                values = [ pkt_time, str(dns.id), str(qr.qname), str(qtype_field.i2repr(qr, qr.qtype)), str(qclass_field.i2repr(qr, qr.qclass)) ]

            print("|".join(values))

# ! Run small function
def dns_sniff_v1(pkt):
    for x in range(pkt[DNS].ancount):
        print(pkt[DNS].an[x].rdata)    # to return the IP address
        print(pkt[DNS].an[x].rrname)   # to return the response record name
        print(pkt[DNS].qd.qname)  # to return the original query name
        print()

        # For a given DNS packet, handle the case for an A record
        if packet[DNS].qd.qtype == 1:
            for x in range(packet[DNS].ancount):
                if re.match(ip_address_pattern, packet[DNS].an[x].rdata) == None:
                    continue
                temp_dict = {packet[DNS].an[x].rdata:[packet[DNS].an[x].rrname,packet[DNS].qd.qname]}
        # And repeat the same process for the additional records by substituting ar for an

# sniff(iface="wlo1", filter="port 53", count=2, prn=dns_sniff_v1, store=0)