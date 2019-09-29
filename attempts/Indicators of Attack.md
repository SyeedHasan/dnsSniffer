
Whether you use Snort, Suricata, or OSSEC, you can compose rules to report DNS requests from unauthorized clients. You can also compose rules to count or report NXDOMAIN responses, responses containing resource records with short TTLs, DNS queries made using TCP, DNS queries to nonstandard ports, suspiciously large DNS responses, etc. Any value in any field of the DNS query or response message is basically "in play." You're essentially limited only by your imagination and mastery of DNS. Intrusion prevention services in firewalls provide permit/deny rules for many of the most common of these checks.


## Important Websites

### Domain Hijacking
https://securitytrails.com/blog/most-popular-types-dns-attacks
Check a picture for NX Domain Attacks (#! Very Important)

### Report on Passive Analysis
https://www.symantec.com/content/dam/symantec/docs/research-papers/exposure-a-passive-dns-analysis-service-to-detect-and-report-malicious-domains-en.pdf

### Readings on NXDomain Hijacking
https://www.icann.org/en/system/files/files/sac-032-en.pdf

### SOA Packets
http://www.peerwisdom.org/2013/05/15/dns-understanding-the-soa-record/

#
## Traceroutes
https://github.com/farrokhi/dnsdiag/blob/master/dnstraceroute.py
https://github.com/secdev/scapy/blob/a864193915adff0e00bb5a9bcd3f2ffd62f9e43d/scapy/layers/inet.py

                    refresh = authNmSv.refresh
                    retry = authNmSv.retry
                    # Can extract minimum and expire fields as well
                    
                    # Issues with the TTL's
                    if (refresh < 1700 or refresh > 7200):
                        warnings.append("Refresh Interval: Possible Issue")

                    if (retry < 600 or retry > 3600):
                        warnings.append("Retry Interval: Possible Issue")
                    
                    if retry > refresh:
                        warnings.append("Retry is greater than Refresh Interval: Possible Issue")
