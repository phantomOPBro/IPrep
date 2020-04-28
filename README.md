You need an API key for AbuseIPDB and an auth key for auth0 - make sure to place them as strings. Run the code and you'll get a print out. 

Example: 

phantomOPBro$ python IPrep.py 
What IP would you like to see results for? 62.210.88.239

=========================


IP Address in Question: 62.210.88.239
Country: FR

=========================



According to auth0:  Malicious



=========================

This IP does not appear in the Emerging Threats Compromised IP list.

=========================

This IP does not appear in the MyIP.MS Real-Time Blacklist database.

=========================



According to Open Threat Exchange, this IP has been reported 2 times. 
These were the names of the IOC dumps containing this IP: 
- Apache honeypot logs for 09/Apr/2020
- Apache honeypot logs for 12/Mar/2020

=========================

According to AbuseIPDB, this IP has been reported for abuse 140 times in the past 90 days. The IP has been reported for the following reasons:
- DDoS Attack Participating in distributed denial-of-service (usually part of botnet).
- Ping of Death Oversized IP packet.
- Web Spam Comment/forum spam, HTTP referer spam, or other CMS spam.
- Port Scan Scanning for open ports and vulnerable services.
- Use of Penetration Testing Tools
- Brute-Force Credential brute-force attacks on webpage logins and services like SSH, FTP, SIP, SMTP, RDP, etc.
- Bad Web Bot Webpage scraping (for email addresses, content, etc) and crawlers that do not honor robots.txt.
- Exploited Host: Host is likely infected with malware and being used for other attacks or to host malicious content. The host owner may not be aware of the compromise.
- Web App Attack Attempts to probe for or exploit installed web applications such as a CMS like WordPress/Drupal, e-commerce solutions, forum software, phpMyAdmin and various other software plugins/solutions.
- SSH Secure Shell (SSH) abuse.

=========================

+++++++++++++++++++++++++

Overall Recommendation: Block
Overall score: 4 out of 6 points.

+++++++++++++++++++++++++

