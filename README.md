<a href="https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQv&s=os_gh"><img src="https://www.spiderfoot.net/wp-content/themes/spiderfoot/img/spiderfoot-wide.png"></a>


[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](https://raw.githubusercontent.com/smicallef/spiderfoot/master/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6+-green)](https://www.python.org)
[![Stable Release](https://img.shields.io/badge/version-3.1-blue.svg)](https://github.com/smicallef/spiderfoot/releases/tag/v3.1)
[![CI Status](https://img.shields.io/travis/smicallef/spiderfoot)](https://travis-ci.com/github/smicallef/spiderfoot)
[![Last Commit](https://img.shields.io/github/last-commit/smicallef/spiderfoot)](https://github.com/smicallef/spiderfoot/commits/master)
[![Libraries.io dependency status for latest release](https://img.shields.io/librariesio/release/github/smicallef/spiderfoot)](https://libraries.io/github/smicallef/spiderfoot)
[![Twitter Follow](https://img.shields.io/twitter/follow/spiderfoot?label=follow&style=social)](https://twitter.com/spiderfoot)

**SpiderFoot** is an open source intelligence (OSINT) automation tool. It integrates with just about every data source available and utilises a range of methods for data analysis, making that data easy to navigate. 

SpiderFoot has an embedded web-server for providing a clean and intuitive web-based interface but can also be used completely via the command-line.  It's written in **Python 3** and **GPL-licensed**.

<img src="https://www.spiderfoot.net/wp-content/uploads/2020/08/SpiderFoot-3.1-browse.png">

### FEATURES

- Web based UI or CLI
- Over 185 modules (see below)
- Python 3
- CSV/JSON/GEXF export
- API key export/import
- SQLite back-end for custom querying
- Highly configurable
- Fully documented
- Visualisations
- TOR integration for dark web searching
- Dockerfile for Docker-based deployments
- Can call other tools like DNSTwist, Whatweb, Nmap and CMSeeK
- Actively developed since 2012!

### USES

SpiderFoot can be used offensively (e.g. in a red team exercise or penetration test) for reconnaissance of your target or defensively to gather information about what you or your organisation might have exposed over the Internet.

You can target the following entities in a SpiderFoot scan:

 - IP address
 - Domain/sub-domain name
 - Hostname
 - Network subnet (CIDR)
 - ASN
 - E-mail address
 - Phone number
 - Username
 - Person's name
 
SpiderFoot's 185+ modules feed each other in a publisher/subscriber model to ensure maximum data extraction to do things like:

- [Host/sub-domain/TLD enumeration/extraction](https://asciinema.org/a/295912)
- [Email address, phone number and human name extraction](https://asciinema.org/a/295947)
- [Bitcoin and Ethereum address extraction](https://asciinema.org/a/295957)
- [Check for susceptibility to sub-domain hijacking](https://asciinema.org/a/344377)
- DNS zone transfers
- [Threat intelligence and Blacklist queries](https://asciinema.org/a/295949)
- API integraiton with [SHODAN](https://asciinema.org/a/127601), [HaveIBeenPwned](https://asciinema.org/a/128731), [GreyNoise](https://asciinema.org/a/295943), AlienVault, SecurityTrails, etc.
- [Social media account enumeration](https://asciinema.org/a/295923)
- [S3/Azure/Digitalocean bucket enumeration/scraping](https://asciinema.org/a/295941)
- IP geo-location
- Web scraping, web content analysis
- [Image, document and binary file meta data analysis](https://asciinema.org/a/296274)
- Dark web searches
- [Port scanning and banner grabbing](https://asciinema.org/a/295939)
- [Data breach searches](https://asciinema.org/a/296145)
- So much more...

### INSTALLING & RUNNING

To install and run SpiderFoot, you need at least Python 3.6 and a number of Python libraries which you can install with `pip`. We recommend you install a packaged release since master will often have bleeding edge features and modules that aren't fully tested.

#### As a packaged release (stable)

```
$ wget https://github.com/smicallef/spiderfoot/archive/v3.1.tar.gz
$ tar zxvf v3.1.tar.gz
$ cd spiderfoot
$ pip3 install -r requirements.txt
~/spiderfoot$ python3 ./sf.py -l 127.0.0.1:5001
```

#### From git (cloning master - may be buggy!):

```
$ git clone https://github.com/smicallef/spiderfoot.git
$ cd spiderfoot
$ pip3 install -r requirements.txt
~/spiderfoot$ python3 ./sf.py -l 127.0.0.1:5001
```

Check out the [documentation](https://www.spiderfoot.net/documentation) and our [asciinema videos](https://asciinema.org/~spiderfoot) for more tutorials.

### MODULES / INTEGRATIONS

| Name          | Description  |
|:-------------| :------------|
abuse.ch|Check if a host/domain, IP or netblock is malicious according to abuse.ch.|
AbuseIPDB|Check if an IP address is malicious according to AbuseIPDB.com.|
Account Finder|Look for possible associated accounts on nearly 200 websites like Ebay, Slashdot, reddit, etc.|
AdBlock Check|Check if linked pages would be blocked by AdBlock Plus.|
Ahmia|Search Tor 'Ahmia' search engine for mentions of the target domain.|
AlienVault IP Reputation|Check if an IP or netblock is malicious according to the AlienVault IP Reputation database.|
AlienVault OTX|Obtain information from AlienVault Open Threat Exchange (OTX)|
Amazon S3 Bucket Finder|Search for potential Amazon S3 buckets associated with the target and attempt to list their contents.|
Apility|Search Apility API for IP address and domain reputation.|
Archive.org|Identifies historic versions of interesting files/pages from the Wayback Machine.|
ARIN|Queries ARIN registry for contact information.|
Azure Blob Finder|Search for potential Azure blobs associated with the target and attempt to list their contents.|
Bad Packets|Obtain information about any malicious activities involving IP addresses found|
badips.com|Check if an IP address is malicious according to BadIPs.com.|
Bambenek C&C List|Check if a host/domain or IP appears on Bambenek Consulting's C&C tracker lists.|
Base64 Decoder|Identify Base64-encoded strings in any content and URLs, often revealing interesting hidden information.|
BGPView|Obtain network information from BGPView API.|
Binary String Extractor|Attempt to identify strings in binary content.|
BinaryEdge|Obtain information from BinaryEdge.io's Internet scanning systems about breaches, vulerabilities, torrents and passive DNS.|
Bing (Shared IPs)|Search Bing for hosts sharing the same IP.|
Bing|Obtain information from bing to identify sub-domains and links.|
Bitcoin Finder|Identify bitcoin addresses in scraped webpages.|
Blockchain|Queries blockchain.info to find the balance of identified bitcoin wallet addresses.|
blocklist.de|Check if a netblock or IP is malicious according to blocklist.de.|
BotScout|Searches botscout.com's database of spam-bot IPs and e-mail addresses.|
botvrij.eu|Check if a domain is malicious according to botvrij.eu.|
BuiltWith|Query BuiltWith.com's Domain API for information about your target's web technology stack, e-mail addresses and more.|
CallerName|Lookup US phone number location and reputation information.|
Censys|Obtain information from Censys.io|
Certificate Transparency|Gather hostnames from historical certificates in crt.sh.|
CINS Army List|Check if a netblock or IP address is malicious according to cinsscore.com's Army List.|
CIRCL.LU|Obtain information from CIRCL.LU's Passive DNS and Passive SSL databases.|
Cleanbrowsing.org|Check if a host would be blocked by Cleanbrowsing.org DNS|
CleanTalk Spam List|Check if a netblock or IP address is on CleanTalk.org's spam IP list.|
Clearbit|Check for names, addresses, domains and more based on lookups of e-mail addresses on clearbit.com.|
CloudFlare Malware DNS|Check if a host would be blocked by CloudFlare Malware-blocking DNS|
CoinBlocker Lists|Check if a host/domain or IP appears on CoinBlocker lists.|
CommonCrawl|Searches for URLs found through CommonCrawl.org.|
Comodo|Check if a host would be blocked by Comodo DNS|
Company Name Extractor|Identify company names in any obtained data.|
Cookie Extractor|Extract Cookies from HTTP headers.|
Country Name Extractor|Identify country names in any obtained data.|
Credit Card Number Extractor|Identify Credit Card Numbers in any data|
Cross-Referencer|Identify whether other domains are associated ('Affiliates') of the target.|
Custom Threat Feed|Check if a host/domain, netblock, ASN or IP is malicious according to your custom feed.|
cybercrime-tracker.net|Check if a host/domain or IP is malicious according to cybercrime-tracker.net.|
Darksearch|Search the Darksearch.io Tor search engine for mentions of the target domain.|
Digital Ocean Space Finder|Search for potential Digital Ocean Spaces associated with the target and attempt to list their contents.|
DNS Brute-forcer|Attempts to identify hostnames through brute-forcing common names and iterations.|
DNS Common SRV|Attempts to identify hostnames through common SRV.|
DNS Look-aside|Attempt to reverse-resolve the IP addresses next to your target to see if they are related.|
DNS Raw Records|Retrieves raw DNS records such as MX, TXT and others.|
DNS Resolver|Resolves Hosts and IP Addresses identified, also extracted from raw content.|
DNS Zone Transfer|Attempts to perform a full DNS zone transfer.|
DNSGrep|Obtain Passive DNS information from Rapid7 Sonar Project using DNSGrep API.|
DroneBL|Query the DroneBL database for open relays, open proxies, vulnerable servers, etc.|
DuckDuckGo|Query DuckDuckGo's API for descriptive information about your target.|
E-Mail Address Extractor|Identify e-mail addresses in any obtained data.|
EmailCrawlr|Search EmailCrawlr for email addresses and phone numbers associated with a domain.|
EmailFormat|Look up e-mail addresses on email-format.com.|
EmailRep|Search EmailRep.io for email address reputation.|
Emerging Threats|Check if a netblock or IP is malicious according to emergingthreats.net.|
Error String Extractor|Identify common error messages in content like SQL errors, etc.|
Ethereum Address Extractor|Identify ethereum addresses in scraped webpages.|
F-Secure Riddler.io|Obtain network information from F-Secure Riddler.io API.|
File Metadata Extractor|Extracts meta data from documents and images.|
Flickr|Search Flickr for domains, URLs and emails related to the specified domain.|
Fortiguard.com|Check if an IP is malicious according to Fortiguard.com.|
Fraudguard|Obtain threat information from Fraudguard.io|
Fringe Project|Obtain network information from Fringe Project API.|
FullContact|Gather domain and e-mail information from fullcontact.com.|
Github|Identify associated public code repositories on Github.|
Google Maps|Identifies potential physical addresses and latitude/longitude coordinates.|
Google Object Storage Finder|Search for potential Google Object Storage buckets associated with the target and attempt to list their contents.|
Google|Obtain information from the Google Custom Search API to identify sub-domains and links.|
Gravatar|Retrieve user information from Gravatar API.|
Greensnow|Check if a netblock or IP address is malicious according to greensnow.co.|
grep.app|Search grep.app API for links and emails related to the specified domain.|
Greynoise|Obtain information from Greynoise.io's Enterprise API.|
HackerOne (Unofficial)|Check external vulnerability scanning/reporting service h1.nobbd.de to see if the target is listed.|
HackerTarget|Search HackerTarget.com for hosts sharing the same IP.|
Hash Extractor|Identify MD5 and SHA hashes in web content, files and more.|
HaveIBeenPwned|Check HaveIBeenPwned.com for hacked e-mail addresses identified in breaches.|
Honeypot Checker|Query the projecthoneypot.org database for entries.|
Hosting Provider Identifier|Find out if any IP addresses identified fall within known 3rd party hosting ranges, e.g. Amazon, Azure, etc.|
Human Name Extractor|Attempt to identify human names in fetched content.|
Hunter.io|Check for e-mail addresses and names on hunter.io.|
IBAN Number Extractor|Identify IBAN Numbers in any data|
Iknowwhatyoudownload.com|Check iknowwhatyoudownload.com for IP addresses that have been using BitTorrent.|
Instagram|Gather information from Instagram profiles.|
IntelligenceX|Obtain information from IntelligenceX about identified IP addresses, domains, e-mail addresses and phone numbers.|
Interesting File Finder|Identifies potential files of interest, e.g. office documents, zip files.|
Internet Storm Center|Check if an IP is malicious according to SANS ISC.|
IPInfo.io|Identifies the physical location of IP addresses identified using ipinfo.io.|
ipstack|Identifies the physical location of IP addresses identified using ipstack.com.|
JsonWHOIS.com|Search JsonWHOIS.com for WHOIS records associated with a domain.|
Junk File Finder|Looks for old/temporary and other similar files.|
Keybase|Obtain additional information about target username|
Leak-Lookup|Searches Leak-Lookup.com's database of breaches.|
LeakIX|Search LeakIX for host data leaks, open ports, software and geoip.|
Maltiverse|Obtain information about any malicious activities involving IP addresses|
malwaredomainlist.com|Check if a host/domain, IP or netblock is malicious according to malwaredomainlist.com.|
malwaredomains.com|Check if a host/domain is malicious according to malwaredomains.com.|
MalwarePatrol|Searches malwarepatrol.net's database of malicious URLs/IPs.|
MetaDefender|Search MetaDefender API for IP address and domain IP reputation.|
Mnemonic PassiveDNS|Obtain Passive DNS information from PassiveDNS.mnemonic.no.|
multiproxy.org Open Proxies|Check if an IP is an open proxy according to multiproxy.org' open proxy list.|
MySpace|Gather username and location from MySpace.com profiles.|
NetworksDB|Search NetworksDB.io API for IP address and domain information.|
NeutrinoAPI|Search NeutrinoAPI for IP address info and check IP reputation.|
Norton ConnectSafe|Check if a host would be blocked by Norton ConnectSafe DNS|
numverify|Lookup phone number location and carrier information from numverify.com.|
Onion.link|Search Tor 'Onion City' search engine for mentions of the target domain.|
Onionsearchengine.com|Search Tor onionsearchengine.com for mentions of the target domain.|
Open Bug Bounty|Check external vulnerability scanning/reporting service openbugbounty.org to see if the target is listed.|
Open Passive DNS Database|Obtain passive DNS information from pdns.daloo.de Open passive DNS database.|
OpenCorporates|Look up company information from OpenCorporates.|
OpenDNS|Check if a host would be blocked by OpenDNS DNS|
OpenPhish|Check if a host/domain is malicious according to OpenPhish.com.|
OpenStreetMap|Retrieves latitude/longitude coordinates for physical addresses from OpenStreetMap API.|
Page Information|Obtain information about web pages (do they take passwords, do they contain forms, etc.)|
PasteBin|PasteBin scraping (via Google) to identify related content.|
PGP Key Servers|Look up e-mail addresses in PGP public key servers.|
PhishStats|Determine if an IP Address is malicious|
PhishTank|Check if a host/domain is malicious according to PhishTank.|
Phone Number Extractor|Identify phone numbers in scraped webpages.|
Port Scanner - TCP|Scans for commonly open TCP ports on Internet-facing systems.|
Psbdmp|Check psbdmp.cc (PasteBin Dump) for potentially hacked e-mails and domains.|
Pulsedive|Obtain information from Pulsedive's API.|
Quad9|Check if a host would be blocked by Quad9|
RIPE|Queries the RIPE registry (includes ARIN data) to identify netblocks and other info.|
RiskIQ|Obtain information from RiskIQ's (formerly PassiveTotal) Passive DNS and Passive SSL databases.|
Robtex|Search Robtex.com for hosts sharing the same IP.|
Scylla|Gather breach data from Scylla API.|
SecurityTrails|Obtain Passive DNS and other information from SecurityTrails|
SHODAN|Obtain information from SHODAN about identified IP addresses.|
Similar Domain Finder|Search various sources to identify similar looking domain names, for instance squatted domains.|
Skymem|Look up e-mail addresses on Skymem.|
SlideShare|Gather name and location from SlideShare profiles.|
Snov|Gather available email IDs from identified domains|
Social Media Profile Finder|Tries to discover the social media profiles for human names identified.|
Social Network Identifier|Identify presence on social media networks such as LinkedIn, Twitter and others.|
SORBS|Query the SORBS database for open relays, open proxies, vulnerable servers, etc.|
SpamCop|Query various spamcop databases for open relays, open proxies, vulnerable servers, etc.|
Spamhaus|Query the Spamhaus databases for open relays, open proxies, vulnerable servers, etc.|
spur.us|Obtain information about any malicious activities involving IP addresses found|
SpyOnWeb|Search SpyOnWeb for hosts sharing the same IP address, Google Analytics code, or Google Adsense code.|
Spyse|SpiderFoot plug-in to search Spyse API for IP address and domain information.|
SSL Certificate Analyzer|Gather information about SSL certificates used by the target's HTTPS sites.|
Strange Header Identifier|Obtain non-standard HTTP headers returned by web servers.|
Subdomain Takeover|Check if affiliated subdomains are vulnerable to takeover.|
Talos Intelligence|Check if a netblock or IP is malicious according to talosintelligence.com.|
ThreatCrowd|Obtain information from ThreatCrowd about identified IP addresses, domains and e-mail addresses.|
ThreatMiner|Obtain information from ThreatMiner's database for passive DNS and threat intelligence.|
TLD Searcher|Search all Internet TLDs for domains with the same name as the target (this can be very slow.)|
Tool - CMSeeK|Identify what Content Management System (CMS) might be used.|
Tool - DNSTwist|Identify bit-squatting, typo and other similar domains to the target using a local DNSTwist installation.|
Tool - Nmap|Identify what Operating System might be used.|
Tool - WhatWeb|Identify what software is in use on the specified website.|
TOR Exit Nodes|Check if an IP or netblock appears on the torproject.org exit node list.|
TORCH|Search Tor 'TORCH' search engine for mentions of the target domain.|
TotalHash.com|Check if a host/domain or IP is malicious according to TotalHash.com.|
Twilio|Obtain information from Twilio about phone numbers. Ensure you have the Caller Name add-on installed in Twilio.|
Twitter|Gather name and location from Twitter profiles.|
UCEPROTECT|Query the UCEPROTECT databases for open relays, open proxies, vulnerable servers, etc.|
URLScan.io|Search URLScan.io cache for domain information.|
Venmo|Gather user information from Venmo API.|
ViewDNS.info|Reverse Whois lookups using ViewDNS.info.|
VirusTotal|Obtain information from VirusTotal about identified IP addresses.|
VoIPBL OpenPBX IPs|Check if an IP or netblock is an open PBX according to VoIPBL OpenPBX IPs.|
VXVault.net|Check if a domain or IP is malicious according to VXVault.net.|
Watchguard|Check if an IP is malicious according to Watchguard's reputationauthority.org.|
Web Analytics Extractor|Identify web analytics IDs in scraped webpages and DNS TXT records.|
Web Framework Identifier|Identify the usage of popular web frameworks like jQuery, YUI and others.|
Web Server Identifier|Obtain web server banners to identify versions of web servers being used.|
Web Spider|Spidering of web-pages to extract content for searching.|
WhatCMS|Check web technology using WhatCMS.org API.|
Whoisology|Reverse Whois lookups using Whoisology.com.|
Whois|Perform a WHOIS look-up on domain names and owned netblocks.|
Whoxy|Reverse Whois lookups using Whoxy.com.|
Wigle.net|Query wigle.net to identify nearby WiFi access points.|
Wikileaks|Search Wikileaks for mentions of domain names and e-mail addresses.|
Wikipedia Edits|Identify edits to Wikipedia articles made from a given IP address or username.|
XForce Exchange|Obtain information from IBM X-Force Exchange|
Yandex DNS|Check if a host would be blocked by Yandex DNS|
Zone-H Defacement Check|Check if a hostname/domain appears on the zone-h.org 'special defacements' RSS feed.|

### DOCUMENTATION

Read more at the [project website](https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQv&s=os_gh), including more complete documentation, blog posts with tutorials/guides, plus information about [SpiderFoot HX](https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQvaHgvCg==&s=os_gh).

Latest updates announced on [Twitter](https://twitter.com/spiderfoot).
