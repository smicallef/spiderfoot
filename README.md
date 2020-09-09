<a href="https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQv&s=os_gh"><img src="https://www.spiderfoot.net/wp-content/themes/spiderfoot/img/spiderfoot-wide.png"></a>


[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](https://raw.githubusercontent.com/smicallef/spiderfoot/master/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6+-green)](https://www.python.org)
[![Stable Release](https://img.shields.io/badge/version-3.2.1-blue.svg)](https://github.com/smicallef/spiderfoot/releases/tag/v3.2.1)
[![CI Status](https://img.shields.io/travis/smicallef/spiderfoot)](https://travis-ci.com/github/smicallef/spiderfoot)
[![Last Commit](https://img.shields.io/github/last-commit/smicallef/spiderfoot)](https://github.com/smicallef/spiderfoot/commits/master)
[![Libraries.io dependency status for latest release](https://img.shields.io/librariesio/release/github/smicallef/spiderfoot)](https://libraries.io/github/smicallef/spiderfoot)
[![Codecov](https://codecov.io/github/smicallef/spiderfoot/coverage.svg)](https://codecov.io/github/smicallef/spiderfoot)
[![Twitter Follow](https://img.shields.io/twitter/follow/spiderfoot?label=follow&style=social)](https://twitter.com/spiderfoot)

**SpiderFoot** is an open source intelligence (OSINT) automation tool. It integrates with just about every data source available and utilises a range of methods for data analysis, making that data easy to navigate. 

SpiderFoot has an embedded web-server for providing a clean and intuitive web-based interface but can also be used completely via the command-line.  It's written in **Python 3** and **GPL-licensed**.

<img src="https://www.spiderfoot.net/wp-content/uploads/2020/08/SpiderFoot-3.1-browse.png">

### FEATURES

- Web based UI or CLI
- Over 190 modules (see below)
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
 
SpiderFoot's 190+ modules feed each other in a publisher/subscriber model to ensure maximum data extraction to do things like:

- [Host/sub-domain/TLD enumeration/extraction](https://asciinema.org/a/295912)
- [Email address, phone number and human name extraction](https://asciinema.org/a/295947)
- [Bitcoin and Ethereum address extraction](https://asciinema.org/a/295957)
- [Check for susceptibility to sub-domain hijacking](https://asciinema.org/a/344377)
- DNS zone transfers
- [Threat intelligence and Blacklist queries](https://asciinema.org/a/295949)
- API integration with [SHODAN](https://asciinema.org/a/127601), [HaveIBeenPwned](https://asciinema.org/a/128731), [GreyNoise](https://asciinema.org/a/295943), AlienVault, SecurityTrails, etc.
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

#### Stable build (packaged release):

```
$ wget https://github.com/smicallef/spiderfoot/archive/v3.2.1.tar.gz
$ tar zxvf v3.2.1.tar.gz
$ cd spiderfoot
~/spiderfoot$ pip3 install -r requirements.txt
~/spiderfoot$ python3 ./sf.py -l 127.0.0.1:5001
```

#### Development build (cloning git master branch):

```
$ git clone https://github.com/smicallef/spiderfoot.git
$ cd spiderfoot
$ pip3 install -r requirements.txt
~/spiderfoot$ python3 ./sf.py -l 127.0.0.1:5001
```

Check out the [documentation](https://www.spiderfoot.net/documentation) and our [asciinema videos](https://asciinema.org/~spiderfoot) for more tutorials.

### MODULES / INTEGRATIONS

SpiderFoot has over 190 modules, most of which *don't require API keys*, and many of those that do require API keys *have a free tier*.

| Name         | Description  | Link       |
|:-------------| :------------| :----------|
abuse.ch|Check if a host/domain, IP or netblock is malicious according to abuse.ch.|[https://www.abuse.ch](https://www.abuse.ch)
AbuseIPDB|Check if an IP address is malicious according to AbuseIPDB.com.|[https://www.abuseipdb.com](https://www.abuseipdb.com)
Account Finder|Look for possible associated accounts on nearly 200 websites like Ebay, Slashdot, reddit, etc.|
AdBlock Check|Check if linked pages would be blocked by AdBlock Plus.|[https://adblockplus.org/](https://adblockplus.org/)
Ahmia|Search Tor 'Ahmia' search engine for mentions of the target domain.|[https://ahmia.fi/](https://ahmia.fi/)
AlienVault IP Reputation|Check if an IP or netblock is malicious according to the AlienVault IP Reputation database.|[https://cybersecurity.att.com/](https://cybersecurity.att.com/)
AlienVault OTX|Obtain information from AlienVault Open Threat Exchange (OTX)|[https://otx.alienvault.com/](https://otx.alienvault.com/)
Amazon S3 Bucket Finder|Search for potential Amazon S3 buckets associated with the target and attempt to list their contents.|[https://aws.amazon.com/s3/](https://aws.amazon.com/s3/)
Apility|Search Apility API for IP address and domain reputation.|[https://auth0.com/signals](https://auth0.com/signals)
Archive.org|Identifies historic versions of interesting files/pages from the Wayback Machine.|[https://archive.org/](https://archive.org/)
ARIN|Queries ARIN registry for contact information.|[https://www.arin.net/](https://www.arin.net/)
Azure Blob Finder|Search for potential Azure blobs associated with the target and attempt to list their contents.|[https://azure.microsoft.com/en-in/services/storage/blobs/](https://azure.microsoft.com/en-in/services/storage/blobs/)
Bad Packets|Obtain information about any malicious activities involving IP addresses found|[https://badpackets.net](https://badpackets.net)
badips.com|Check if an IP address is malicious according to BadIPs.com.|[https://www.badips.com/](https://www.badips.com/)
Bambenek C&C List|Check if a host/domain or IP appears on Bambenek Consulting's C&C tracker lists.|[http://www.bambenekconsulting.com/](http://www.bambenekconsulting.com/)
Base64 Decoder|Identify Base64-encoded strings in any content and URLs, often revealing interesting hidden information.|
BGPView|Obtain network information from BGPView API.|[https://bgpview.io/](https://bgpview.io/)
Binary String Extractor|Attempt to identify strings in binary content.|
BinaryEdge|Obtain information from BinaryEdge.io Internet scanning systems, including breaches, vulnerabilities, torrents and passive DNS.|[https://www.binaryedge.io/](https://www.binaryedge.io/)
Bing (Shared IPs)|Search Bing for hosts sharing the same IP.|[https://www.bing.com/](https://www.bing.com/)
Bing|Obtain information from bing to identify sub-domains and links.|[https://www.bing.com/](https://www.bing.com/)
Bitcoin Finder|Identify bitcoin addresses in scraped webpages.|
BitcoinAbuse|Check bitcoin address against bitcoinabuse.com database|[https://www.bitcoinabuse.com/](https://www.bitcoinabuse.com/)
Blockchain|Queries blockchain.info to find the balance of identified bitcoin wallet addresses.|[https://www.blockchain.com/](https://www.blockchain.com/)
blocklist.de|Check if a netblock or IP is malicious according to blocklist.de.|[http://www.blocklist.de/en/index.html](http://www.blocklist.de/en/index.html)
BotScout|Searches botscout.com's database of spam-bot IPs and e-mail addresses.|[http://botscout.com/](http://botscout.com/)
botvrij.eu|Check if a domain is malicious according to botvrij.eu.|
BuiltWith|Query BuiltWith.com's Domain API for information about your target's web technology stack, e-mail addresses and more.|[https://builtwith.com/](https://builtwith.com/)
C99|This module queries c99 API that offers various data (geo location, proxy detection, phone lookup, etc).|[https://api.c99.nl/](https://api.c99.nl/)
CallerName|Lookup US phone number location and reputation information.|[http://callername.com/](http://callername.com/)
Censys|Obtain information from Censys.io|[https://censys.io/](https://censys.io/)
Certificate Transparency|Gather hostnames from historical certificates in crt.sh.|[https://crt.sh/](https://crt.sh/)
CINS Army List|Check if a netblock or IP address is malicious according to cinsscore.com's Army List.|
CIRCL.LU|Obtain information from CIRCL.LU's Passive DNS and Passive SSL databases.|[https://www.circl.lu/](https://www.circl.lu/)
Cleanbrowsing.org|Check if a host would be blocked by Cleanbrowsing.org DNS|[https://cleanbrowsing.org/](https://cleanbrowsing.org/)
CleanTalk Spam List|Check if a netblock or IP address is on CleanTalk.org's spam IP list.|[https://cleantalk.org](https://cleantalk.org)
Clearbit|Check for names, addresses, domains and more based on lookups of e-mail addresses on clearbit.com.|[https://clearbit.com/](https://clearbit.com/)
CloudFlare Malware DNS|Check if a host would be blocked by CloudFlare Malware-blocking DNS|[https://www.cloudflare.com/](https://www.cloudflare.com/)
CoinBlocker Lists|Check if a host/domain or IP appears on CoinBlocker lists.|[https://zerodot1.gitlab.io/CoinBlockerListsWeb/](https://zerodot1.gitlab.io/CoinBlockerListsWeb/)
CommonCrawl|Searches for URLs found through CommonCrawl.org.|[http://commoncrawl.org/](http://commoncrawl.org/)
Comodo|Check if a host would be blocked by Comodo DNS|[https://www.comodo.com/secure-dns/](https://www.comodo.com/secure-dns/)
Company Name Extractor|Identify company names in any obtained data.|
Cookie Extractor|Extract Cookies from HTTP headers.|
Country Name Extractor|Identify country names in any obtained data.|
Credit Card Number Extractor|Identify Credit Card Numbers in any data|
Crobat API|Search Crobat API for subdomains.|
Cross-Referencer|Identify whether other domains are associated ('Affiliates') of the target.|
Custom Threat Feed|Check if a host/domain, netblock, ASN or IP is malicious according to your custom feed.|
cybercrime-tracker.net|Check if a host/domain or IP is malicious according to cybercrime-tracker.net.|[http://cybercrime-tracker.net/](http://cybercrime-tracker.net/)
Darksearch|Search the Darksearch.io Tor search engine for mentions of the target domain.|[https://darksearch.io/](https://darksearch.io/)
Digital Ocean Space Finder|Search for potential Digital Ocean Spaces associated with the target and attempt to list their contents.|[https://www.digitalocean.com/products/spaces/](https://www.digitalocean.com/products/spaces/)
DNS Brute-forcer|Attempts to identify hostnames through brute-forcing common names and iterations.|
DNS Common SRV|Attempts to identify hostnames through common SRV.|
DNS Look-aside|Attempt to reverse-resolve the IP addresses next to your target to see if they are related.|
DNS Raw Records|Retrieves raw DNS records such as MX, TXT and others.|
DNS Resolver|Resolves Hosts and IP Addresses identified, also extracted from raw content.|
DNS Zone Transfer|Attempts to perform a full DNS zone transfer.|
DNSGrep|Obtain Passive DNS information from Rapid7 Sonar Project using DNSGrep API.|[https://opendata.rapid7.com/](https://opendata.rapid7.com/)
DroneBL|Query the DroneBL database for open relays, open proxies, vulnerable servers, etc.|[https://dronebl.org/](https://dronebl.org/)
DuckDuckGo|Query DuckDuckGo's API for descriptive information about your target.|[https://duckduckgo.com/](https://duckduckgo.com/)
E-Mail Address Extractor|Identify e-mail addresses in any obtained data.|
EmailCrawlr|Search EmailCrawlr for email addresses and phone numbers associated with a domain.|[https://emailcrawlr.com/](https://emailcrawlr.com/)
EmailFormat|Look up e-mail addresses on email-format.com.|[https://www.email-format.com/](https://www.email-format.com/)
EmailRep|Search EmailRep.io for email address reputation.|[https://emailrep.io/](https://emailrep.io/)
Emerging Threats|Check if a netblock or IP is malicious according to emergingthreats.net.|[https://rules.emergingthreats.net/](https://rules.emergingthreats.net/)
Error String Extractor|Identify common error messages in content like SQL errors, etc.|
Ethereum Address Extractor|Identify ethereum addresses in scraped webpages.|
F-Secure Riddler.io|Obtain network information from F-Secure Riddler.io API.|[https://riddler.io/](https://riddler.io/)
File Metadata Extractor|Extracts meta data from documents and images.|
Flickr|Search Flickr for domains, URLs and emails related to the specified domain.|[https://www.flickr.com/](https://www.flickr.com/)
Fortiguard.com|Check if an IP is malicious according to Fortiguard.com.|[https://fortiguard.com/](https://fortiguard.com/)
Fraudguard|Obtain threat information from Fraudguard.io|[https://fraudguard.io/](https://fraudguard.io/)
Fringe Project|Obtain network information from Fringe Project API.|[https://fringeproject.com/](https://fringeproject.com/)
FullContact|Gather domain and e-mail information from fullcontact.com.|[https://www.fullcontact.com](https://www.fullcontact.com)
Github|Identify associated public code repositories on Github.|[https://github.com/](https://github.com/)
Google Maps|Identifies potential physical addresses and latitude/longitude coordinates.|[https://cloud.google.com/maps-platform/](https://cloud.google.com/maps-platform/)
Google Object Storage Finder|Search for potential Google Object Storage buckets associated with the target and attempt to list their contents.|[https://cloud.google.com/storage](https://cloud.google.com/storage)
Google SafeBrowsing|Check if the URL is included on any of the Safe Browsing lists.|[https://developers.google.com/safe-browsing/v4/lookup-api](https://developers.google.com/safe-browsing/v4/lookup-api)
Google|Obtain information from the Google Custom Search API to identify sub-domains and links.|[https://developers.google.com/custom-search](https://developers.google.com/custom-search)
Gravatar|Retrieve user information from Gravatar API.|[https://secure.gravatar.com/](https://secure.gravatar.com/)
Greensnow|Check if a netblock or IP address is malicious according to greensnow.co.|[https://greensnow.co/](https://greensnow.co/)
grep.app|Search grep.app API for links and emails related to the specified domain.|[https://grep.app/](https://grep.app/)
Greynoise|Obtain information from Greynoise.io's Enterprise API.|[https://greynoise.io/](https://greynoise.io/)
HackerOne (Unofficial)|Check external vulnerability scanning/reporting service h1.nobbd.de to see if the target is listed.|[http://www.nobbd.de/](http://www.nobbd.de/)
HackerTarget|Search HackerTarget.com for hosts sharing the same IP.|[https://hackertarget.com/](https://hackertarget.com/)
Hash Extractor|Identify MD5 and SHA hashes in web content, files and more.|
HaveIBeenPwned|Check HaveIBeenPwned.com for hacked e-mail addresses identified in breaches.|[https://haveibeenpwned.com/](https://haveibeenpwned.com/)
Honeypot Checker|Query the projecthoneypot.org database for entries.|[https://www.projecthoneypot.org/](https://www.projecthoneypot.org/)
Host.io|Obtain information about domain names from host.io.|[https://host.io](https://host.io)
Hosting Provider Identifier|Find out if any IP addresses identified fall within known 3rd party hosting ranges, e.g. Amazon, Azure, etc.|
Human Name Extractor|Attempt to identify human names in fetched content.|
Hunter.io|Check for e-mail addresses and names on hunter.io.|[https://hunter.io/](https://hunter.io/)
Hybrid Analysis|Search Hybrid Analysis for domains and URLs related to the target.|[https://www.hybrid-analysis.com](https://www.hybrid-analysis.com)
IBAN Number Extractor|Identify IBAN Numbers in any data|
Iknowwhatyoudownload.com|Check iknowwhatyoudownload.com for IP addresses that have been using BitTorrent.|[https://iknowwhatyoudownload.com/en/peer/](https://iknowwhatyoudownload.com/en/peer/)
Instagram|Gather information from Instagram profiles.|[https://www.instagram.com/](https://www.instagram.com/)
IntelligenceX|Obtain information from IntelligenceX about identified IP addresses, domains, e-mail addresses and phone numbers.|[https://intelx.io/](https://intelx.io/)
Interesting File Finder|Identifies potential files of interest, e.g. office documents, zip files.|
Internet Storm Center|Check if an IP is malicious according to SANS ISC.|[https://isc.sans.edu](https://isc.sans.edu)
IPInfo.io|Identifies the physical location of IP addresses identified using ipinfo.io.|[https://ipinfo.io](https://ipinfo.io)
ipstack|Identifies the physical location of IP addresses identified using ipstack.com.|[https://ipstack.com/](https://ipstack.com/)
JsonWHOIS.com|Search JsonWHOIS.com for WHOIS records associated with a domain.|[https://jsonwhois.com](https://jsonwhois.com)
Junk File Finder|Looks for old/temporary and other similar files.|
Keybase|Obtain additional information about target username|[https://keybase.io/](https://keybase.io/)
Leak-Lookup|Searches Leak-Lookup.com's database of breaches.|[https://leak-lookup.com/](https://leak-lookup.com/)
LeakIX|Search LeakIX for host data leaks, open ports, software and geoip.|[https://leakix.net/](https://leakix.net/)
Maltiverse|Obtain information about any malicious activities involving IP addresses|[https://maltiverse.com](https://maltiverse.com)
malwaredomainlist.com|Check if a host/domain, IP or netblock is malicious according to malwaredomainlist.com.|[http://www.malwaredomainlist.com/](http://www.malwaredomainlist.com/)
malwaredomains.com|Check if a host/domain is malicious according to malwaredomains.com.|[http://www.malwaredomains.com/](http://www.malwaredomains.com/)
MalwarePatrol|Searches malwarepatrol.net's database of malicious URLs/IPs.|[https://www.malwarepatrol.net/](https://www.malwarepatrol.net/)
MetaDefender|Search MetaDefender API for IP address and domain IP reputation.|[https://metadefender.opswat.com/](https://metadefender.opswat.com/)
Mnemonic PassiveDNS|Obtain Passive DNS information from PassiveDNS.mnemonic.no.|[https://www.mnemonic.no](https://www.mnemonic.no)
multiproxy.org Open Proxies|Check if an IP is an open proxy according to multiproxy.org' open proxy list.|[https://multiproxy.org/](https://multiproxy.org/)
MySpace|Gather username and location from MySpace.com profiles.|[https://myspace.com/](https://myspace.com/)
NetworksDB|Search NetworksDB.io API for IP address and domain information.|[https://networksdb.io/](https://networksdb.io/)
NeutrinoAPI|Search NeutrinoAPI for IP address info and check IP reputation.|[https://www.neutrinoapi.com/](https://www.neutrinoapi.com/)
Norton ConnectSafe|Check if a host would be blocked by Norton ConnectSafe DNS|
numverify|Lookup phone number location and carrier information from numverify.com.|[http://numverify.com/](http://numverify.com/)
Onion.link|Search Tor 'Onion City' search engine for mentions of the target domain.|[https://onion.link/](https://onion.link/)
Onionsearchengine.com|Search Tor onionsearchengine.com for mentions of the target domain.|[https://as.onionsearchengine.com](https://as.onionsearchengine.com)
Onyphe|Check Onyphe data (threat list, geo-location, pastries, vulnerabilities)  about a given IP.|[https://www.onyphe.io](https://www.onyphe.io)
Open Bug Bounty|Check external vulnerability scanning/reporting service openbugbounty.org to see if the target is listed.|[https://www.openbugbounty.org/](https://www.openbugbounty.org/)
Open Passive DNS Database|Obtain passive DNS information from pdns.daloo.de Open passive DNS database.|[http://pdns.daloo.de/](http://pdns.daloo.de/)
OpenCorporates|Look up company information from OpenCorporates.|[https://opencorporates.com](https://opencorporates.com)
OpenDNS|Check if a host would be blocked by OpenDNS DNS|[https://www.opendns.com/](https://www.opendns.com/)
OpenPhish|Check if a host/domain is malicious according to OpenPhish.com.|[https://openphish.com/](https://openphish.com/)
OpenStreetMap|Retrieves latitude/longitude coordinates for physical addresses from OpenStreetMap API.|[https://www.openstreetmap.org/](https://www.openstreetmap.org/)
Page Information|Obtain information about web pages (do they take passwords, do they contain forms, etc.)|
PasteBin|PasteBin scraping (via Google) to identify related content.|[https://pastebin.com/](https://pastebin.com/)
PGP Key Servers|Look up e-mail addresses in PGP public key servers.|
PhishStats|Determine if an IP Address is malicious|[https://phishstats.info/](https://phishstats.info/)
PhishTank|Check if a host/domain is malicious according to PhishTank.|[https://phishtank.com/](https://phishtank.com/)
Phone Number Extractor|Identify phone numbers in scraped webpages.|
Port Scanner - TCP|Scans for commonly open TCP ports on Internet-facing systems.|
Psbdmp|Check psbdmp.cc (PasteBin Dump) for potentially hacked e-mails and domains.|[https://psbdmp.cc/](https://psbdmp.cc/)
Pulsedive|Obtain information from Pulsedive's API.|[https://pulsedive.com/](https://pulsedive.com/)
Quad9|Check if a host would be blocked by Quad9|[https://quad9.net/](https://quad9.net/)
Recon.dev|Search Recon.dev for subdomains.|[https://recon.dev](https://recon.dev)
RIPE|Queries the RIPE registry (includes ARIN data) to identify netblocks and other info.|[https://www.ripe.net/](https://www.ripe.net/)
RiskIQ|Obtain information from RiskIQ's (formerly PassiveTotal) Passive DNS and Passive SSL databases.|[https://community.riskiq.com/](https://community.riskiq.com/)
Robtex|Search Robtex.com for hosts sharing the same IP.|[https://www.robtex.com/](https://www.robtex.com/)
Scylla|Gather breach data from Scylla API.|[https://scylla.sh/](https://scylla.sh/)
SecurityTrails|Obtain Passive DNS and other information from SecurityTrails|[https://securitytrails.com/](https://securitytrails.com/)
SHODAN|Obtain information from SHODAN about identified IP addresses.|[https://www.shodan.io/](https://www.shodan.io/)
Similar Domain Finder|Search various sources to identify similar looking domain names, for instance squatted domains.|
Skymem|Look up e-mail addresses on Skymem.|[http://www.skymem.info/](http://www.skymem.info/)
SlideShare|Gather name and location from SlideShare profiles.|[https://www.slideshare.net](https://www.slideshare.net)
Snov|Gather available email IDs from identified domains|[https://snov.io/](https://snov.io/)
Social Media Profile Finder|Tries to discover the social media profiles for human names identified.|[https://developers.google.com/custom-search](https://developers.google.com/custom-search)
Social Network Identifier|Identify presence on social media networks such as LinkedIn, Twitter and others.|
SORBS|Query the SORBS database for open relays, open proxies, vulnerable servers, etc.|[http://www.sorbs.net/](http://www.sorbs.net/)
SpamCop|Query various spamcop databases for open relays, open proxies, vulnerable servers, etc.|[https://www.spamcop.net/](https://www.spamcop.net/)
Spamhaus|Query the Spamhaus databases for open relays, open proxies, vulnerable servers, etc.|[https://www.spamhaus.org/](https://www.spamhaus.org/)
spur.us|Obtain information about any malicious activities involving IP addresses found|[https://spur.us/](https://spur.us/)
SpyOnWeb|Search SpyOnWeb for hosts sharing the same IP address, Google Analytics code, or Google Adsense code.|[http://spyonweb.com/](http://spyonweb.com/)
Spyse|SpiderFoot plug-in to search Spyse API for IP address and domain information.|[https://spyse.com](https://spyse.com)
SSL Certificate Analyzer|Gather information about SSL certificates used by the target's HTTPS sites.|
Strange Header Identifier|Obtain non-standard HTTP headers returned by web servers.|
Subdomain Takeover Checker|Check if affiliated subdomains are vulnerable to takeover.|
Talos Intelligence|Check if a netblock or IP is malicious according to talosintelligence.com.|[https://talosintelligence.com/](https://talosintelligence.com/)
ThreatCrowd|Obtain information from ThreatCrowd about identified IP addresses, domains and e-mail addresses.|[https://www.threatcrowd.org](https://www.threatcrowd.org)
ThreatMiner|Obtain information from ThreatMiner's database for passive DNS and threat intelligence.|[https://www.threatminer.org/](https://www.threatminer.org/)
TLD Searcher|Search all Internet TLDs for domains with the same name as the target (this can be very slow.)|
Tool - CMSeeK|Identify what Content Management System (CMS) might be used.|[https://github.com/Tuhinshubhra/CMSeeK](https://github.com/Tuhinshubhra/CMSeeK)
Tool - DNSTwist|Identify bit-squatting, typo and other similar domains to the target using a local DNSTwist installation.|[https://github.com/elceef/dnstwist](https://github.com/elceef/dnstwist)
Tool - Nmap|Identify what Operating System might be used.|[https://nmap.org/](https://nmap.org/)
Tool - WhatWeb|Identify what software is in use on the specified website.|[https://github.com/urbanadventurer/whatweb](https://github.com/urbanadventurer/whatweb)
TOR Exit Nodes|Check if an IP or netblock appears on the torproject.org exit node list.|
TORCH|Search Tor 'TORCH' search engine for mentions of the target domain.|
TotalHash.com|Check if a host/domain or IP is malicious according to TotalHash.com.|[https://totalhash.cymru.com/](https://totalhash.cymru.com/)
Twilio|Obtain information from Twilio about phone numbers. Ensure you have the Caller Name add-on installed in Twilio.|[https://www.twilio.com/](https://www.twilio.com/)
Twitter|Gather name and location from Twitter profiles.|[https://twitter.com/](https://twitter.com/)
UCEPROTECT|Query the UCEPROTECT databases for open relays, open proxies, vulnerable servers, etc.|[http://www.uceprotect.net/](http://www.uceprotect.net/)
URLScan.io|Search URLScan.io cache for domain information.|[https://urlscan.io/](https://urlscan.io/)
Venmo|Gather user information from Venmo API.|[https://venmo.com/](https://venmo.com/)
ViewDNS.info|Reverse Whois lookups using ViewDNS.info.|[https://viewdns.info/](https://viewdns.info/)
VirusTotal|Obtain information from VirusTotal about identified IP addresses.|[https://www.virustotal.com/](https://www.virustotal.com/)
VoIPBL OpenPBX IPs|Check if an IP or netblock is an open PBX according to VoIPBL OpenPBX IPs.|[http://www.voipbl.org/](http://www.voipbl.org/)
VXVault.net|Check if a domain or IP is malicious according to VXVault.net.|[http://vxvault.net/](http://vxvault.net/)
Watchguard|Check if an IP is malicious according to Watchguard's reputationauthority.org.|[http://reputationauthority.org/](http://reputationauthority.org/)
Web Analytics Extractor|Identify web analytics IDs in scraped webpages and DNS TXT records.|
Web Framework Identifier|Identify the usage of popular web frameworks like jQuery, YUI and others.|
Web Server Identifier|Obtain web server banners to identify versions of web servers being used.|
Web Spider|Spidering of web-pages to extract content for searching.|
WhatCMS|Check web technology using WhatCMS.org API.|[https://whatcms.org/](https://whatcms.org/)
Whoisology|Reverse Whois lookups using Whoisology.com.|[https://whoisology.com/](https://whoisology.com/)
Whois|Perform a WHOIS look-up on domain names and owned netblocks.|
Whoxy|Reverse Whois lookups using Whoxy.com.|[https://www.whoxy.com/](https://www.whoxy.com/)
WiGLE|Query WiGLE to identify nearby WiFi access points.|[https://wigle.net/](https://wigle.net/)
Wikileaks|Search Wikileaks for mentions of domain names and e-mail addresses.|[https://wikileaks.org/](https://wikileaks.org/)
Wikipedia Edits|Identify edits to Wikipedia articles made from a given IP address or username.|[https://www.wikipedia.org/](https://www.wikipedia.org/)
XForce Exchange|Obtain information from IBM X-Force Exchange|[https://exchange.xforce.ibmcloud.com/](https://exchange.xforce.ibmcloud.com/)
Yandex DNS|Check if a host would be blocked by Yandex DNS|[https://yandex.com/](https://yandex.com/)
Zone-H Defacement Check|Check if a hostname/domain appears on the zone-h.org 'special defacements' RSS feed.|[https://zone-h.org/](https://zone-h.org/)

### DOCUMENTATION

Read more at the [project website](https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQv&s=os_gh), including more complete documentation, blog posts with tutorials/guides, plus information about [SpiderFoot HX](https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQvaHgvCg==&s=os_gh).

Latest updates announced on [Twitter](https://twitter.com/spiderfoot).
