<a href="https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQv&s=os_gh"><img src="https://www.spiderfoot.net/wp-content/themes/spiderfoot/img/spiderfoot-wide.png"></a>


[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/smicallef/spiderfoot/master/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.7+-green)](https://www.python.org)
[![Stable Release](https://img.shields.io/badge/version-4.0-blue.svg)](https://github.com/smicallef/spiderfoot/releases/tag/v4.0)
[![CI status](https://github.com/smicallef/spiderfoot/workflows/Tests/badge.svg)](https://github.com/smicallef/spiderfoot/actions?query=workflow%3A"Tests")
[![Last Commit](https://img.shields.io/github/last-commit/smicallef/spiderfoot)](https://github.com/smicallef/spiderfoot/commits/master)
[![Codecov](https://codecov.io/github/smicallef/spiderfoot/coverage.svg)](https://codecov.io/github/smicallef/spiderfoot)
[![Twitter Follow](https://img.shields.io/twitter/follow/spiderfoot?label=follow&style=social)](https://twitter.com/spiderfoot)
[![Discord](https://img.shields.io/discord/770524432464216074)](https://discord.gg/vyvztrG)

**SpiderFoot** is an open source intelligence (OSINT) automation tool. It integrates with just about every data source available and utilises a range of methods for data analysis, making that data easy to navigate. 

SpiderFoot has an embedded web-server for providing a clean and intuitive web-based interface but can also be used completely via the command-line.  It's written in **Python 3** and **MIT-licensed**.

<img src="https://www.spiderfoot.net/wp-content/uploads/2022/04/opensource-screenshot-v4.png" />

### FEATURES

- Web based UI or CLI
- Over 200 modules (see below)
- Python 3.7+
- YAML-configurable [correlation engine](/correlations/README.md) with [37 pre-defined rules](/correlations)
- CSV/JSON/GEXF export
- API key export/import
- SQLite back-end for custom querying
- Highly configurable
- Fully documented
- Visualisations
- TOR integration for dark web searching
- Dockerfile for Docker-based deployments
- Can call other tools like DNSTwist, Whatweb, Nmap and CMSeeK
- [Actively developed since 2012!](https://medium.com/@micallst/lessons-learned-from-my-10-year-open-source-project-4a4c8c2b4f64)

### WANT MORE?

Need more from SpiderFoot? Check out [SpiderFoot HX](https://www.spiderfoot.net/hx) for:
- 100% Cloud-based and managed for you
- Attack Surface Monitoring with change notifications by email, REST and Slack
- Multiple targets per scan
- Multi-user collaboration
- Authenticated and 2FA
- Investigations
- Customer support
- Third party tools pre-installed & configured
- Drive it with a fully RESTful API
- TOR integration built-in
- Screenshotting
- Bring your own Python SpiderFoot modules
- Feed scan data to Splunk, ElasticSearch and REST endpoints

See the full set of differences between SpiderFoot HX and the open source version [here](https://www.spiderfoot.net/open-source-vs-hx/).

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
 - Bitcoin address
 
SpiderFoot's 200+ modules feed each other in a publisher/subscriber model to ensure maximum data extraction to do things like:

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

To install and run SpiderFoot, you need at least Python 3.7 and a number of Python libraries which you can install with `pip`. We recommend you install a packaged release since master will often have bleeding edge features and modules that aren't fully tested.

#### Stable build (packaged release):

```
 wget https://github.com/smicallef/spiderfoot/archive/v4.0.tar.gz
 tar zxvf v4.0.tar.gz
 cd spiderfoot-4.0
 pip3 install -r requirements.txt
 python3 ./sf.py -l 127.0.0.1:5001
```

#### Development build (cloning git master branch):

```
 git clone https://github.com/smicallef/spiderfoot.git
 cd spiderfoot
 pip3 install -r requirements.txt
 python3 ./sf.py -l 127.0.0.1:5001
```

Check out the [documentation](https://www.spiderfoot.net/documentation) and our [asciinema videos](https://asciinema.org/~spiderfoot) for more tutorials.

### COMMUNITY

Whether you're a contributor, user or just curious about SpiderFoot and OSINT in general, we'd love to have you join our community! SpiderFoot now has a [Discord server](https://discord.gg/vyvztrG) for seeking help from the community, requesting features or just general OSINT chit-chat.

### WRITING CORRELATION RULES

We have a comprehensive write-up and reference of the correlation rule-set introduced in SpiderFoot 4.0 [here](/correlations/README.md).

Also take a look at the [template.yaml](/correlations/template.yaml) file for a walk through. The existing [37 rules](/correlations) are also quite readable and good as starting points for additional rules.

### MODULES / INTEGRATIONS

SpiderFoot has over 200 modules, most of which *don't require API keys*, and many of those that do require API keys *have a free tier*.

| Name     | Description | Type   |
|:---------| :-----------|:-------|
[AbstractAPI](https://app.abstractapi.com/)|Look up domain, phone and IP address information from AbstractAPI.|Tiered API
[abuse.ch](https://www.abuse.ch)|Check if a host/domain, IP address or netblock is malicious according to Abuse.ch.|Free API
[AbuseIPDB](https://www.abuseipdb.com)|Check if an IP address is malicious according to AbuseIPDB.com blacklist.|Tiered API
[Abusix Mail Intelligence](https://abusix.org/)|Check if a netblock or IP address is in the Abusix Mail Intelligence blacklist.|Tiered API
Account Finder|Look for possible associated accounts on over 500 social and other websites such as Instagram, Reddit, etc.|Internal
[AdBlock Check](https://adblockplus.org/)|Check if linked pages would be blocked by AdBlock Plus.|Tiered API
[AdGuard DNS](https://adguard.com/)|Check if a host would be blocked by AdGuard DNS.|Free API
[Ahmia](https://ahmia.fi/)|Search Tor 'Ahmia' search engine for mentions of the target.|Free API
[AlienVault IP Reputation](https://cybersecurity.att.com/)|Check if an IP or netblock is malicious according to the AlienVault IP Reputation database.|Free API
[AlienVault OTX](https://otx.alienvault.com/)|Obtain information from AlienVault Open Threat Exchange (OTX)|Tiered API
[Amazon S3 Bucket Finder](https://aws.amazon.com/s3/)|Search for potential Amazon S3 buckets associated with the target and attempt to list their contents.|Free API
[Apple iTunes](https://itunes.apple.com/)|Search Apple iTunes for mobile apps.|Free API
[Archive.org](https://archive.org/)|Identifies historic versions of interesting files/pages from the Wayback Machine.|Free API
[ARIN](https://www.arin.net/)|Queries ARIN registry for contact information.|Free API
[Azure Blob Finder](https://azure.microsoft.com/en-in/services/storage/blobs/)|Search for potential Azure blobs associated with the target and attempt to list their contents.|Free API
Base64 Decoder|Identify Base64-encoded strings in URLs, often revealing interesting hidden information.|Internal
[BGPView](https://bgpview.io/)|Obtain network information from BGPView API.|Free API
Binary String Extractor|Attempt to identify strings in binary content.|Internal
[BinaryEdge](https://www.binaryedge.io/)|Obtain information from BinaryEdge.io Internet scanning systems, including breaches, vulnerabilities, torrents and passive DNS.|Tiered API
[Bing (Shared IPs)](https://www.bing.com/)|Search Bing for hosts sharing the same IP.|Tiered API
[Bing](https://www.bing.com/)|Obtain information from bing to identify sub-domains and links.|Tiered API
Bitcoin Finder|Identify bitcoin addresses in scraped webpages.|Internal
[Bitcoin Who's Who](https://bitcoinwhoswho.com/)|Check for Bitcoin addresses against the Bitcoin Who's Who database of suspect/malicious addresses.|Tiered API
[BitcoinAbuse](https://www.bitcoinabuse.com/)|Check Bitcoin addresses against the bitcoinabuse.com database of suspect/malicious addresses.|Free API
[Blockchain](https://www.blockchain.com/)|Queries blockchain.info to find the balance of identified bitcoin wallet addresses.|Free API
[blocklist.de](http://www.blocklist.de/en/index.html)|Check if a netblock or IP is malicious according to blocklist.de.|Free API
[BotScout](https://botscout.com/)|Searches BotScout.com's database of spam-bot IP addresses and e-mail addresses.|Tiered API
[botvrij.eu](https://botvrij.eu/)|Check if a domain is malicious according to botvrij.eu.|Free API
[BuiltWith](https://builtwith.com/)|Query BuiltWith.com's Domain API for information about your target's web technology stack, e-mail addresses and more.|Tiered API
[C99](https://api.c99.nl/)|Queries the C99 API which offers various data (geo location, proxy detection, phone lookup, etc).|Commercial API
[CallerName](http://callername.com/)|Lookup US phone number location and reputation information.|Free API
[Censys](https://censys.io/)|Obtain host information from Censys.io.|Tiered API
[Certificate Transparency](https://crt.sh/)|Gather hostnames from historical certificates in crt.sh.|Free API
[CertSpotter](https://sslmate.com/certspotter/)|Gather information about SSL certificates from SSLMate CertSpotter API.|Tiered API
[CINS Army List](https://cinsscore.com/)|Check if a netblock or IP address is malicious according to Collective Intelligence Network Security (CINS) Army list.|Free API
[CIRCL.LU](https://www.circl.lu/)|Obtain information from CIRCL.LU's Passive DNS and Passive SSL databases.|Free API
[CleanBrowsing.org](https://cleanbrowsing.org/)|Check if a host would be blocked by CleanBrowsing.org DNS content filters.|Free API
[CleanTalk Spam List](https://cleantalk.org)|Check if a netblock or IP address is on CleanTalk.org's spam IP list.|Free API
[Clearbit](https://clearbit.com/)|Check for names, addresses, domains and more based on lookups of e-mail addresses on clearbit.com.|Tiered API
[CloudFlare DNS](https://www.cloudflare.com/)|Check if a host would be blocked by CloudFlare DNS.|Free API
[CoinBlocker Lists](https://zerodot1.gitlab.io/CoinBlockerListsWeb/)|Check if a domain appears on CoinBlocker lists.|Free API
[CommonCrawl](http://commoncrawl.org/)|Searches for URLs found through CommonCrawl.org.|Free API
[Comodo Secure DNS](https://www.comodo.com/secure-dns/)|Check if a host would be blocked by Comodo Secure DNS.|Tiered API
Company Name Extractor|Identify company names in any obtained data.|Internal
Cookie Extractor|Extract Cookies from HTTP headers.|Internal
Country Name Extractor|Identify country names in any obtained data.|Internal
Credit Card Number Extractor|Identify Credit Card Numbers in any data|Internal
[Crobat API](https://sonar.omnisint.io/)|Search Crobat API for subdomains.|Free API
Cross-Referencer|Identify whether other domains are associated ('Affiliates') of the target by looking for links back to the target site(s).|Internal
[CRXcavator](https://crxcavator.io/)|Search CRXcavator for Chrome extensions.|Free API
Custom Threat Feed|Check if a host/domain, netblock, ASN or IP is malicious according to your custom feed.|Internal
[CyberCrime-Tracker.net](https://cybercrime-tracker.net/)|Check if a host/domain or IP address is malicious according to CyberCrime-Tracker.net.|Free API
[Debounce](https://debounce.io/)|Check whether an email is disposable|Free API
[Dehashed](https://www.dehashed.com/)|Gather breach data from Dehashed API.|Commercial API
[Digital Ocean Space Finder](https://www.digitalocean.com/products/spaces/)|Search for potential Digital Ocean Spaces associated with the target and attempt to list their contents.|Free API
DNS Brute-forcer|Attempts to identify hostnames through brute-forcing common names and iterations.|Internal
DNS Common SRV|Attempts to identify hostnames through brute-forcing common DNS SRV records.|Internal
[DNS for Family](https://dnsforfamily.com/)|Check if a host would be blocked by DNS for Family.|Free API
DNS Look-aside|Attempt to reverse-resolve the IP addresses next to your target to see if they are related.|Internal
DNS Raw Records|Retrieves raw DNS records such as MX, TXT and others.|Internal
DNS Resolver|Resolves hosts and IP addresses identified, also extracted from raw content.|Internal
DNS Zone Transfer|Attempts to perform a full DNS zone transfer.|Internal
[DNSDB](https://www.farsightsecurity.com)|Query FarSight's DNSDB for historical and passive DNS data.|Tiered API
[DNSDumpster](https://dnsdumpster.com/)|Passive subdomain enumeration using HackerTarget's DNSDumpster|Free API
[DNSGrep](https://opendata.rapid7.com/)|Obtain Passive DNS information from Rapid7 Sonar Project using DNSGrep API.|Free API
[DroneBL](https://dronebl.org/)|Query the DroneBL database for open relays, open proxies, vulnerable servers, etc.|Free API
[DuckDuckGo](https://duckduckgo.com/)|Query DuckDuckGo's API for descriptive information about your target.|Free API
E-Mail Address Extractor|Identify e-mail addresses in any obtained data.|Internal
[EmailCrawlr](https://emailcrawlr.com/)|Search EmailCrawlr for email addresses and phone numbers associated with a domain.|Tiered API
[EmailFormat](https://www.email-format.com/)|Look up e-mail addresses on email-format.com.|Free API
[EmailRep](https://emailrep.io/)|Search EmailRep.io for email address reputation.|Tiered API
[Emerging Threats](https://rules.emergingthreats.net/)|Check if a netblock or IP address is malicious according to EmergingThreats.net.|Free API
Error String Extractor|Identify common error messages in content like SQL errors, etc.|Internal
Ethereum Address Extractor|Identify ethereum addresses in scraped webpages.|Internal
[Etherscan](https://etherscan.io)|Queries etherscan.io to find the balance of identified ethereum wallet addresses.|Free API
File Metadata Extractor|Extracts meta data from documents and images.|Internal
[Flickr](https://www.flickr.com/)|Search Flickr for domains, URLs and emails related to the specified domain.|Free API
[Focsec](https://focsec.com/)|Look up IP address information from Focsec.|Tiered API
[FortiGuard Antispam](https://www.fortiguard.com/)|Check if an IP address is malicious according to FortiGuard Antispam.|Free API
[Fraudguard](https://fraudguard.io/)|Obtain threat information from Fraudguard.io|Tiered API
[F-Secure Riddler.io](https://riddler.io/)|Obtain network information from F-Secure Riddler.io API.|Commercial API
[FullContact](https://www.fullcontact.com)|Gather domain and e-mail information from FullContact.com API.|Tiered API
[FullHunt](https://fullhunt.io/)|Identify domain attack surface using FullHunt API.|Tiered API
[Github](https://github.com/)|Identify associated public code repositories on Github.|Free API
[GLEIF](https://search.gleif.org/)|Look up company information from Global Legal Entity Identifier Foundation (GLEIF).|Tiered API
[Google Maps](https://cloud.google.com/maps-platform/)|Identifies potential physical addresses and latitude/longitude coordinates.|Tiered API
[Google Object Storage Finder](https://cloud.google.com/storage)|Search for potential Google Object Storage buckets associated with the target and attempt to list their contents.|Free API
[Google SafeBrowsing](https://developers.google.com/safe-browsing/v4/lookup-api)|Check if the URL is included on any of the Safe Browsing lists.|Free API
[Google](https://developers.google.com/custom-search)|Obtain information from the Google Custom Search API to identify sub-domains and links.|Tiered API
[Gravatar](https://secure.gravatar.com/)|Retrieve user information from Gravatar API.|Free API
[Grayhat Warfare](https://buckets.grayhatwarfare.com/)|Find bucket names matching the keyword extracted from a domain from Grayhat API.|Tiered API
[Greensnow](https://greensnow.co/)|Check if a netblock or IP address is malicious according to greensnow.co.|Free API
[grep.app](https://grep.app/)|Search grep.app API for links and emails related to the specified domain.|Free API
[GreyNoise Community](https://greynoise.io/)|Obtain IP enrichment data from GreyNoise Community API|Tiered API
[GreyNoise](https://greynoise.io/)|Obtain IP enrichment data from GreyNoise|Tiered API
[HackerOne (Unofficial)](http://www.nobbd.de/)|Check external vulnerability scanning/reporting service h1.nobbd.de to see if the target is listed.|Free API
[HackerTarget](https://hackertarget.com/)|Search HackerTarget.com for hosts sharing the same IP.|Free API
Hash Extractor|Identify MD5 and SHA hashes in web content, files and more.|Internal
[HaveIBeenPwned](https://haveibeenpwned.com/)|Check HaveIBeenPwned.com for hacked e-mail addresses identified in breaches.|Commercial API
Hosting Provider Identifier|Find out if any IP addresses identified fall within known 3rd party hosting ranges, e.g. Amazon, Azure, etc.|Internal
[Host.io](https://host.io)|Obtain information about domain names from host.io.|Tiered API
Human Name Extractor|Attempt to identify human names in fetched content.|Internal
[Hunter.io](https://hunter.io/)|Check for e-mail addresses and names on hunter.io.|Tiered API
[Hybrid Analysis](https://www.hybrid-analysis.com)|Search Hybrid Analysis for domains and URLs related to the target.|Free API
IBAN Number Extractor|Identify International Bank Account Numbers (IBANs) in any data.|Internal
[Iknowwhatyoudownload.com](https://iknowwhatyoudownload.com/en/peer/)|Check iknowwhatyoudownload.com for IP addresses that have been using torrents.|Tiered API
[IntelligenceX](https://intelx.io/)|Obtain information from IntelligenceX about identified IP addresses, domains, e-mail addresses and phone numbers.|Tiered API
Interesting File Finder|Identifies potential files of interest, e.g. office documents, zip files.|Internal
[Internet Storm Center](https://isc.sans.edu)|Check if an IP address is malicious according to SANS ISC.|Free API
[ipapi.co](https://ipapi.co/)|Queries ipapi.co to identify geolocation of IP Addresses using ipapi.co API|Tiered API
[ipapi.com](https://ipapi.com/)|Queries ipapi.com to identify geolocation of IP Addresses using ipapi.com API|Tiered API
[IPInfo.io](https://ipinfo.io)|Identifies the physical location of IP addresses identified using ipinfo.io.|Tiered API
[IPQualityScore](https://www.ipqualityscore.com/)|Determine if target is malicious using IPQualityScore API|Tiered API
[ipregistry](https://ipregistry.co/)|Query the ipregistry.co database for reputation and geo-location.|Tiered API
[ipstack](https://ipstack.com/)|Identifies the physical location of IP addresses identified using ipstack.com.|Tiered API
[JsonWHOIS.com](https://jsonwhois.com)|Search JsonWHOIS.com for WHOIS records associated with a domain.|Tiered API
Junk File Finder|Looks for old/temporary and other similar files.|Internal
[Keybase](https://keybase.io/)|Obtain additional information about domain names and identified usernames.|Free API
[Koodous](https://koodous.com/apks/)|Search Koodous for mobile apps.|Tiered API
[LeakIX](https://leakix.net/)|Search LeakIX for host data leaks, open ports, software and geoip.|Free API
[Leak-Lookup](https://leak-lookup.com/)|Searches Leak-Lookup.com's database of breaches.|Free API
[Maltiverse](https://maltiverse.com)|Obtain information about any malicious activities involving IP addresses|Free API
[MalwarePatrol](https://www.malwarepatrol.net/)|Searches malwarepatrol.net's database of malicious URLs/IPs.|Tiered API
[MetaDefender](https://metadefender.opswat.com/)|Search MetaDefender API for IP address and domain IP reputation.|Tiered API
[Mnemonic PassiveDNS](https://www.mnemonic.no)|Obtain Passive DNS information from PassiveDNS.mnemonic.no.|Free API
[multiproxy.org Open Proxies](https://multiproxy.org/)|Check if an IP address is an open proxy according to multiproxy.org open proxy list.|Free API
[MySpace](https://myspace.com/)|Gather username and location from MySpace.com profiles.|Free API
[NameAPI](https://www.nameapi.org/)|Check whether an email is disposable|Tiered API
[NetworksDB](https://networksdb.io/)|Search NetworksDB.io API for IP address and domain information.|Tiered API
[NeutrinoAPI](https://www.neutrinoapi.com/)|Search NeutrinoAPI for phone location information, IP address information, and host reputation.|Tiered API
[numverify](http://numverify.com/)|Lookup phone number location and carrier information from numverify.com.|Tiered API
[Onion.link](https://onion.link/)|Search Tor 'Onion City' search engine for mentions of the target domain using Google Custom Search.|Free API
[Onionsearchengine.com](https://as.onionsearchengine.com)|Search Tor onionsearchengine.com for mentions of the target domain.|Free API
[Onyphe](https://www.onyphe.io)|Check Onyphe data (threat list, geo-location, pastries, vulnerabilities)  about a given IP.|Tiered API
[Open Bug Bounty](https://www.openbugbounty.org/)|Check external vulnerability scanning/reporting service openbugbounty.org to see if the target is listed.|Free API
[OpenCorporates](https://opencorporates.com)|Look up company information from OpenCorporates.|Tiered API
[OpenDNS](https://www.opendns.com/)|Check if a host would be blocked by OpenDNS.|Free API
[OpenNIC DNS](https://www.opennic.org/)|Resolves host names in the OpenNIC alternative DNS system.|Free API
[OpenPhish](https://openphish.com/)|Check if a host/domain is malicious according to OpenPhish.com.|Free API
[OpenStreetMap](https://www.openstreetmap.org/)|Retrieves latitude/longitude coordinates for physical addresses from OpenStreetMap API.|Free API
Page Information|Obtain information about web pages (do they take passwords, do they contain forms, etc.)|Internal
[PasteBin](https://pastebin.com/)|PasteBin search (via Google Search API) to identify related content.|Tiered API
PGP Key Servers|Look up domains and e-mail addresses in PGP public key servers.|Internal
[PhishStats](https://phishstats.info/)|Check if a netblock or IP address is malicious according to PhishStats.|Free API
[PhishTank](https://phishtank.com/)|Check if a host/domain is malicious according to PhishTank.|Free API
Phone Number Extractor|Identify phone numbers in scraped webpages.|Internal
Port Scanner - TCP|Scans for commonly open TCP ports on Internet-facing systems.|Internal
[Project Honey Pot](https://www.projecthoneypot.org/)|Query the Project Honey Pot database for IP addresses.|Free API
[ProjectDiscovery Chaos](https://chaos.projectdiscovery.io)|Search for hosts/subdomains using chaos.projectdiscovery.io|Commercial API
[Psbdmp](https://psbdmp.cc/)|Check psbdmp.cc (PasteBin Dump) for potentially hacked e-mails and domains.|Free API
[Pulsedive](https://pulsedive.com/)|Obtain information from Pulsedive's API.|Tiered API
[PunkSpider](https://punkspider.io/)|Check the QOMPLX punkspider.io service to see if the target is listed as vulnerable.|Free API
[Quad9](https://quad9.net/)|Check if a host would be blocked by Quad9 DNS.|Free API
[ReverseWhois](https://www.reversewhois.io/)|Reverse Whois lookups using reversewhois.io.|Free API
[RIPE](https://www.ripe.net/)|Queries the RIPE registry (includes ARIN data) to identify netblocks and other info.|Free API
[RiskIQ](https://community.riskiq.com/)|Obtain information from RiskIQ's (formerly PassiveTotal) Passive DNS and Passive SSL databases.|Tiered API
[Robtex](https://www.robtex.com/)|Search Robtex.com for hosts sharing the same IP.|Free API
[searchcode](https://searchcode.com/)|Search searchcode for code repositories mentioning the target domain.|Free API
[SecurityTrails](https://securitytrails.com/)|Obtain Passive DNS and other information from SecurityTrails|Tiered API
[Seon](https://seon.io/)|Queries seon.io to gather intelligence about IP Addresses, email addresses, and phone numbers|Commercial API
[SHODAN](https://www.shodan.io/)|Obtain information from SHODAN about identified IP addresses.|Tiered API
Similar Domain Finder|Search various sources to identify similar looking domain names, for instance squatted domains.|Internal
[Skymem](http://www.skymem.info/)|Look up e-mail addresses on Skymem.|Free API
[SlideShare](https://www.slideshare.net)|Gather name and location from SlideShare profiles.|Free API
[Snov](https://snov.io/)|Gather available email IDs from identified domains|Tiered API
[Social Links](https://sociallinks.io/)|Queries SocialLinks.io to gather intelligence from social media platforms and dark web.|Commercial API
[Social Media Profile Finder](https://developers.google.com/custom-search)|Tries to discover the social media profiles for human names identified.|Tiered API
Social Network Identifier|Identify presence on social media networks such as LinkedIn, Twitter and others.|Internal
[SORBS](http://www.sorbs.net/)|Query the SORBS database for open relays, open proxies, vulnerable servers, etc.|Free API
[SpamCop](https://www.spamcop.net/)|Check if a netblock or IP address is in the SpamCop database.|Free API
[Spamhaus Zen](https://www.spamhaus.org/)|Check if a netblock or IP address is in the Spamhaus Zen database.|Free API
[spur.us](https://spur.us/)|Obtain information about any malicious activities involving IP addresses found|Commercial API
[SpyOnWeb](http://spyonweb.com/)|Search SpyOnWeb for hosts sharing the same IP address, Google Analytics code, or Google Adsense code.|Tiered API
SSL Certificate Analyzer|Gather information about SSL certificates used by the target's HTTPS sites.|Internal
[StackOverflow](https://www.stackexchange.com)|Search StackOverflow for any mentions of a target domain. Returns potentially related information.|Tiered API
[Steven Black Hosts](https://github.com/StevenBlack/hosts)|Check if a domain is malicious (malware or adware) according to Steven Black Hosts list.|Free API
Strange Header Identifier|Obtain non-standard HTTP headers returned by web servers.|Internal
Subdomain Takeover Checker|Check if affiliated subdomains are vulnerable to takeover.|Internal
[Sublist3r PassiveDNS](https://api.sublist3r.com)|Passive subdomain enumeration using Sublist3r's API|Free API
[SURBL](http://www.surbl.org/)|Check if a netblock, IP address or domain is in the SURBL blacklist.|Free API
[Talos Intelligence](https://talosintelligence.com/)|Check if a netblock or IP address is malicious according to TalosIntelligence.|Free API
[TextMagic](https://www.textmagic.com/)|Obtain phone number type from TextMagic API|Tiered API
[Threat Jammer](https://threatjammer.com)|Check if an IP address is malicious according to ThreatJammer.com|Tiered API
[ThreatCrowd](https://www.threatcrowd.org)|Obtain information from ThreatCrowd about identified IP addresses, domains and e-mail addresses.|Free API
[ThreatFox](https://threatfox.abuse.ch)|Check if an IP address is malicious according to ThreatFox.|Free API
[ThreatMiner](https://www.threatminer.org/)|Obtain information from ThreatMiner's database for passive DNS and threat intelligence.|Free API
TLD Searcher|Search all Internet TLDs for domains with the same name as the target (this can be very slow.)|Internal
[Tool - CMSeeK]([https://github.com/Tuhinshubhra/CMSeeK](https://github.com/Tuhinshubhra/CMSeeK))|Identify what Content Management System (CMS) might be used.|Tool
[Tool - DNSTwist]([https://github.com/elceef/dnstwist](https://github.com/elceef/dnstwist))|Identify bit-squatting, typo and other similar domains to the target using a local DNSTwist installation.|Tool
[Tool - nbtscan]([http://www.unixwiz.net/tools/nbtscan.html](http://www.unixwiz.net/tools/nbtscan.html))|Scans for open NETBIOS nameservers on your target's network.|Tool
[Tool - Nmap]([https://nmap.org/](https://nmap.org/))|Identify what Operating System might be used.|Tool
[Tool - Nuclei]([https://nuclei.projectdiscovery.io/](https://nuclei.projectdiscovery.io/))|Fast and customisable vulnerability scanner.|Tool
[Tool - onesixtyone]([https://github.com/trailofbits/onesixtyone](https://github.com/trailofbits/onesixtyone))|Fast scanner to find publicly exposed SNMP services.|Tool
[Tool - Retire.js]([http://retirejs.github.io/retire.js/](http://retirejs.github.io/retire.js/))|Scanner detecting the use of JavaScript libraries with known vulnerabilities|Tool
[Tool - snallygaster]([https://github.com/hannob/snallygaster](https://github.com/hannob/snallygaster))|Finds file leaks and other security problems on HTTP servers.|Tool
[Tool - testssl.sh]([https://testssl.sh](https://testssl.sh))|Identify various TLS/SSL weaknesses, including Heartbleed, CRIME and ROBOT.|Tool
[Tool - TruffleHog]([https://github.com/trufflesecurity/truffleHog](https://github.com/trufflesecurity/truffleHog))|Searches through git repositories for high entropy strings and secrets, digging deep into commit history.|Tool
[Tool - WAFW00F]([https://github.com/EnableSecurity/wafw00f](https://github.com/EnableSecurity/wafw00f))|Identify what web application firewall (WAF) is in use on the specified website.|Tool
[Tool - Wappalyzer]([https://www.wappalyzer.com/](https://www.wappalyzer.com/))|Wappalyzer indentifies technologies on websites.|Tool
[Tool - WhatWeb]([https://github.com/urbanadventurer/whatweb](https://github.com/urbanadventurer/whatweb))|Identify what software is in use on the specified website.|Tool
[TOR Exit Nodes](https://metrics.torproject.org/)|Check if an IP adddress or netblock appears on the Tor Metrics exit node list.|Free API
[TORCH](https://torchsearch.wordpress.com/)|Search Tor 'TORCH' search engine for mentions of the target domain.|Free API
[Trashpanda](https://got-hacked.wtf)|Queries Trashpanda to gather intelligence about mentions of target in pastesites|Tiered API
[Trumail](https://trumail.io/)|Check whether an email is disposable|Free API
[Twilio](https://www.twilio.com/)|Obtain information from Twilio about phone numbers. Ensure you have the Caller Name add-on installed in Twilio.|Tiered API
[Twitter](https://twitter.com/)|Gather name and location from Twitter profiles.|Free API
[UCEPROTECT](http://www.uceprotect.net/)|Check if a netblock or IP address is in the UCEPROTECT database.|Free API
[URLScan.io](https://urlscan.io/)|Search URLScan.io cache for domain information.|Free API
[Venmo](https://venmo.com/)|Gather user information from Venmo API.|Free API
[ViewDNS.info](https://viewdns.info/)|Identify co-hosted websites and perform reverse Whois lookups using ViewDNS.info.|Tiered API
[VirusTotal](https://www.virustotal.com/)|Obtain information from VirusTotal about identified IP addresses.|Tiered API
[VoIP Blacklist (VoIPBL)](https://voipbl.org/)|Check if an IP address or netblock is malicious according to VoIP Blacklist (VoIPBL).|Free API
[VXVault.net](http://vxvault.net/)|Check if a domain or IP address is malicious according to VXVault.net.|Free API
Web Analytics Extractor|Identify web analytics IDs in scraped webpages and DNS TXT records.|Internal
Web Framework Identifier|Identify the usage of popular web frameworks like jQuery, YUI and others.|Internal
Web Server Identifier|Obtain web server banners to identify versions of web servers being used.|Internal
Web Spider|Spidering of web-pages to extract content for searching.|Internal
[WhatCMS](https://whatcms.org/)|Check web technology using WhatCMS.org API.|Tiered API
[Whoisology](https://whoisology.com/)|Reverse Whois lookups using Whoisology.com.|Commercial API
Whois|Perform a WHOIS look-up on domain names and owned netblocks.|Internal
[Whoxy](https://www.whoxy.com/)|Reverse Whois lookups using Whoxy.com.|Commercial API
[WiGLE](https://wigle.net/)|Query WiGLE to identify nearby WiFi access points.|Free API
[Wikileaks](https://wikileaks.org/)|Search Wikileaks for mentions of domain names and e-mail addresses.|Free API
[Wikipedia Edits](https://www.wikipedia.org/)|Identify edits to Wikipedia articles made from a given IP address or username.|Free API
[XForce Exchange](https://exchange.xforce.ibmcloud.com/)|Obtain IP reputation and passive DNS information from IBM X-Force Exchange.|Tiered API
[Yandex DNS](https://yandex.com/)|Check if a host would be blocked by Yandex DNS.|Free API
[Zetalytics](https://zetalytics.com/)|Query the Zetalytics database for hosts on your target domain(s).|Tiered API
[ZoneFile.io](https://zonefiles.io)|Search ZoneFiles.io Domain query API for domain information.|Tiered API
[Zone-H Defacement Check](https://zone-h.org/)|Check if a hostname/domain appears on the zone-h.org 'special defacements' RSS feed.|Free API

### DOCUMENTATION

Read more at the [project website](https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQv&s=os_gh), including more complete documentation, blog posts with tutorials/guides, plus information about [SpiderFoot HX](https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQvaHgvCg==&s=os_gh).

Latest updates announced on [Twitter](https://twitter.com/spiderfoot).


## 🌐 Web Resources & Interactive Index
- [CLICKER HERO](https://chuyentestss.pages.dev/clicker-hero.html)
- [CATEGORY BALL173](https://ieduquests.web.app/category-ball173.html)
- [LINGO DREAMS](https://eduquestspt.pages.dev/lingo-dreams.html)
- [CUPHEAD](https://eduquestsfr.pages.dev/cuphead.html)
- [SITEMAP](https://eduquestses.pages.dev/sitemap.html)
- [MERGE MUSCLE](https://ieduquests.web.app/merge-muscle.html)
- [CATEGORY BUBBLE SHOOTER](https://eduquests.onrender.com/category-bubble-shooter.html)
- [CATEGORY CASUAL 13](https://brainquests.pages.dev/category-casual-13.html)
- [CATEGORY 3KH0](https://quizzesarena.onrender.com/category-3kh0.html)
- [BUNNY BOY ONLINE](https://eduquests.onrender.com/bunny-boy-online.html)
- [QUACKVENTURE](https://ieduquests.web.app/quackventure.html)
- [WILD WEST MATCH 2 THE GOLD RUSH](https://ieduquests.web.app/wild-west-match-2-the-gold-rush.html)
- [CATEGORY PLATFORM260](https://brainquestses.pages.dev/category-platform260.html)
- [STEAL ITEMS IO](https://brainquestsfr.pages.dev/steal-items-io.html)
- [HAPPY FARM THE CROP](https://eduquestsfr.pages.dev/happy-farm-the-crop.html)
- [CATEGORY ANIMAL](https://brainquestses.pages.dev/category-animal.html)
- [ITALIAN BRAINROT BABY CLICKER](https://eduquestsjp.pages.dev/italian-brainrot-baby-clicker.html)
- [KEY QUEST](https://quizzesarena.onrender.com/key-quest.html)
- [FASHION HEROES ACADEMY](https://eduquestsfr.pages.dev/fashion-heroes-academy.html)
- [LINK COLOR PICTURES](https://quizzesarena.web.app/link-color-pictures.html)
- [BOX MONSTER UNBOX DRESS UP](https://eduquestsfr.pages.dev/box-monster-unbox-dress-up.html)
- [CATEGORY SPORTS](https://eduquests.onrender.com/category-sports.html)
- [VOLLEY BEAN](https://brainquestsfr.pages.dev/volley-bean.html)
- [CATEGORY DRESS UP](https://quizzesarena.onrender.com/category-dress-up.html)
- [SITEMAP](https://brainquestspt.pages.dev/sitemap.html)
- [CATEGORY LOGIC538](https://quizzesarena.onrender.com/category-logic538.html)
- [TROPICAL MATCH](https://brainquestsfr.pages.dev/tropical-match.html)
- [INDEX2](https://eduquests.onrender.com/index2.html)
- [UP HERO](https://quizzesarena.onrender.com/up-hero.html)
- [ARROW PUZZLE](https://brainquestspt.pages.dev/arrow-puzzle.html)
- [POLICE CHASE DRIFTER](https://quizzesarena.web.app/police-chase-drifter.html)
- [CATEGORY SHOOTER](https://ieduquests.web.app/category-shooter.html)
- [CATEGORY HALLOWEEN45](https://quizzesarena.onrender.com/category-halloween45.html)
- [CATEGORY PHYSICS371](https://brainquests.pages.dev/category-physics371.html)
- [OBBY DEAD RIVER](https://quizzesarena.onrender.com/obby-dead-river.html)
- [CATEGORY ARMY](https://brainquestses.pages.dev/category-army.html)
- [CATEGORY STORY45](https://eduquestsjp.pages.dev/category-story45.html)
- [CATEGORY HERO72](https://eduquestsjp.pages.dev/category-hero72.html)
- [THE SORTING MART](https://brainquestsfr.pages.dev/the-sorting-mart.html)
- [ENGLISH CHECKERS](https://brainquestspt.pages.dev/english-checkers.html)
- [CATEGORY INCREMENTAL388](https://brainquestses.pages.dev/category-incremental388.html)
- [CATEGORY SORTING](https://brainquestses.pages.dev/category-sorting.html)
- [INDEX37](https://eduquestsjp.pages.dev/index37.html)
- [CATEGORY SHOOTER 2](https://eduquests.onrender.com/category-shooter-2.html)
- [BOMB HEAD HOT POTATO](https://quizzesarena.web.app/bomb-head-hot-potato.html)
- [FURRY WEDDING PROPOSAL](https://quizzesarena.onrender.com/furry-wedding-proposal.html)
- [HOUSE ROBBER](https://eduquestsfr.pages.dev/house-robber.html)
- [VEHICLE FUN RACE](https://brainquestsfr.pages.dev/vehicle-fun-race.html)
- [CATEGORY CAN T STOP PLAYING212](https://quizzesarena.onrender.com/category-can-t-stop-playing212.html)
- [CATEGORY COOKING46](https://brainquests.pages.dev/category-cooking46.html)
- [CATEGORY MERGE](https://eduquestsjp.pages.dev/category-merge.html)
- [CATEGORY PUZZLE 5](https://eduquests.onrender.com/category-puzzle-5.html)
- [CATEGORY PUZZLE 5](https://eduquestsfr.pages.dev/category-puzzle-5.html)
- [CATEGORY FASHION105](https://eduquestsjp.pages.dev/category-fashion105.html)
- [SPACE PIN MASTER PULL PIN PUZZLE](https://eduquests.netlify.app/space-pin-master-pull-pin-puzzle.html)
- [GLOVES GROW RUSH](https://eduquests.onrender.com/gloves-grow-rush.html)
- [BUILD AND RUN](https://learnaction.netlify.app/build-and-run.html)
- [SHOOT RUN MONSTER HUNTING](https://brainquestspt.pages.dev/shoot-run-monster-hunting.html)
- [CARS WITH GUNS WASTELAND SHOWDOWN](https://quizzesarena.onrender.com/cars-with-guns-wasteland-showdown.html)
- [DOWNHILL CAR RIDE CRASH TEST](https://ieduquests.web.app/downhill-car-ride-crash-test.html)
- [OMG WORD SUSHI](https://eduquests.netlify.app/omg-word-sushi.html)
- [CATEGORY MAHJONG 2](https://eduquests.netlify.app/category-mahjong-2.html)
- [KOMARU CAT](https://brainquestspt.pages.dev/komaru-cat.html)
- [CATEGORY SPEED158](https://eduquestsjp.pages.dev/category-speed158.html)
- [PLANE CHASE](https://ieduquests.web.app/plane-chase.html)
- [ZINDEX](https://ieduquests.web.app/zindex.html)
- [ROBBOTTO](https://eduquests.onrender.com/robbotto.html)
- [CATEGORY CASUAL 14](https://quizzesarena.onrender.com/category-casual-14.html)
- [DADDY RABBIT](https://eduquests.netlify.app/daddy-rabbit.html)
- [CATEGORY BOARDGAMES](https://eduquestsjp.pages.dev/category-boardgames.html)
- [COZY KITCHEN MERGE](https://quizzesarena.onrender.com/cozy-kitchen-merge.html)
- [GOOD TO DRIVE](https://ieduquests.web.app/good-to-drive.html)
- [COLLECT BRAINROT ARENA](https://ieduquests.web.app/collect-brainrot-arena.html)
- [CATEGORY AGILITY 3](https://quizzesarena.onrender.com/category-agility-3.html)
- [CATEGORY ROBOT49](https://learnaction.netlify.app/category-robot49.html)
- [NOOB VS ZOMBIE APOCALYPSE SHOOTING PRO](https://ieduquests.web.app/noob-vs-zombie-apocalypse-shooting-pro.html)
- [CATEGORY MERGE](https://brainquestspt.pages.dev/category-merge.html)
- [FRUIT SURVIVOR](https://quizzesarena.onrender.com/fruit-survivor.html)
- [CATEGORY POOL 3](https://eduquestsfr.pages.dev/category-pool-3.html)
- [TWO STUNT SUPERCARS](https://quizzesarena.web.app/two-stunt-supercars.html)
- [INDEX11](https://eduquestsjp.pages.dev/index11.html)
- [CATEGORY MAHJONG37](https://eduquestsjp.pages.dev/category-mahjong37.html)
- [DUET CATS HALLOWEEN CAT MUSIC](https://ieduquests.web.app/duet-cats-halloween-cat-music.html)
- [CATEGORY NATIVEGAMES](https://eduquestsfr.pages.dev/category-nativegames.html)
- [CATEGORY FARMING87](https://eduquests.netlify.app/category-farming87.html)
- [TOCA TEENS FLOATING BEACH PARTY](https://ieduquests.web.app/toca-teens-floating-beach-party.html)
- [CATEGORY CASUAL 15](https://quizzesarena.onrender.com/category-casual-15.html)
- [GMOD BOMBS](https://quizzesarena.web.app/gmod-bombs.html)
- [CATEGORY 3KH0 GAMES](https://quizzesarena.onrender.com/category-3kh0-games.html)
- [HIDDEN OBJECTS ISLAND](https://eduquestsfr.pages.dev/hidden-objects-island.html)
- [CATEGORY TURN BASED30](https://ieduquests.web.app/category-turn-based30.html)
- [CATEGORY BUBBLE SHOOTER](https://quizzesarena.onrender.com/category-bubble-shooter.html)
- [DELIVERY CHAOS](https://brainquests.pages.dev/delivery-chaos.html)
- [BITBALL](https://ieduquests.web.app/bitball.html)
- [DOGGO DROP](https://brainquestspt.pages.dev/doggo-drop.html)
- [CATEGORY MINECRAFT](https://eduquests.netlify.app/category-minecraft.html)
- [ARCHERY RAGDOLL](https://quizzesarena.web.app/archery-ragdoll.html)
- [CATEGORY MATCH 3 2](https://eduquestsjp.pages.dev/category-match-3-2.html)
- [CATEGORY CLASSIC98](https://brainquests.pages.dev/category-classic98.html)
- [WORM HUNT](https://eduquestsfr.pages.dev/worm-hunt.html)
- [CATEGORY FIGHTING124](https://quizzesarena.onrender.com/category-fighting124.html)
- [CATEGORY CONTROLLER](https://eduquests.pages.dev/category-controller.html)
- [2020 CONNECT](https://eduquests.onrender.com/2020-connect.html)
- [CATEGORY MAHJONG 2](https://quizzesarena.onrender.com/category-mahjong-2.html)
- [CATEGORY SANDBOX41](https://learnaction.netlify.app/category-sandbox41.html)
- [BUILD AND RUN](https://brainquestsfr.pages.dev/build-and-run.html)
- [CATEGORY CAT55](https://learnaction.netlify.app/category-cat55.html)
- [CATEGORY FREE FASHION GAMES](https://eduquests.netlify.app/category-free-fashion-games.html)
- [CATEGORY RACING127](https://learnaction.netlify.app/category-racing127.html)
- [INDEX15](https://eduquestsjp.pages.dev/index15.html)
- [INDEX6](https://eduquests.onrender.com/index6.html)
- [CATEGORY IDLE445](https://eduquestsjp.pages.dev/category-idle445.html)
- [CATEGORY AVOID295](https://quizzesarena.onrender.com/category-avoid295.html)
- [PORTAL MASTER](https://brainquests.pages.dev/portal-master.html)
- [CATEGORY BIKE 3](https://eduquestses.pages.dev/category-bike-3.html)
- [POPCATS MERGE THE CATS](https://ieduquests.web.app/popcats-merge-the-cats.html)
- [CATEGORY BATTLE ROYALE GAMES](https://eduquestsjp.pages.dev/category-battle-royale-games.html)
- [BRICKS BALLS BREAKER](https://quizzesarena.web.app/bricks-balls-breaker.html)
- [CATEGORY CASUAL 11](https://brainquestses.pages.dev/category-casual-11.html)
- [CATEGORY PUZZLE](https://quizzesarena.web.app/category-puzzle.html)
- [CATEGORY IDLE448](https://quizzesarena.onrender.com/category-idle448.html)
- [PORTAL HOP](https://brainquestspt.pages.dev/portal-hop.html)
- [CATEGORY ANIMAL](https://eduquestses.pages.dev/category-animal.html)
- [CATEGORY FIGHTING](https://eduquests.netlify.app/category-fighting.html)
- [SURVIVAL ISLAND](https://ieduquests.web.app/survival-island.html)
- [CRAZYZOMBIES 3D](https://ieduquests.web.app/crazyzombies-3d.html)
- [VALLEY OF WOLVES AMBUSH](https://eduquestsfr.pages.dev/valley-of-wolves-ambush.html)
- [CHICKEN STRIKE](https://ieduquests.web.app/chicken-strike.html)
- [CATEGORY HALLOWEEN45](https://eduquests.onrender.com/category-halloween45.html)
- [SERIOUS HEAD 2](https://eduquests.pages.dev/serious-head-2.html)
