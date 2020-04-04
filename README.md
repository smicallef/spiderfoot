<h1 align="center">
  <a href="https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQv&s=os_gh"><img src="https://www.spiderfoot.net/wp-content/themes/spiderfoot/img/spiderfoot-wide.png"></a>
</h1>

### ABOUT

SpiderFoot is an open source intelligence (OSINT) automation tool. It integrates with just about every data source available and utilises a range of methods for data analysis, making that data easy to navigate. 

SpiderFoot has an embedded web-server for providing a clean and intuitive web-based interface but can also be used completely via the command-line.  It's written in **Python 3** and **GPL-licensed**.

<img src="https://www.spiderfoot.net/wp-content/themes/spiderfoot/img/spiderfoot-browse.png">

### FEATURES

- Web based UI or CLI
- Over 170 modules (see below)
- Python 3
- CSV/JSON/GEXF export
- API key export/import
- SQLite back-end for custom querying
- Highly configurable
- Fully documented
- Visualisations
- TOR integration for dark web searching
- Dockerfile for Docker-based deployments
- Can call other tools like DNSTwist, Whatweb and CMSeeK
- Actively developed since 2012!

### USES

SpiderFoot's 170+ modules feed each other in a pub/sub model to ensure maximum data extraction to do things like:

- Host/sub-domain/TLD enumeration/extraction
- E-mail address enumeration/extraction
- Phone number extraction
- Bitcoin and Ethereum address extraction
- DNS zone transfers
- Threat intelligence and Blacklist queries
- API integraiton with SHODAN, HaveIBeenPwned, Censys, AlienVault, SecurityTrails, etc.
- Social media account enumeration
- S3/Azure/Digitalocean bucket enumeration/scraping
- IP geo-location
- Web scraping, web content analysis
- Image and binary file meta data analysis
- Office document meta data analysis
- Dark web searches
- So much more...

See it in action here, performing some DNS recon:

[![asciicast](https://asciinema.org/a/295912.svg)](https://asciinema.org/a/295912)

### PURPOSE

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

### MODULES

| Module        | Name          | Description  |
| :------------- |:-------------| :------------|
sfp_abusech.py|abuse.ch|Check if a host/domain, IP or netblock is malicious according to abuse.ch.|
sfp_abuseipdb.py|AbuseIPDB|Check if a netblock or IP is malicious according to AbuseIPDB.com.|
sfp_accounts.py|Accounts|Look for possible associated accounts on nearly 200 websites like Ebay, Slashdot, reddit, etc.|
sfp_adblock.py|AdBlock Check|Check if linked pages would be blocked by AdBlock Plus.|
sfp_ahmia.py|Ahmia|Search Tor 'Ahmia' search engine for mentions of the target domain.|
sfp_alienvaultiprep.py|AlienVault IP Reputation|Check if an IP or netblock is malicious according to the AlienVault IP Reputation database.|
sfp_alienvault.py|AlienVault OTX|Obtain information from AlienVault Open Threat Exchange (OTX)|
sfp_apility.py|Apility|Search Apility API for IP address and domain reputation.|
sfp_archiveorg.py|Archive.org|Identifies historic versions of interesting files/pages from the Wayback Machine.|
sfp_arin.py|ARIN|Queries ARIN registry for contact information.|
sfp_azureblobstorage.py|Azure Blob Finder|Search for potential Azure blobs associated with the target and attempt to list their contents.|
sfp_badipscom.py|badips.com|Check if a domain or IP is malicious according to badips.com.|
sfp_bambenek.py|Bambenek C&C List|Check if a host/domain or IP appears on Bambenek Consulting's C&C tracker lists.|
sfp_base64.py|Base64|Identify Base64-encoded strings in any content and URLs, often revealing interesting hidden information.|
sfp_bgpview.py|BGPView|Obtain network information from BGPView API.|
sfp_binaryedge.py|BinaryEdge|Obtain information from BinaryEdge.io's Internet scanning systems about breaches, vulerabilities, torrents and passive DNS.|
sfp_bingsearch.py|Bing|Obtain information from bing to identify sub-domains and links.|
sfp_bingsharedip.py|Bing (Shared IPs)|Search Bing for hosts sharing the same IP.|
sfp_binstring.py|Binary String Extractor|Attempt to identify strings in binary content.|
sfp_bitcoin.py|Bitcoin Finder|Identify bitcoin addresses in scraped webpages.|
sfp_blockchain.py|Blockchain|Queries blockchain.info to find the balance of identified bitcoin wallet addresses.|
sfp_blocklistde.py|blocklist.de|Check if a netblock or IP is malicious according to blocklist.de.|
sfp_botscout.py|BotScout|Searches botscout.com's database of spam-bot IPs and e-mail addresses.|
sfp_builtwith.py|BuiltWith|Query BuiltWith.com's Domain API for information about your target's web technology stack, e-mail addresses and more.|
sfp_callername.py|CallerName|Lookup US phone number location and reputation information.|
sfp_censys.py|Censys|Obtain information from Censys.io|
sfp_cinsscore.py|CINS Army List|Check if a netblock or IP is malicious according to cinsscore.com's Army List.|
sfp_circllu.py|CIRCL.LU|Obtain information from CIRCL.LU's Passive DNS and Passive SSL databases.|
sfp_citadel.py|Citadel Engine|Searches Leak-Lookup.com's database of breaches.|
sfp_cleanbrowsing.py|Cleanbrowsing.org|Check if a host would be blocked by Cleanbrowsing.org DNS|
sfp_cleantalk.py|CleanTalk Spam List|Check if an IP is on CleanTalk.org's spam IP list.|
sfp_clearbit.py|Clearbit|Check for names, addresses, domains and more based on lookups of e-mail addresses on clearbit.com.|
sfp_coinblocker.py|CoinBlocker Lists|Check if a host/domain or IP appears on CoinBlocker lists.|
sfp_commoncrawl.py|CommonCrawl|Searches for URLs found through CommonCrawl.org.|
sfp_comodo.py|Comodo|Check if a host would be blocked by Comodo DNS|
sfp_company.py|Company Names|Identify company names in any obtained data.|
sfp_cookie.py|Cookies|Extract Cookies from HTTP headers.|
sfp_crossref.py|Cross-Reference|Identify whether other domains are associated ('Affiliates') of the target.|
sfp_crt.py|Certificate Transparency|Gather hostnames from historical certificates in crt.sh.|
sfp_customfeed.py|Custom Threat Feed|Check if a host/domain, netblock, ASN or IP is malicious according to your custom feed.|
sfp_cybercrimetracker.py|cybercrime-tracker.net|Check if a host/domain or IP is malicious according to cybercrime-tracker.net.|
sfp_darksearch.py|Darksearch|Search the Darksearch.io Tor search engine for mentions of the target domain.|
sfp_digitaloceanspace.py|Digital Ocean Space Finder|Search for potential Digital Ocean Spaces associated with the target and attempt to list their contents.|
sfp_dnsbrute.py|DNS Brute-force|Attempts to identify hostnames through brute-forcing common names and iterations.|
sfp_dnscommonsrv.py|DNS Common SRV|Attempts to identify hostnames through common SRV.|
sfp_dnsneighbor.py|DNS Look-aside|Attempt to reverse-resolve the IP addresses next to your target to see if they are related.|
sfp_dnsraw.py|DNS Raw Records|Retrieves raw DNS records such as MX, TXT and others.|
sfp_dnsresolve.py|DNS Resolver|Resolves Hosts and IP Addresses identified, also extracted from raw content.|
sfp_dnszonexfer.py|DNS Zone Transfer|Attempts to perform a full DNS zone transfer.|
sfp_dronebl.py|DroneBL|Query the DroneBL database for open relays, open proxies, vulnerable servers, etc.|
sfp_duckduckgo.py|DuckDuckGo|Query DuckDuckGo's API for descriptive information about your target.|
sfp_emailformat.py|EmailFormat|Look up e-mail addresses on email-format.com.|
sfp_email.py|E-Mail|Identify e-mail addresses in any obtained data.|
sfp_emailrep.py|EmailRep|Search EmailRep.io for email address reputation.|
sfp_errors.py|Errors|Identify common error messages in content like SQL errors, etc.|
sfp_ethereum.py|Ethereum Finder|Identify ethereum addresses in scraped webpages.|
sfp_filemeta.py|File Metadata|Extracts meta data from documents and images.|
sfp_flickr.py|Flickr|Look up e-mail addresses on Flickr.|
sfp_fortinet.py|Fortiguard.com|Check if an IP is malicious according to Fortiguard.com.|
sfp_fraudguard.py|Fraudguard|Obtain threat information from Fraudguard.io|
sfp_fringeproject.py|Fringe Project|Obtain network information from Fringe Project API.|
sfp_fsecure_riddler.py|F-Secure Riddler.io|Obtain network information from F-Secure Riddler.io API.|
sfp_fullcontact.py|FullContact|Gather domain and e-mail information from fullcontact.com.|
sfp_github.py|Github|Identify associated public code repositories on Github.|
sfp_googlemaps.py|Google Maps|Identifies potential physical addresses and latitude/longitude coordinates.|
sfp_googlesearch.py|Google|Obtain information from the Google Custom Search API to identify sub-domains and links.|
sfp_gravatar.py|Gravatar|Retrieve user information from Gravatar API.|
sfp_greynoise.py|Greynoise|Obtain information from Greynoise.io's Enterprise API.|
sfp_h1nobbdde.py|HackerOne (Unofficial)|Check external vulnerability scanning/reporting service h1.nobbd.de to see if the target is listed.|
sfp_hackertarget.py|HackerTarget.com|Search HackerTarget.com for hosts sharing the same IP.|
sfp_haveibeenpwned.py|HaveIBeenPwned|Check HaveIBeenPwned.com for hacked e-mail addresses identified in breaches.|
sfp_honeypot.py|Honeypot Checker|Query the projecthoneypot.org database for entries.|
sfp_hosting.py|Hosting Providers|Find out if any IP addresses identified fall within known 3rd party hosting ranges, e.g. Amazon, Azure, etc.|
sfp_hostsfilenet.py|hosts-file.net Malicious Hosts|Check if a host/domain is malicious according to hosts-file.net Malicious Hosts.|
sfp_hunter.py|Hunter.io|Check for e-mail addresses and names on hunter.io.|
sfp_iknowwhatyoudownload.py|Iknowwhatyoudownload.com|Check iknowwhatyoudownload.com for IP addresses that have been using BitTorrent.|
sfp_instagram.py|Instagram|Gather information from Instagram profiles.|
sfp_intelx.py|IntelligenceX|Obtain information from IntelligenceX about identified IP addresses, domains, e-mail addresses and phone numbers.|
sfp_intfiles.py|Interesting Files|Identifies potential files of interest, e.g. office documents, zip files.|
sfp_ipinfo.py|IPInfo.io|Identifies the physical location of IP addresses identified using ipinfo.io.|
sfp_ipstack.py|ipstack|Identifies the physical location of IP addresses identified using ipstack.com.|
sfp_isc.py|Internet Storm Center|Check if an IP is malicious according to SANS ISC.|
sfp_junkfiles.py|Junk Files|Looks for old/temporary and other similar files.|
sfp_malwaredomainlist.py|malwaredomainlist.com|Check if a host/domain, IP or netblock is malicious according to malwaredomainlist.com.|
sfp_malwaredomains.py|malwaredomains.com|Check if a host/domain is malicious according to malwaredomains.com.|
sfp_malwarepatrol.py|MalwarePatrol|Searches malwarepatrol.net's database of malicious URLs/IPs.|
sfp_metadefender.py|MetaDefender|Search MetaDefender API for IP address and domain IP reputation.|
sfp_mnemonic.py|Mnemonic PassiveDNS|Obtain Passive DNS information from PassiveDNS.mnemonic.no.|
sfp_multiproxy.py|multiproxy.org Open Proxies|Check if an IP is an open proxy according to multiproxy.org' open proxy list.|
sfp_myspace.py|MySpace|Gather username and location from MySpace.com profiles.|
sfp_names.py|Name Extractor|Attempt to identify human names in fetched content.|
sfp_neutrinoapi.py|NeutrinoAPI|Search NeutrinoAPI for IP address info and check IP reputation.|
sfp_norton.py|Norton ConnectSafe|Check if a host would be blocked by Norton ConnectSafe DNS|
sfp_nothink.py|Nothink.org|Check if a host/domain, netblock or IP is malicious according to Nothink.org.|
sfp_numpi.py|numpi|Lookup USA/Canada phone number location and carrier information from numpi.com.|
sfp_numverify.py|numverify|Lookup phone number location and carrier information from numverify.com.|
sfp_onioncity.py|Onion.link|Search Tor 'Onion City' search engine for mentions of the target domain.|
sfp_onionsearchengine.py|Onionsearchengine.com|Search Tor onionsearchengine.com for mentions of the target domain.|
sfp_openbugbounty.py|Open Bug Bounty|Check external vulnerability scanning/reporting service openbugbounty.org to see if the target is listed.|
sfp_opencorporates.py|OpenCorporates|Look up company information from OpenCorporates.|
sfp_opendns.py|OpenDNS|Check if a host would be blocked by OpenDNS DNS|
sfp_openphish.py|OpenPhish|Check if a host/domain is malicious according to OpenPhish.com.|
sfp_openstreetmap.py|OpenStreetMap|Retrieves latitude/longitude coordinates for physical addresses from OpenStreetMap API.|
sfp_pageinfo.py|Page Info|Obtain information about web pages (do they take passwords, do they contain forms, etc.)|
sfp_pastebin.py|PasteBin|PasteBin scraping (via Google) to identify related content.|
sfp_pgp.py|PGP Key Look-up|Look up e-mail addresses in PGP public key servers.|
sfp_phishtank.py|PhishTank|Check if a host/domain is malicious according to PhishTank.|
sfp_phone.py|Phone Numbers|Identify phone numbers in scraped webpages.|
sfp_portscan_tcp.py|Port Scanner - TCP|Scans for commonly open TCP ports on Internet-facing systems.|
sfp_psbdmp.py|Psbdmp.com|Check psbdmp.cc (PasteBin Dump) for potentially hacked e-mails and domains.|
sfp_pulsedive.py|Pulsedive|Obtain information from Pulsedive's API.|
sfp_quad9.py|Quad9|Check if a host would be blocked by Quad9|
sfp_ripe.py|RIPE|Queries the RIPE registry (includes ARIN data) to identify netblocks and other info.|
sfp_riskiq.py|RiskIQ|Obtain information from RiskIQ's (formerly PassiveTotal) Passive DNS and Passive SSL databases.|
sfp_robtex.py|Robtex|Search Robtex.com for hosts sharing the same IP.|
sfp_s3bucket.py|Amazon S3 Bucket Finder|Search for potential Amazon S3 buckets associated with the target and attempt to list their contents.|
sfp_scylla.py|Scylla|Gather breach data from Scylla API.|
sfp_securitytrails.py|SecurityTrails|Obtain Passive DNS and other information from SecurityTrails|
sfp_shodan.py|SHODAN|Obtain information from SHODAN about identified IP addresses.|
sfp_similar.py|Similar Domains|Search various sources to identify similar looking domain names, for instance squatted domains.|
sfp_skymem.py|Skymem|Look up e-mail addresses on Skymem.|
sfp_slideshare.py|SlideShare|Gather name and location from SlideShare profiles.|
sfp_socialprofiles.py|Social Media Profiles|Tries to discover the social media profiles for human names identified.|
sfp_social.py|Social Networks|Identify presence on social media networks such as LinkedIn, Twitter and others.|
sfp_sorbs.py|SORBS|Query the SORBS database for open relays, open proxies, vulnerable servers, etc.|
sfp_spamcop.py|SpamCop|Query various spamcop databases for open relays, open proxies, vulnerable servers, etc.|
sfp_spamhaus.py|Spamhaus|Query the Spamhaus databases for open relays, open proxies, vulnerable servers, etc.|
sfp_spider.py|Spider|Spidering of web-pages to extract content for searching.|
sfp_spyonweb.py|SpyOnWeb|Search SpyOnWeb for hosts sharing the same IP address, Google Analytics code, or Google Adsense code.|
sfp_sslcert.py|SSL Certificates|Gather information about SSL certificates used by the target's HTTPS sites.|
sfp_ssltools.py|SSL Tools|Gather information about SSL certificates from SSLTools.com.|
sfp__stor_db.py|Storage|Stores scan results into the back-end SpiderFoot database. You will need this.|
sfp__stor_stdout.py|Command-line output|Dumps output to standard out. Used for when a SpiderFoot scan is run via the command-line.|
sfp_strangeheaders.py|Strange Headers|Obtain non-standard HTTP headers returned by web servers.|
sfp_talosintel.py|Talos Intelligence|Check if a netblock or IP is malicious according to talosintelligence.com.|
sfp_threatcrowd.py|ThreatCrowd|Obtain information from ThreatCrowd about identified IP addresses, domains and e-mail addresses.|
sfp_threatexpert.py|ThreatExpert.com|Check if a host/domain or IP is malicious according to ThreatExpert.com.|
sfp_threatminer.py|ThreatMiner|Obtain information from ThreatMiner's database for passive DNS and threat intelligence.|
sfp_tldsearch.py|TLD Search|Search all Internet TLDs for domains with the same name as the target (this can be very slow.)|
sfp_tool_cmseek.py|Tool - CMSeeK|Identify what Content Management System (CMS) might be used.|
sfp_tool_dnstwist.py|Tool - DNSTwist|Identify bit-squatting, typo and other similar domains to the target using a local DNSTwist installation.|
sfp_tool_whatweb.py|Tool - WhatWeb|Identify what software is in use on the specified website.|
sfp_torch.py|TORCH|Search Tor 'TORCH' search engine for mentions of the target domain.|
sfp_torexits.py|TOR Exit Nodes|Check if an IP or netblock appears on the torproject.org exit node list.|
sfp_totalhash.py|TotalHash.com|Check if a host/domain or IP is malicious according to TotalHash.com.|
sfp_twitter.py|Twitter|Gather name and location from Twitter profiles.|
sfp_uceprotect.py|UCEPROTECT|Query the UCEPROTECT databases for open relays, open proxies, vulnerable servers, etc.|
sfp_urlscan.py|URLScan.io|Search URLScan.io cache for domain information.|
sfp_venmo.py|Venmo|Gather user information from Venmo API.|
sfp_viewdns.py|ViewDNS.info|Reverse Whois lookups using ViewDNS.info.|
sfp_virustotal.py|VirusTotal|Obtain information from VirusTotal about identified IP addresses.|
sfp_voipbl.py|VoIPBL OpenPBX IPs|Check if an IP or netblock is an open PBX according to VoIPBL OpenPBX IPs.|
sfp_vxvault.py|VXVault.net|Check if a domain or IP is malicious according to VXVault.net.|
sfp_watchguard.py|Watchguard|Check if an IP is malicious according to Watchguard's reputationauthority.org.|
sfp_webanalytics.py|Web Analytics|Identify web analytics IDs in scraped webpages and DNS TXT records.|
sfp_webframework.py|Web Framework|Identify the usage of popular web frameworks like jQuery, YUI and others.|
sfp_webserver.py|Web Server|Obtain web server banners to identify versions of web servers being used.|
sfp_whatcms.py|WhatCMS|Check web technology using WhatCMS.org API.|
sfp_whoisology.py|Whoisology|Reverse Whois lookups using Whoisology.com.|
sfp_whois.py|Whois|Perform a WHOIS look-up on domain names and owned netblocks.|
sfp_whoxy.py|Whoxy|Reverse Whois lookups using Whoxy.com.|
sfp_wigle.py|Wigle.net|Query wigle.net to identify nearby WiFi access points.|
sfp_wikileaks.py|Wikileaks|Search Wikileaks for mentions of domain names and e-mail addresses.|
sfp_wikipediaedits.py|Wikipedia Edits|Identify edits to Wikipedia articles made from a given IP address or username.|
sfp_xforce.py|XForce Exchange|Obtain information from IBM X-Force Exchange|
sfp_yandexdns.py|Yandex DNS|Check if a host would be blocked by Yandex DNS|
sfp_zoneh.py|Zone-H Defacement Check|Check if a hostname/domain appears on the zone-h.org 'special defacements' RSS feed.|

### DOCUMENTATION

Read more at the [project website](https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQv&s=os_gh), including more complete documentation, blog posts with tutorials/guides, plus information about [SpiderFoot HX](https://www.spiderfoot.net/r.php?u=aHR0cHM6Ly93d3cuc3BpZGVyZm9vdC5uZXQvaHgvCg==&s=os_gh).

Latest updates announced on [Twitter](https://twitter.com/spiderfoot).
