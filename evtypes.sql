--
-- Event types and their descriptions
--
-- Event type types..
-- ENTITY = Something that exists
-- DESCRIPTOR = Something that gives information about an entity, like an attribute or enrichment
-- SUBENTITY = Something that exists within another entity, too small to be treated on its own
-- DATA = Raw data

INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ROOT', 'Internal SpiderFoot Root event', 1, "INTERNAL");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ACCOUNT_EXTERNAL_OWNED', 'Account on External Site', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ACCOUNT_EXTERNAL_OWNED_COMPROMISED', 'Hacked Account on External Site', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ACCOUNT_EXTERNAL_USER_SHARED', 'User Account on External Site', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED', 'Hacked User Account on External Site', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_INTERNET_NAME', 'Affiliate - Internet Name', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_IPADDR', 'Affiliate - IP Address', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_WEB_CONTENT', 'Affiliate - Web Content', 1, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BGP_AS_OWNER', 'BGP AS Ownership', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BGP_AS_MEMBER', 'BGP AS Membership', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BGP_AS_PEER', 'BGP AS Peer', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BLACKLISTED_IPADDR', 'Blacklisted IP Address', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BLACKLISTED_AFFILIATE_IPADDR', 'Blacklisted Affiliate IP Address', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BLACKLISTED_SUBNET', 'Blacklisted IP on Same Subnet', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BLACKLISTED_NETBLOCK', 'Blacklisted IP on Owned Netblock', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('CO_HOSTED_SITE', 'Co-Hosted Site', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEFACED_INTERNET_NAME', 'Defaced', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEFACED_IPADDR', 'Defaced IP Address', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEFACED_AFFILIATE_INTERNET_NAME', 'Defaced Affiliate', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEFACED_COHOST', 'Defaced Co-Hosted Site', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEFACED_AFFILIATE_IPADDR', 'Defaced Affiliate IP Address', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEVICE_TYPE', 'Device Type', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DNS_TEXT', 'DNS TXT Record', 0, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DOMAIN_NAME', 'Domain Name', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DOMAIN_REGISTRAR', 'Domain Registrar', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DOMAIN_WHOIS', 'Domain Whois', 1, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('EMAILADDR', 'Email Address', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('EMAILADDR_COMPROMISED', 'Hacked Email Address', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ERROR_MESSAGE', 'Error Message', 0, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('GEOINFO', 'Physical Location', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('HTTP_CODE', 'HTTP Status Code', 0, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('HUMAN_NAME', 'Human Name', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('INTERESTING_FILE', 'Interesting File', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('JUNK_FILE', 'Junk File', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('INTERNET_NAME', 'Internet Name', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('IP_ADDRESS', 'IP Address', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('IPV6_ADDRESS', 'IPv6 Address', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('LINKED_URL_INTERNAL', 'Linked URL - Internal', 0, "SUBENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('LINKED_URL_EXTERNAL', 'Linked URL - External', 0, "SUBENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_ASN', 'Malicious AS', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_IPADDR', 'Malicious IP Address', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_COHOST', 'Malicious Co-Hosted Site', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_INTERNET_NAME', 'Malicious Internet Name', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_AFFILIATE_INTERNET_NAME', 'Malicious Affiliate', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_AFFILIATE_IPADDR', 'Malicious Affiliate IP Address', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_NETBLOCK', 'Malicious IP on Owned Netblock', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_SUBNET', 'Malicious IP on Same Subnet', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('NETBLOCK_OWNER', 'Netblock Ownership', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('NETBLOCK_MEMBER', 'Netblock Membership', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('NETBLOCK_WHOIS', 'Netblock Whois', 1, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('OPERATING_SYSTEM', 'Operating System', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PASTEBIN_CONTENT', 'PasteBin Content', 1, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PGP_KEY', 'PGP Public Key', 0, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PROVIDER_DNS', 'Name Server (DNS ''NS'' Records)', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PROVIDER_JAVASCRIPT', 'Externally Hosted Javascript', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PROVIDER_MAIL', 'Email Gateway (DNS ''MX'' Records)', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('RAW_RIR_DATA', 'Raw Data from RIRs', 1, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('RAW_DNS_RECORDS', 'Raw DNS Records', 1, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('RAW_FILE_META_DATA', 'Raw File Meta Data', 1, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SEARCH_ENGINE_WEB_CONTENT', 'Search Engine''s Web Content', 1, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SOCIAL_MEDIA', 'Social Media Presence', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SIMILARDOMAIN', 'Similar Domain', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SOFTWARE_USED', 'Software Used', 0, "SUBENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_RAW', 'SSL Certificate - Raw Data', 1, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_ISSUED', 'SSL Certificate - Issued to', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_ISSUER', 'SSL Certificate - Issued by', 0, "ENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_MISMATCH', 'SSL Certificate Host Mismatch', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_EXPIRED', 'SSL Certificate Expired', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_EXPIRING', 'SSL Certificate Expiring', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('TARGET_WEB_CONTENT', 'Web Content', 1, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('TARGET_WEB_COOKIE', 'Cookies', 0, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('TCP_PORT_OPEN', 'Open TCP Port', 0, "SUBENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('TCP_PORT_OPEN_BANNER', 'Open TCP Port Banner', 0, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('UDP_PORT_OPEN', 'Open UDP Port', 0, "SUBENTITY");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('UDP_PORT_OPEN_INFO', 'Open UDP Port Information', 0, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_ADBLOCKED_EXTERNAL', 'URL (AdBlocked External)', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_ADBLOCKED_INTERNAL', 'URL (AdBlocked Internal)', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_FORM', 'URL (Form)', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_FLASH', 'URL (Uses Flash)', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_JAVASCRIPT', 'URL (Uses Javascript)', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_WEB_FRAMEWORK', 'URL (Uses a Web Framework)', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_JAVA_APPLET', 'URL (Uses Java Applet)', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_STATIC', 'URL (Purely Static)', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_PASSWORD', 'URL (Accepts Passwords)', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_UPLOAD', 'URL (Accepts Uploads)', 0, "DESCRIPTOR");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('WEBSERVER_BANNER', 'Web Server', 0, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('WEBSERVER_HTTPHEADERS', 'HTTP Headers', 1, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('WEBSERVER_STRANGEHEADER', 'Non-Standard HTTP Header', 0, "DATA");
INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('WEBSERVER_TECHNOLOGY', 'Web Technology', 0, "DESCRIPTOR");
