# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfdb
# Purpose:      Common functions for working with the database back-end.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     15/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

import sqlite3
import re
import time
from sflib import SpiderFoot

# SQLite doesn't support regex queries, so we create
# a custom function to do so..
def __dbregex__(qry, data):
    try:
        rx = re.compile(qry, re.IGNORECASE|re.DOTALL)
        ret = rx.match(data)
    except BaseException as e:
        return False
    return ret is not None


class SpiderFootDb:
    sf = None
    dbh = None
    conn = None

    # Queries for creating the SpiderFoot database
    createSchemaQueries = [
        "PRAGMA journal_mode=WAL",
        "CREATE TABLE tbl_event_types ( \
            event       VARCHAR NOT NULL PRIMARY KEY, \
            event_descr VARCHAR NOT NULL, \
            event_raw   INT NOT NULL DEFAULT 0, \
            event_type  VARCHAR NOT NULL \
        )",
        "CREATE TABLE tbl_config ( \
            scope   VARCHAR NOT NULL, \
            opt     VARCHAR NOT NULL, \
            val     VARCHAR NOT NULL, \
            PRIMARY KEY (scope, opt) \
        )",
        "CREATE TABLE tbl_scan_instance ( \
            guid        VARCHAR NOT NULL PRIMARY KEY, \
            name        VARCHAR NOT NULL, \
            seed_target VARCHAR NOT NULL, \
            created     INT DEFAULT 0, \
            started     INT DEFAULT 0, \
            ended       INT DEFAULT 0, \
            status      VARCHAR NOT NULL \
        )",
        "CREATE TABLE tbl_scan_log ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            generated           INT NOT NULL, \
            component           VARCHAR, \
            type                VARCHAR NOT NULL, \
            message             VARCHAR \
        )",
        "CREATE TABLE tbl_scan_config ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            component           VARCHAR NOT NULL, \
            opt                 VARCHAR NOT NULL, \
            val                 VARCHAR NOT NULL \
        )",
        "CREATE TABLE tbl_scan_results ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            hash                VARCHAR NOT NULL, \
            type                VARCHAR NOT NULL REFERENCES tbl_event_types(event), \
            generated           INT NOT NULL, \
            confidence          INT NOT NULL DEFAULT 100, \
            visibility          INT NOT NULL DEFAULT 100, \
            risk                INT NOT NULL DEFAULT 0, \
            module              VARCHAR NOT NULL, \
            data                VARCHAR, \
            false_positive      INT NOT NULL DEFAULT 0, \
            source_event_hash  VARCHAR DEFAULT 'ROOT' \
        )",
        "CREATE INDEX idx_scan_results_id ON tbl_scan_results (scan_instance_id)",
        "CREATE INDEX idx_scan_results_type ON tbl_scan_results (scan_instance_id, type)",
        "CREATE INDEX idx_scan_results_hash ON tbl_scan_results (scan_instance_id, hash)",
        "CREATE INDEX idx_scan_results_srchash ON tbl_scan_results (scan_instance_id, source_event_hash)",
        "CREATE INDEX idx_scan_logs ON tbl_scan_log (scan_instance_id)"

    ]

    createTypeQueries = [
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ROOT', 'Internal SpiderFoot Root event', 1, 'INTERNAL')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ACCOUNT_EXTERNAL_OWNED', 'Account on External Site', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ACCOUNT_EXTERNAL_OWNED_COMPROMISED', 'Hacked Account on External Site', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED', 'Hacked User Account on External Site', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_EMAILADDR', 'Affiliate - Email Address', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_INTERNET_NAME', 'Affiliate - Internet Name', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_IPADDR', 'Affiliate - IP Address', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_WEB_CONTENT', 'Affiliate - Web Content', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_DOMAIN', 'Affiliate - Domain Name', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_DOMAIN_UNRESOLVED', 'Affiliate - Domain Name - Unresolved', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_COMPANY_NAME', 'Affiliate - Company Name', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_DOMAIN_WHOIS', 'Affiliate - Domain Whois', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_DESCRIPTION_CATEGORY', 'Affiliate Description - Category', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('AFFILIATE_DESCRIPTION_ABSTRACT', 'Affiliate Description - Abstract', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('APPSTORE_ENTRY', 'App Store Entry', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('CLOUD_STORAGE_BUCKET', 'Cloud Storage Bucket', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('CLOUD_STORAGE_BUCKET_OPEN', 'Cloud Storage Bucket Open', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('COMPANY_NAME', 'Company Name', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BASE64_DATA', 'Base64-encoded Data', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BITCOIN_ADDRESS', 'Bitcoin Address', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BITCOIN_BALANCE', 'Bitcoin Balance', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BGP_AS_OWNER', 'BGP AS Ownership', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BGP_AS_MEMBER', 'BGP AS Membership', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BGP_AS_PEER', 'BGP AS Peer', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BLACKLISTED_IPADDR', 'Blacklisted IP Address', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BLACKLISTED_AFFILIATE_IPADDR', 'Blacklisted Affiliate IP Address', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BLACKLISTED_SUBNET', 'Blacklisted IP on Same Subnet', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('BLACKLISTED_NETBLOCK', 'Blacklisted IP on Owned Netblock', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('CO_HOSTED_SITE', 'Co-Hosted Site', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('CO_HOSTED_SITE_DOMAIN', 'Co-Hosted Site - Domain Name', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('CO_HOSTED_SITE_DOMAIN_WHOIS', 'Co-Hosted Site - Domain Whois', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DARKNET_MENTION_URL', 'Darknet Mention URL', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DARKNET_MENTION_CONTENT', 'Darknet Mention Web Content', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DATE_HUMAN_DOB', 'Date of Birth', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEFACED_INTERNET_NAME', 'Defaced', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEFACED_IPADDR', 'Defaced IP Address', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEFACED_AFFILIATE_INTERNET_NAME', 'Defaced Affiliate', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEFACED_COHOST', 'Defaced Co-Hosted Site', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEFACED_AFFILIATE_IPADDR', 'Defaced Affiliate IP Address', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DESCRIPTION_CATEGORY', 'Description - Category', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DESCRIPTION_ABSTRACT', 'Description - Abstract', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DEVICE_TYPE', 'Device Type', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DNS_TEXT', 'DNS TXT Record', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DNS_SRV', 'DNS SRV Record', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DNS_SPF', 'DNS SPF Record', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DOMAIN_NAME', 'Domain Name', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DOMAIN_NAME_PARENT', 'Domain Name (Parent)', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DOMAIN_REGISTRAR', 'Domain Registrar', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('DOMAIN_WHOIS', 'Domain Whois', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('EMAILADDR', 'Email Address', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('EMAILADDR_COMPROMISED', 'Hacked Email Address', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ERROR_MESSAGE', 'Error Message', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('ETHEREUM_ADDRESS', 'Ethereum Address', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('GEOINFO', 'Physical Location', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('HASH_COMPROMISED', 'Compromised Password Hash', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('HTTP_CODE', 'HTTP Status Code', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('HUMAN_NAME', 'Human Name', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('INTERESTING_FILE', 'Interesting File', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('INTERESTING_FILE_HISTORIC', 'Historic Interesting File', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('JUNK_FILE', 'Junk File', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('INTERNET_NAME', 'Internet Name', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('INTERNET_NAME_UNRESOLVED', 'Internet Name - Unresolved', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('IP_ADDRESS', 'IP Address', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('IPV6_ADDRESS', 'IPv6 Address', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('LINKED_URL_INTERNAL', 'Linked URL - Internal', 0, 'SUBENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('LINKED_URL_EXTERNAL', 'Linked URL - External', 0, 'SUBENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_ASN', 'Malicious AS', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_IPADDR', 'Malicious IP Address', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_COHOST', 'Malicious Co-Hosted Site', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_EMAILADDR', 'Malicious E-mail Address', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_INTERNET_NAME', 'Malicious Internet Name', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_AFFILIATE_INTERNET_NAME', 'Malicious Affiliate', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_AFFILIATE_IPADDR', 'Malicious Affiliate IP Address', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_NETBLOCK', 'Malicious IP on Owned Netblock', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_PHONE_NUMBER', 'Malicious Phone Number', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('MALICIOUS_SUBNET', 'Malicious IP on Same Subnet', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('NETBLOCK_OWNER', 'Netblock Ownership', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('NETBLOCK_MEMBER', 'Netblock Membership', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('NETBLOCK_WHOIS', 'Netblock Whois', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('OPERATING_SYSTEM', 'Operating System', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('LEAKSITE_URL', 'Leak Site URL', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('LEAKSITE_CONTENT', 'Leak Site Content', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PASSWORD_COMPROMISED', 'Compromised Password', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PHONE_NUMBER', 'Phone Number', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PHYSICAL_ADDRESS', 'Physical Address', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PHYSICAL_COORDINATES', 'Physical Coordinates', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PGP_KEY', 'PGP Public Key', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PROVIDER_DNS', 'Name Server (DNS ''NS'' Records)', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PROVIDER_JAVASCRIPT', 'Externally Hosted Javascript', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PROVIDER_MAIL', 'Email Gateway (DNS ''MX'' Records)', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PROVIDER_HOSTING', 'Hosting Provider', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PROVIDER_TELCO', 'Telecommunications Provider', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('PUBLIC_CODE_REPO', 'Public Code Repository', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('RAW_RIR_DATA', 'Raw Data from RIRs/APIs', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('RAW_DNS_RECORDS', 'Raw DNS Records', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('RAW_FILE_META_DATA', 'Raw File Meta Data', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SEARCH_ENGINE_WEB_CONTENT', 'Search Engine''s Web Content', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SOCIAL_MEDIA', 'Social Media Presence', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SIMILARDOMAIN', 'Similar Domain', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SIMILARDOMAIN_WHOIS', 'Similar Domain - Whois', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SOFTWARE_USED', 'Software Used', 0, 'SUBENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_RAW', 'SSL Certificate - Raw Data', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_ISSUED', 'SSL Certificate - Issued to', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_ISSUER', 'SSL Certificate - Issued by', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_MISMATCH', 'SSL Certificate Host Mismatch', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_EXPIRED', 'SSL Certificate Expired', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('SSL_CERTIFICATE_EXPIRING', 'SSL Certificate Expiring', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('TARGET_WEB_CONTENT', 'Web Content', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('TARGET_WEB_CONTENT_TYPE', 'Web Content Type', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('TARGET_WEB_COOKIE', 'Cookies', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('TCP_PORT_OPEN', 'Open TCP Port', 0, 'SUBENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('TCP_PORT_OPEN_BANNER', 'Open TCP Port Banner', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('UDP_PORT_OPEN', 'Open UDP Port', 0, 'SUBENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('UDP_PORT_OPEN_INFO', 'Open UDP Port Information', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_ADBLOCKED_EXTERNAL', 'URL (AdBlocked External)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_ADBLOCKED_INTERNAL', 'URL (AdBlocked Internal)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_FORM', 'URL (Form)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_FLASH', 'URL (Uses Flash)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_JAVASCRIPT', 'URL (Uses Javascript)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_WEB_FRAMEWORK', 'URL (Uses a Web Framework)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_JAVA_APPLET', 'URL (Uses Java Applet)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_STATIC', 'URL (Purely Static)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_PASSWORD', 'URL (Accepts Passwords)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_UPLOAD', 'URL (Accepts Uploads)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_FORM_HISTORIC', 'Historic URL (Form)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_FLASH_HISTORIC', 'Historic URL (Uses Flash)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_JAVASCRIPT_HISTORIC', 'Historic URL (Uses Javascript)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_WEB_FRAMEWORK_HISTORIC', 'Historic URL (Uses a Web Framework)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_JAVA_APPLET_HISTORIC', 'Historic URL (Uses Java Applet)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_STATIC_HISTORIC', 'Historic URL (Purely Static)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_PASSWORD_HISTORIC', 'Historic URL (Accepts Passwords)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('URL_UPLOAD_HISTORIC', 'Historic URL (Accepts Uploads)', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('USERNAME', 'Username', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('VULNERABILITY', 'Vulnerability in Public Domain', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('WEB_ANALYTICS_ID', 'Web Analytics', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('WEBSERVER_BANNER', 'Web Server', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('WEBSERVER_HTTPHEADERS', 'HTTP Headers', 1, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('WEBSERVER_STRANGEHEADER', 'Non-Standard HTTP Header', 0, 'DATA')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('WEBSERVER_TECHNOLOGY', 'Web Technology', 0, 'DESCRIPTOR')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('WIFI_ACCESS_POINT', 'WiFi Access Point Nearby', 0, 'ENTITY')",
        "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES ('WIKIPEDIA_PAGE_EDIT', 'Wikipedia Page Edit', 0, 'DESCRIPTOR')"
    ]

    def __init__(self, opts, init=False):
        self.sf = SpiderFoot(opts)

        # connect() will create the database file if it doesn't exist, but
        # at least we can use this opportunity to ensure we have permissions to
        # read and write to such a file.
        dbh = sqlite3.connect(self.sf.myPath() + "/" + opts['__database'], timeout=10)
        if dbh is None:
            self.sf.fatal("Could not connect to internal database, and couldn't create " + opts['__database'])
        dbh.text_factory = str

        self.conn = dbh
        self.dbh = dbh.cursor()

        # Now we actually check to ensure the database file has the schema set
        # up correctly.
        try:
            self.dbh.execute('SELECT COUNT(*) FROM tbl_scan_config')
            self.conn.create_function("REGEXP", 2, __dbregex__)
        except sqlite3.Error:
            # .. If not set up, we set it up.
            try:
                self.create()
                init = True
            except BaseException as e:
                self.sf.error("Tried to set up the SpiderFoot database schema, but failed: " + e.args[0])
            return

        if init:
            print("Attempting to verify database and update if necessary...")
            for qry in self.createTypeQueries:
                try:
                    self.dbh.execute(qry)
                    self.conn.commit()
                except BaseException as e:
                    continue
            self.conn.commit()
            #self.conn.close()

    #
    # Back-end database operations
    #

    # Create the back-end schema
    def create(self):
        try:
            for qry in self.createSchemaQueries:
                self.dbh.execute(qry)
            self.conn.commit()
            for qry in self.createTypeQueries:
                self.dbh.execute(qry)
            self.conn.commit()
        except sqlite3.Error as e:
            raise BaseException("SQL error encountered when setting up database: " + e.args[0])

    # Close the database handle
    def close(self):
        self.dbh.close()

    # Search results
    # criteria is search criteria such as:
    #  - scan_id (search within a scan, if omitted search all)
    #  - type (search a specific type, if omitted search all)
    #  - value (search values for a specific string, if omitted search all)
    #  - regex (search values for a regular expression)
    # ** at least two criteria must be set **
    def search(self, criteria, filterFp=False):
        if criteria.values().count(None) == 3:
            return False

        qvars = list()
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, c.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
            WHERE s.scan_instance_id = c.scan_instance_id AND \
            t.event = c.type AND c.source_event_hash = s.hash "

        if filterFp:
            qry += " AND c.false_positive <> 1 "

        if criteria.get('scan_id') is not None:
            qry += "AND c.scan_instance_id = ? "
            qvars.append(criteria['scan_id'])

        if criteria.get('type') is not None:
            qry += " AND c.type = ? "
            qvars.append(criteria['type'])

        if criteria.get('value') is not None:
            qry += " AND (c.data LIKE ? OR s.data LIKE ?) "
            qvars.append(criteria['value'])
            qvars.append(criteria['value'])

        if criteria.get('regex') is not None:
            qry += " AND (c.data REGEXP ? OR s.data REGEXP ?) "
            qvars.append(criteria['regex'])
            qvars.append(criteria['regex'])

        qry += " ORDER BY c.data"

        try:
            #print(qry)
            #print(str(qvars))
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when fetching search results: " + e.args[0])

    # Get event types
    def eventTypes(self):
        qry = "SELECT event_descr, event, event_raw, event_type FROM tbl_event_types"
        try:
            self.dbh.execute(qry)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when retreiving event types:" + e.args[0])

    # Log an event to the database
    def scanLogEvent(self, instanceId, classification, message, component=None):
        if component is None:
            component = "SpiderFoot"

        qry = "INSERT INTO tbl_scan_log \
            (scan_instance_id, generated, component, type, message) \
            VALUES (?, ?, ?, ?, ?)"
        try:
            self.dbh.execute(qry, (
                instanceId, time.time() * 1000, component, classification, message
            ))
            self.conn.commit()
        except sqlite3.Error as e:
            if "locked" in e.args[0]:
                # TODO: Do something smarter here to handle locked databases
                self.sf.fatal("Unable to log event in DB due to lock: " + e.args[0])
            else:
                self.sf.fatal("Unable to log event in DB: " + e.args[0])

        return True

    # Store a scan instance
    def scanInstanceCreate(self, instanceId, scanName, scanTarget):
        qry = "INSERT INTO tbl_scan_instance \
            (guid, name, seed_target, created, status) \
            VALUES (?, ?, ?, ?, ?)"
        try:
            self.dbh.execute(qry, (
                instanceId, scanName, scanTarget, time.time() * 1000, 'CREATED'
            ))
            self.conn.commit()
        except sqlite3.Error as e:
            self.sf.fatal("Unable to create instance in DB: " + e.args[0])

        return True

    # Update the start time, end time or status (or all 3) of a scan instance
    def scanInstanceSet(self, instanceId, started=None, ended=None, status=None):
        qvars = list()
        qry = "UPDATE tbl_scan_instance SET "

        if started is not None:
            qry += " started = ?,"
            qvars.append(started)

        if ended is not None:
            qry += " ended = ?,"
            qvars.append(ended)

        if status is not None:
            qry += " status = ?,"
            qvars.append(status)

        # guid = guid is a little hack to avoid messing with , placement above
        qry += " guid = guid WHERE guid = ?"
        qvars.append(instanceId)

        try:
            self.dbh.execute(qry, qvars)
            self.conn.commit()
        except sqlite3.Error:
            self.sf.fatal("Unable to set information for the scan instance.")

    # Return info about a scan instance (name, target, created, started,
    # ended, status) - don't need this yet - untested
    def scanInstanceGet(self, instanceId):
        qry = "SELECT name, seed_target, ROUND(created/1000) AS created, \
            ROUND(started/1000) AS started, ROUND(ended/1000) AS ended, status \
            FROM tbl_scan_instance WHERE guid = ?"
        qvars = [instanceId]
        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchone()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when retreiving scan instance:" + e.args[0])

    # Obtain a summary of the results per event type
    def scanResultSummary(self, instanceId, by="type"):
        if by == "type":
            qry = "SELECT r.type, e.event_descr, MAX(ROUND(generated)) AS last_in, \
                count(*) AS total, count(DISTINCT r.data) as utotal FROM \
                tbl_scan_results r, tbl_event_types e WHERE e.event = r.type \
                AND r.scan_instance_id = ? GROUP BY r.type ORDER BY e.event_descr"

        if by == "module":
            qry = "SELECT r.module, '', MAX(ROUND(generated)) AS last_in, \
                count(*) AS total, count(DISTINCT r.data) as utotal FROM \
                tbl_scan_results r, tbl_event_types e WHERE e.event = r.type \
                AND r.scan_instance_id = ? GROUP BY r.module ORDER BY r.module DESC"

        if by == "entity":
            qry = "SELECT r.data, e.event_descr, MAX(ROUND(generated)) AS last_in, \
                count(*) AS total, count(DISTINCT r.data) as utotal FROM \
                tbl_scan_results r, tbl_event_types e WHERE e.event = r.type \
                AND r.scan_instance_id = ? \
                AND e.event_type in ('ENTITY') \
                GROUP BY r.data, e.event_descr ORDER BY total DESC limit 50"

        qvars = [instanceId]
        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when fetching result summary: " + e.args[0])

    # Obtain the data for a scan and event type
    def scanResultEvent(self, instanceId, eventType='ALL', filterFp=False):
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
            WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
            s.scan_instance_id = c.scan_instance_id AND \
            t.event = c.type"

        qvars = [instanceId]

        if eventType != "ALL":
            qry += " AND c.type = ?"
            qvars.append(eventType)

        if filterFp:
            qry += " AND c.false_positive <> 1"

        qry += " ORDER BY c.data"

        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when fetching result events: " + e.args[0])

    # Obtain a unique list of elements
    def scanResultEventUnique(self, instanceId, eventType='ALL', filterFp=False):
        qry = "SELECT DISTINCT data, type, COUNT(*) FROM tbl_scan_results \
            WHERE scan_instance_id = ?"
        qvars = [instanceId]

        if eventType != "ALL":
            qry += " AND type = ?"
            qvars.append(eventType)

        if filterFp:
            qry += " AND false_positive <> 1"

        qry += " GROUP BY type, data ORDER BY COUNT(*)"

        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when fetching unique result events: " + e.args[0])

    # Get scan logs
    def scanLogs(self, instanceId, limit=None, fromRowId=None, reverse=False):
        qry = "SELECT generated AS generated, component, \
            type, message, rowid FROM tbl_scan_log WHERE scan_instance_id = ?"
        if fromRowId:
            qry += " and rowid > ?"
        
        qry += " ORDER BY generated "
        if reverse:
            qry += "ASC"
        else:
            qry += "DESC"
        qvars = [instanceId]

        if fromRowId:
            qvars.append(fromRowId)

        if limit is not None:
            qry += " LIMIT ?"
            qvars.append(limit)

        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when fetching scan logs: " + e.args[0])

    # Get scan errors
    def scanErrors(self, instanceId, limit=None):
        qry = "SELECT generated AS generated, component, \
            message FROM tbl_scan_log WHERE scan_instance_id = ? \
            AND type = 'ERROR' ORDER BY generated DESC"
        qvars = [instanceId]

        if limit is not None:
            qry += " LIMIT ?"
            qvars.append(limit)

        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when fetching scan errors: " + e.args[0])

    # Delete a scan instance
    def scanInstanceDelete(self, instanceId):
        qry1 = "DELETE FROM tbl_scan_instance WHERE guid = ?"
        qry2 = "DELETE FROM tbl_scan_config WHERE scan_instance_id = ?"
        qry3 = "DELETE FROM tbl_scan_results WHERE scan_instance_id = ?"
        qry4 = "DELETE FROM tbl_scan_log WHERE scan_instance_id = ?"
        qvars = [instanceId]
        try:
            self.dbh.execute(qry1, qvars)
            self.dbh.execute(qry2, qvars)
            self.dbh.execute(qry3, qvars)
            self.dbh.execute(qry4, qvars)
            self.conn.commit()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when deleting scan: " + e.args[0])

    # Set the false positive flag for a result
    def scanResultsUpdateFP(self, instanceId, resultHashes, fpFlag):
        for resultHash in resultHashes:
            qry = "UPDATE tbl_scan_results SET false_positive = ? WHERE \
                scan_instance_id = ? AND hash = ?"
            qvars = [fpFlag, instanceId, resultHash]
            try:
                self.dbh.execute(qry, qvars)
            except sqlite3.Error as e:
                self.sf.error("SQL error encountered when updating F/P: " + e.args[0], False)
                return False

        self.conn.commit()
        return True

    # Store the default configuration
    def configSet(self, optMap=dict()):
        qry = "REPLACE INTO tbl_config (scope, opt, val) VALUES (?, ?, ?)"
        for opt in optMap.keys():
            # Module option
            if ":" in opt:
                parts = opt.split(':')
                qvals = [parts[0], parts[1], optMap[opt]]
            else:
                # Global option
                qvals = ["GLOBAL", opt, optMap[opt]]

            try:
                self.dbh.execute(qry, qvals)
            except sqlite3.Error as e:
                self.sf.error("SQL error encountered when storing config, aborting: " + e.args[0])

            self.conn.commit()

    # Retreive the config from the database
    def configGet(self):
        qry = "SELECT scope, opt, val FROM tbl_config"
        try:
            retval = dict()
            self.dbh.execute(qry)
            for [scope, opt, val] in self.dbh.fetchall():
                if scope == "GLOBAL":
                    retval[opt] = val
                else:
                    retval[scope + ":" + opt] = val

            return retval
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when fetching configuration: " + e.args[0])

    # Reset the config to default (clear it from the DB and let the hard-coded
    # settings in the code take effect.)
    def configClear(self):
        qry = "DELETE from tbl_config"
        try:
            self.dbh.execute(qry)
            self.conn.commit()
        except sqlite3.Error as e:
            self.sf.error("Unable to clear configuration from the database: " + e.args[0])

    # Store a configuration value for a scan
    def scanConfigSet(self, id, optMap=dict()):
        qry = "REPLACE INTO tbl_scan_config \
                (scan_instance_id, component, opt, val) VALUES (?, ?, ?, ?)"

        for opt in optMap.keys():
            # Module option
            if ":" in opt:
                parts = opt.split(':')
                qvals = [id, parts[0], parts[1], optMap[opt]]
            else:
                # Global option
                qvals = [id, "GLOBAL", opt, optMap[opt]]

            try:
                self.dbh.execute(qry, qvals)
            except sqlite3.Error as e:
                self.sf.error("SQL error encountered when storing config, aborting: " + e.args[0])

            self.conn.commit()

    # Retreive configuration data for a scan component
    def scanConfigGet(self, instanceId):
        qry = "SELECT component, opt, val FROM tbl_scan_config \
                WHERE scan_instance_id = ? ORDER BY component, opt"
        qvars = [instanceId]
        try:
            retval = dict()
            self.dbh.execute(qry, qvars)
            for [component, opt, val] in self.dbh.fetchall():
                if component == "GLOBAL":
                    retval[opt] = val
                else:
                    retval[component + ":" + opt] = val
            return retval
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when fetching configuration: " + e.args[0])

    # Store an event
    # eventData is a SpiderFootEvent object with the following variables:
    # - eventType: the event, e.g. URL_FORM, RAW_DATA, etc.
    # - generated: time the event occurred
    # - confidence: how sure are we of this data's validity, 0-100
    # - visibility: how 'visible' was this data, 0-100
    # - risk: how much risk does this data represent, 0-100
    # - module: module that generated the event
    # - data: the actual data, i.e. a URL, port number, webpage content, etc.
    # - sourceEventHash: hash of the event that triggered this event
    # And getHash() will return the event hash.
    def scanEventStore(self, instanceId, sfEvent, truncateSize=0):
        storeData = ''

        if type(sfEvent.data) is not unicode:
            # If sfEvent.data is a dict or list, convert it to a string first, as
            # those types do not have a unicode converter.
            if type(sfEvent.data) is str:
                storeData = unicode(sfEvent.data, 'utf-8', errors='replace')
            else:
                try:
                    storeData = unicode(str(sfEvent.data), 'utf-8', errors='replace')
                except BaseException as e:
                    self.sf.fatal("Unhandled type detected: " + str(type(sfEvent.data)))
        else:
            storeData = sfEvent.data

        if truncateSize > 0:
            storeData = storeData[0:truncateSize]

        if sfEvent.sourceEventHash in ["", None]:
            self.sf.fatal("UNABLE TO CREATE RECORD WITH EMPTY SOURCE EVENT HASH!")

        qry = "INSERT INTO tbl_scan_results \
            (scan_instance_id, hash, type, generated, confidence, \
            visibility, risk, module, data, source_event_hash) \
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        qvals = [instanceId, sfEvent.getHash(), sfEvent.eventType, sfEvent.generated,
                 sfEvent.confidence, sfEvent.visibility, sfEvent.risk,
                 sfEvent.module, storeData, sfEvent.sourceEventHash]

        #print("STORING: " + str(qvals))

        try:
            self.dbh.execute(qry, qvals)
            self.conn.commit()
            return None
        except sqlite3.Error as e:
            self.sf.fatal("SQL error encountered when storing event data (" + str(self.dbh) + ": " + e.args[0])

    # List of all previously run scans
    def scanInstanceList(self):
        # SQLite doesn't support OUTER JOINs, so we need a work-around that
        # does a UNION of scans with results and scans without results to 
        # get a complete listing.
        qry = "SELECT i.guid, i.name, i.seed_target, ROUND(i.created/1000), \
            ROUND(i.started)/1000 as started, ROUND(i.ended)/1000, i.status, COUNT(r.type) \
            FROM tbl_scan_instance i, tbl_scan_results r WHERE i.guid = r.scan_instance_id \
            AND r.type <> 'ROOT' GROUP BY i.guid \
            UNION ALL \
            SELECT i.guid, i.name, i.seed_target, ROUND(i.created/1000), \
            ROUND(i.started)/1000 as started, ROUND(i.ended)/1000, i.status, '0' \
            FROM tbl_scan_instance i  WHERE i.guid NOT IN ( \
            SELECT distinct scan_instance_id FROM tbl_scan_results WHERE type <> 'ROOT') \
            ORDER BY started DESC"
        try:
            self.dbh.execute(qry)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when fetching scan list: " + e.args[0])

    # History of data from the scan
    def scanResultHistory(self, instanceId):
        qry = "SELECT STRFTIME('%H:%M %w', generated, 'unixepoch') AS hourmin, \
                type, COUNT(*) FROM tbl_scan_results \
                WHERE scan_instance_id = ? GROUP BY hourmin, type"
        qvars = [instanceId]
        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when fetching scan history: " + e.args[0])


    # Get the source IDs, types and data for a set of IDs
    def scanElementSourcesDirect(self, instanceId, elementIdList):
        # the output of this needs to be aligned with scanResultEvent,
        # as other functions call both expecting the same output.
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
            WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
            s.scan_instance_id = c.scan_instance_id AND \
            t.event = c.type AND c.hash in ("
        qvars = [instanceId]

        for hashId in elementIdList:
            qry = qry + "'" + hashId + "',"
        qry += "'')"

        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when getting source element IDs: " + e.args[0])

    # Get the child IDs, types and data for a set of IDs
    def scanElementChildrenDirect(self, instanceId, elementIdList):
        # the output of this needs to be aligned with scanResultEvent,
        # as other functions call both expecting the same output.
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
            WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
            s.scan_instance_id = c.scan_instance_id AND \
            t.event = c.type AND s.hash in ("
        qvars = [instanceId]

        for hashId in elementIdList:
            qry = qry + "'" + hashId + "',"
        qry += "'')"

        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            self.sf.error("SQL error encountered when getting child element IDs: " + e.args[0])

    # Get the full set of upstream IDs which are parents to the 
    # supplied set of IDs.
    # Data has to be in the format of output from scanElementSourcesDirect
    # and produce output in the same format.
    def scanElementSourcesAll(self, instanceId, childData):
        # Get the first round of source IDs for the leafs
        keepGoing = True
        nextIds = list()
        datamap = dict()
        pc = dict()

        for row in childData:
            # these must be unique values!
            parentId = row[9]
            childId = row[8]
            datamap[childId] = row

            if parentId in pc:
                if childId not in pc[parentId]:
                    pc[parentId].append(childId)
            else:
                pc[parentId] = [childId]

            # parents of the leaf set
            if parentId not in nextIds:
                nextIds.append(parentId)

        while keepGoing:
            parentSet = self.scanElementSourcesDirect(instanceId, nextIds)
            nextIds = list()
            keepGoing = False

            for row in parentSet:
                parentId = row[9]
                childId = row[8]
                datamap[childId] = row
                #print(childId + " = " + str(row))

                if parentId in pc:
                    if childId not in pc[parentId]:
                        pc[parentId].append(childId)
                else:
                    pc[parentId] = [childId]
                if parentId not in nextIds:
                    nextIds.append(parentId)

                # Prevent us from looping at root
                if parentId != "ROOT":
                    keepGoing = True

        datamap[parentId] = row
        return [datamap, pc]

    # Get the full set of downstream IDs which are children of the 
    # supplied set of IDs
    # NOTE FOR NOW THE BEHAVIOR IS NOT THE SAME AS THE scanElementParent*
    # FUNCTIONS - THIS ONLY RETURNS IDS!!
    def scanElementChildrenAll(self, instanceId, parentIds):
        datamap = list()
        keepGoing = True
        nextIds = list()

        nextSet = self.scanElementChildrenDirect(instanceId, parentIds)
        for row in nextSet:
            datamap.append(row[8])

        for row in nextSet:
            if row[8] not in nextIds:
                nextIds.append(row[8])

        while keepGoing:
            nextSet = self.scanElementChildrenDirect(instanceId, nextIds)
            if nextSet == None or len(nextSet) == 0:
                keepGoing = False
                break

            for row in nextSet:
                datamap.append(row[8])
                nextIds = list()
                nextIds.append(row[8])

        return datamap
