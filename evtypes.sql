--
-- Event types and their descriptions
--
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('AFFILIATE', 'Affiliate', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('EMAILADDR', 'Email Address', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('GEOINFO', 'Physical Location', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('HTTP_CODE', 'HTTP Status Code', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('INITIAL_TARGET', 'User-Supplied Target', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('IP_ADDRESS', 'IP Address', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('LINKED_URL_INTERNAL', 'Linked URL - Internal', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('LINKED_URL_EXTERNAL', 'Linked URL - External', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('NETBLOCK', 'Netblock Ownership', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('PROVIDER_DNS', 'DNS Name Server', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('PROVIDER_HOSTING', 'Hosting Provider', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('PROVIDER_INTERNET', 'Internet Service Provider', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('PROVIDER_JAVASCRIPT', 'Externally Hosted Javascript', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('PROVIDER_MAIL', 'Email Gateway (MX)', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('RAW_DATA', 'Raw Data', 1);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('SOCIAL_MEDIA', 'Social Media Presence', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('SUBDOMAIN', 'Sub-domain', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('SIMILARDOMAIN', 'Similar Domain', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('SSL_CERTIFICATE_ISSUER', 'SSL Certificate Issuer', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('SSL_CERTIFICATE_MISMATCH', 'SSL Certificate Host Mismatch', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('SSL_CERTIFICATE_EXPIRED', 'SSL Certificate Expired', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('TCP_PORT_OPEN', 'Open TCP Port', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('TCP_PORT_OPEN_BANNER', 'Open TCP Port Banner', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_FORM', 'URL (Form)', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_FLASH', 'URL (Uses Flash)', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_JAVASCRIPT', 'URL (Uses Javascript)', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_JAVASCRIPT_FRAMEWORK', 'URL (Uses a Javascript Framework)', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_JAVA_APPLET', 'URL (Uses Java Applet)', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_STATIC', 'URL (Purely Static)', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_PASSWORD', 'URL (Accepts Passwords)', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_UPLOAD', 'URL (Accepts Uploads)', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('WEBSERVER_BANNER', 'Web Server', 0);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('WEBSERVER_HTTPHEADERS', 'HTTP Headers', 1);
INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('WEBSERVER_TECHNOLOGY', 'Web Technology', 0);
