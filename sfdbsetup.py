#-------------------------------------------------------------------------------
# Name:         sfdbsetup
# Purpose:      Create a new SpiderFoot database.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     15/02/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
#-------------------------------------------------------------------------------

import sqlite3
import sys

class SpiderFootDbInit:
    def __init__(self, opts):

        # connect() will create the database file if it doesn't exist, but
        # at least we can use this opportunity to ensure we have permissions to
        # read and write to such a file.
        dbh = sqlite3.connect(opts['__database'], timeout=10)
        if dbh == None:
            sf.error("Could not initialize internal database. Check that " + \
                opts['__database'] + " is readable and writable.")
        dbh.text_factory = str
        self.conn = dbh
        self.dbh = dbh.cursor()
        return

    # Close the database handle
    def close(self):
        self.dbh.close()

    def create(self):
        queries = [
            "PRAGMA journal_mode=WAL",
            "CREATE TABLE tbl_event_types ( \
                event       VARCHAR NOT NULL PRIMARY KEY, \
                event_descr VARCHAR NOT NULL, \
                event_raw   INT NOT NULL DEFAULT 0 \
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
                source_event_hash  VARCHAR DEFAULT 'ROOT' \
            )",
            "CREATE INDEX idx_scan_results_id ON tbl_scan_results (scan_instance_id)",
            "CREATE INDEX idx_scan_results_type ON tbl_scan_results (scan_instance_id, type)",
            "CREATE INDEX idx_scan_results_hash ON tbl_scan_results (hash)",
            "CREATE INDEX idx_scan_logs ON tbl_scan_log (scan_instance_id)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('AFFILIATE', 'Affiliate', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('EMAILADDR', 'Email Address', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('GEOINFO', 'Physical Location', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('HTTP_CODE', 'HTTP Status Code', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('INITIAL_TARGET', 'User-Supplied Target', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('IP_ADDRESS', 'IP Address', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('NETBLOCK', 'Netblock Ownership', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('LINKED_URL_INTERNAL', 'Linked URL - Internal', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('LINKED_URL_EXTERNAL', 'Linked URL - External', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('RAW_DATA', 'Raw Data', 1)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('SUBDOMAIN', 'Sub-domain', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('SIMILARDOMAIN', 'Similar Domain', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('TCP_PORT_OPEN', 'Open TCP Port', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_FORM', 'URL (Form)', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_FLASH', 'URL (Uses Flash)', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_JAVASCRIPT', 'URL (Uses Javascript)', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_JAVA_APPLET', 'URL (Uses Java applet)', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_STATIC', 'URL (Purely Static)', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_PASSWORD', 'URL (Accepts Passwords)', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('URL_UPLOAD', 'URL (Accepts Uploads)', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('WEBSERVER_BANNER', 'Web Server', 0)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('WEBSERVER_HTTPHEADERS', 'HTTP Headers', 1)",
            "INSERT INTO tbl_event_types (event, event_descr, event_raw) VALUES ('WEBSERVER_TECHNOLOGY', 'Web Technology', 0)"
        ]

        try:
            for qry in queries:
                self.dbh.execute(qry)
            self.conn.commit()
        except sqlite3.Error as e:
            raise BaseException("SQL error encountered when setting up database: " +
                e.args[0])

