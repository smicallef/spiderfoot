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
            "CREATE TABLE tbl_event_types ( \
                event       VARCHAR NOT NULL PRIMARY KEY, \
                event_descr VARCHAR NOT NULL \
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
            "CREATE TABLE tbl_scan_config ( \
                scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
                component           VARCHAR NOT NULL, \
                opt                 VARCHAR NOT NULL, \
                val                 VARCHAR NOT NULL \
            )",
            "CREATE TABLE tbl_scan_results ( \
                scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
                generated           INT NOT NULL, \
                event               VARCHAR NOT NULL REFERENCES tbl_event_types(event), \
                event_source        VARCHAR NOT NULL, \
                event_data          VARCHAR NOT NULL, \
                event_data_source   VARCHAR NOT NULL \
            )",
            "CREATE INDEX idx_scan_results_event ON tbl_scan_results (scan_instance_id, event)",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('AFFILIATE', 'Affiliate')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('EMAILADDR', 'Email Address')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('GEOINFO', 'Physical Location')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('HTTP_CODE', 'HTTP Status Code')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('IP_ADDRESS', 'IP Address')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('SUBDOMAIN', 'Sub-domain')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('SIMILARDOMAIN', 'Similar Domain')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('TCP_PORT_OPEN', 'Open TCP Port')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('URL_INTERNAL', 'URL - Internal')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('URL_EXTERNAL', 'URL - External')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('WEBCONTENT', 'Web Content')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('WEBCONTENT_FORM', 'Web Content (Form)')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('WEBCONTENT_HASFLASH', 'Web Content (Uses Flash)')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('WEBCONTENT_JAVASCRIPT', 'Web Content (Uses Javascript)')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('WEBCONTENT_STATIC', 'Web Content (Purely Static)')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('WEBCONTENT_PASSWORD', 'Web Content (Accepts Passwords)')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('WEBCONTENT_UPLOAD', 'Web Content (Accepts Uploads)')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('WEBSERVER_BANNER', 'Web Server')",
            "INSERT INTO tbl_event_types (event, event_descr) VALUES ('WEBSERVER_HTTPHEADERS', 'HTTP Headers')"
        ]

        try:
            for qry in queries:
                self.dbh.execute(qry)
            self.conn.commit()
        except sqlite3.Error as e:
            raise BaseException("SQL error encountered when setting up database: " +
                e.args[0])

