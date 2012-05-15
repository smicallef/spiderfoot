#-------------------------------------------------------------------------------
# Name:         sfdb
# Purpose:      Common functions for working with the database back-end.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     15/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import hashlib
import random
import sqlite3
import sys
import time
from sflib import SpiderFoot

# SpiderFoot class passed to us
sf = None

class SpiderFootDb:
    def __init__(self, opts):
        global sf

        # connect() will create the database file if it doesn't exist, but
        # at least we can use this opportunity to ensure we have permissions to
        # read and write to such a file.
        dbh = sqlite3.connect(opts['_database'], timeout=10)
        if dbh == None:
            sf.fatal("Could not connect to internal database. Check that " + \
                opts['_database'] + " exists and is readable and writable.")
        dbh.text_factory = str

        self.conn = dbh

        self.dbh = dbh.cursor()
        sf = SpiderFoot(opts)

        # Now we actually check to ensure the database file has the schema set
        # up correctly.
        try:
            self.dbh.execute('SELECT COUNT(*) FROM tbl_scan_config')
        except sqlite3.Error:
            sf.fatal("Found spiderfoot.db but it doesn't appear to be in " \
                "the expected state - ensure the schema is created.")

        return

    #
    # Back-end database operations
    #

    # Close the database handle
    def close(self):
        self.dbh.close()

    # Generate an globally unique ID for this scan
    def scanInstanceGenGUID(self, scanName):
        hashStr = hashlib.sha256(
                scanName +
                str(time.time() * 1000) +
                str(random.randint(100000, 999999))
            ).hexdigest()
        sf.debug("Using GUID of: " + hashStr)
        return hashStr

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
            sf.fatal("Unable to create instance in DB: " + e.message)

        return True

    # Update the start time, end time or status (or all 3) of a scan instance
    def scanInstanceSet(self, instanceId, started=None, ended=None, status=None):
        qvars = list()
        qry = "UPDATE tbl_scan_instance SET "

        if started != None:
            qry += " started = ?,"
            qvars.append(started)

        if ended != None:
            qry += " ended = ?,"
            qvars.append(ended)

        if status != None:
            qry += " status = ?,"
            qvars.append(status)

        # guid = guid is a little hack to avoid messing with , placement above
        qry += " guid = guid WHERE guid = ?"
        qvars.append(instanceId)

        try:
            self.dbh.execute(qry, qvars)
            self.conn.commit()
        except sqlite3.Error:
            sf.fatal("Unable to set information for the scan instance.")

    # Return info about a scan instance (name, target, created, started,
    # ended, status) - don't need this yet - untested
    def scanInstanceGet(self, instanceId):
        qry = "SELECT name, seed_target, created, started, ended, status \
            FROM tbl_scan_instance WHERE guid = ?"
        try:
            self.dbh.execute(qry, list(instanceId))
            return self.dbh.fetchone()
        except sqlite3.Error as e:
            sf.fatal("SQL error encountered when retreiving scan instance:" +
                e.message)

    # Delete a scan instance - don't need this yet
    def scanInstanceDelete(self, instanceId):
        pass

    # Store a configuration value for a scan
    # To unset, simply set the optMap key value to None
    # don't need this yet
    def scanConfigSet(self, instanceId, component, optMap=dict()):
        pass

    # Retreive configuration data for a scan component
    # don't need this yet
    def scanConfigGet(self, instanceId, component):
        pass

    # Store an event
    def scanEventStore(self, instanceId, eventName, eventSource,
        eventData, eventDataSource):
        qry = "INSERT INTO tbl_scan_results \
            (scan_instance_id, generated, event, event_source, \
            event_data, event_data_source) \
            VALUES (?, ?, ?, ?, ?, ?)"
        qvals = [instanceId, time.time() * 1000, eventName, eventSource,
            eventData, eventDataSource]

        try:
            self.dbh.execute(qry, qvals)
            self.conn.commit()
            return None
        except sqlite3.Error as e:
            sf.fatal("SQL error encountered when storing event data: " +
                e.message)
