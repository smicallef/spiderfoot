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
        dbh = sqlite3.connect(opts['__database'], timeout=10)
        if dbh == None:
            sf.error("Could not connect to internal database. Check that " + \
                opts['__database'] + " exists and is readable and writable.")
        dbh.text_factory = str

        self.conn = dbh

        self.dbh = dbh.cursor()
        sf = SpiderFoot(opts)

        # Now we actually check to ensure the database file has the schema set
        # up correctly.
        try:
            self.dbh.execute('SELECT COUNT(*) FROM tbl_scan_config')
        except sqlite3.Error:
            sf.error("Found spiderfoot.db but it doesn't appear to be in " \
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
            sf.fatal("Unable to create instance in DB: " + e.args[0])

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
        qry = "SELECT name, seed_target, ROUND(created/1000) AS created, \
            ROUND(started/1000) AS started, ROUND(ended/1000) AS ended, status \
            FROM tbl_scan_instance WHERE guid = ?"
        qvars = [instanceId]
        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchone()
        except sqlite3.Error as e:
            sf.error("SQL error encountered when retreiving scan instance:" +
                e.args[0])

    # Obtain a summary of the results per event type
    def scanResultSummary(self, instanceId):
        qry = "SELECT r.event, e.event_descr, max(ROUND(generated))/1000 AS last_in, \
            count(*) AS total FROM \
            tbl_scan_results r, tbl_event_types e WHERE e.event = r.event \
            AND r.scan_instance_id = ? GROUP BY r.event"
        qvars = [instanceId]
        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            sf.error("SQL error encountered when fetching result summary: " +
                e.args[0])

    # Obtain the data for a scan and event type
    def scanResultEvent(self, instanceId, eventType='ALL'):
        qry = "SELECT ROUND(generated/1000) AS generated, event_data, event_source, \
            event_data_source, event FROM tbl_scan_results WHERE scan_instance_id = ?"
        qvars = [instanceId]

        if eventType != "ALL":
            qry = qry + " AND event = ?"
            qvars.append(eventType)

        qry = qry + " ORDER BY event_data, event_source"

        try:
            self.dbh.execute(qry, qvars)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            sf.error("SQL error encountered when fetching result events: " +
                e.args[0])

    # Delete a scan instance
    def scanInstanceDelete(self, instanceId):
        qry1 = "DELETE FROM tbl_scan_instance WHERE guid = ?"
        qry2 = "DELETE FROM tbl_scan_config WHERE scan_instance_id = ?"
        qry3 = "DELETE FROM tbl_scan_results WHERE scan_instance_id = ?"
        qvars = [instanceId]
        try:
            self.dbh.execute(qry1, qvars)
            self.dbh.execute(qry2, qvars)
            self.dbh.execute(qry3, qvars)
            self.conn.commit()
        except sqlite3.Error as e:
            sf.error("SQL error encountered when deleting scan: " +
                e.args[0])

    # Store the default configuration
    def configSet(self, optMap=dict()):
        qry = "REPLACE INTO tbl_config (scope, opt, val) VALUES (?, ?, ?)"
        for opt in optMap.keys():
            # Module option
            if ":" in opt:
                parts = opt.split(':')
                qvals = [ parts[0], parts[1], optMap[opt] ]
            else:
            # Global option
                qvals = [ "GLOBAL", opt, optMap[opt] ]

            try:
                self.dbh.execute(qry, qvals)
            except sqlite3.Error as e:
                sf.error("SQL error encountered when storing config, aborting: " +
                    e.args[0])

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
            sf.error("SQL error encountered when fetching configuration: " + e.args[0])

    # Reset the config to default (clear it from the DB and let the hard-coded
    # settings in the code take effect.)
    def configClear(self):
        qry = "DELETE from tbl_config"
        try:
            self.dbh.execute(qry)
            self.conn.commit()
        except sqlite3.Error as e:
            sf.error("Unable to clear configuration from the database: " + e.args[0])

    # Store a configuration value for a scan
    def scanConfigSet(self, id, optMap=dict()):
        qry = "REPLACE INTO tbl_scan_config \
                (scan_instance_id, component, opt, val) VALUES (?, ?, ?, ?)"

        for opt in optMap.keys():
            # Module option
            if ":" in opt:
                parts = opt.split(':')
                qvals = [ id, parts[0], parts[1], optMap[opt] ]
            else:
            # Global option
                qvals = [ id, "GLOBAL", opt, optMap[opt] ]

            try:
                self.dbh.execute(qry, qvals)
            except sqlite3.Error as e:
                sf.error("SQL error encountered when storing config, aborting: " +
                    e.args[0])

            self.conn.commit()

    # Retreive configuration data for a scan component
    def scanConfigGet(self, instanceId):
        qry = "SELECT component, opt, val FROM tbl_scan_config \
                WHERE scan_instance_id = ?"
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
            sf.error("SQL error encountered when fetching configuration: " + e.args[0])

    # Store an event
    def scanEventStore(self, instanceId, eventName, eventSource,
        eventData, eventDataSource):
        qry = "INSERT INTO tbl_scan_results \
            (scan_instance_id, generated, event, event_source, \
            event_data, event_data_source) \
            VALUES (?, ?, ?, ?, ?, ?)"
        qvals = [instanceId, time.time() * 1000, eventName, eventSource,
            eventData.__str__(), eventDataSource]

        try:
            self.dbh.execute(qry, qvals)
            self.conn.commit()
            return None
        except sqlite3.Error as e:
            sf.fatal("SQL error encountered when storing event data (" + str(self.dbh) + ": " +
                e.args[0])

    # List of all previously run scans
    def scanInstanceList(self):
        # SQLite doesn't support OUTER JOINs, so we need a work-around that
        # does a UNION of scans with results and scans without results to 
        # get a complete listing.
        qry = "SELECT i.guid, i.name, i.seed_target, ROUND(i.created/1000), \
            ROUND(i.started)/1000 as started, ROUND(i.ended)/1000, i.status, COUNT(r.event) \
            FROM tbl_scan_instance i, tbl_scan_results r WHERE i.guid = r.scan_instance_id \
            GROUP BY i.guid \
            UNION ALL \
            SELECT i.guid, i.name, i.seed_target, ROUND(i.created/1000), \
            ROUND(i.started)/1000 as started, ROUND(i.ended)/1000, i.status, '0' \
            FROM tbl_scan_instance i  WHERE i.guid NOT IN ( \
            SELECT distinct scan_instance_id FROM tbl_scan_results) \
            ORDER BY started DESC"
        try:
            self.dbh.execute(qry)
            return self.dbh.fetchall()
        except sqlite3.Error as e:
            sf.error("SQL error encountered when fetching scan list: " + e.args[0])
