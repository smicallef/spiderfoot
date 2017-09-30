# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_accounts
# Purpose:      Identify the existence of a given acount on various sites thanks 
#               to Micah Hoffman's (https://github.com/WebBreacher) list.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     18/02/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import time
import threading
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_accounts(SpiderFootPlugin):
    """Accounts:Footprint,Passive:Social Media:slow:Look for possible associated accounts on nearly 200 websites like Ebay, Slashdot, reddit, etc."""


    # Default options
    opts = {
        "generic": ["root", "abuse", "sysadm", "sysadmin", "noc", "support", "admin",
                    "contact", "help", "flame", "test", "info", "sales", "hostmaster"],
        "ignorenamedict": True,
        "ignoreworddict": True,
        "musthavename": True,
        "maxthreads": 25
    }

    # Option descriptions
    optdescs = {
        "generic": "Generic internal accounts to not bother looking up externally.",
        "ignorenamedict": "Don't bother looking up names that are just stand-alone first names (too many false positives).",
        "ignoreworddict": "Don't bother looking up names that appear in the dictionary.",
        "musthavename": "The username must be mentioned on the social media page to consider it valid (helps avoid false positives).",
        "maxthreads": "Maximum number of simultaneous threads (one thread per site the account is being checked on.)"
    }

    results = dict()
    reportedUsers = list()
    siteResults = dict()
    sites = dict()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.commonNames = list()
        self.reportedUsers = list()
        self.errorState = False
        self.__dataSource__ = "Social Media"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        self.commonNames = set(self.sf.dictnames())
        self.words = set(self.sf.dictwords())

        content = self.sf.cacheGet("sfaccounts", 48)
        if content is None:
            url = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/master/web_accounts_list.json"
            data = self.sf.fetchUrl(url, useragent="SpiderFoot")
            if data['content'] is None:
                self.sf.error("Unable to fetch " + url, False)
                self.errorState = True
                return None
            else:
                self.sf.cachePut("sfaccounts", data['content'])
                content = data['content']

        self.sites = json.loads(content)

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["EMAILADDR", "DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["USERNAME", "ACCOUNT_EXTERNAL_OWNED", 
                "ACCOUNT_EXTERNAL_USER_SHARED"]

    def checkSite(self, name, site):
        if 'check_uri' not in site:
            return None

        url = site['check_uri'].format(account=name)
        retname = site['name'] + " (Category: " + site['category'] + ")\n<SFURL>" + \
                url + "</SFURL>"

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'], noLog=True)

        if not res['content']:
            self.siteResults[retname] = False
            return

        try:
            found = False
            site['account_existence_code'] = str(site['account_existence_code'])
            if site['account_existence_code']:
                if site['account_existence_code'] == res['code']:
                    found = True
            if site['account_missing_code']: 
                if site['account_missing_code'] == res['code']:
                    found = False
            if site['account_existence_string']:
                if site['account_existence_string'] in res['content']:
                    found = True
            if site['account_missing_string']:
                if site['account_missing_string'] in res['content']:
                    found = False
        except BaseException:
            #self.sf.debug("Error parsing configuration: " + str(site))
            found = False

        if found and self.opts['musthavename']:
            if name not in res['content']:
                found = False

        self.siteResults[retname] = found

    def threadSites(self, name, siteList):
        ret = list()
        self.siteResults = dict()
        running = True
        i = 0
        t = []

        for site in siteList:
            if self.checkForStop():
                return None

            self.sf.info("Spawning thread to check site: " + site['name'] + \
                        " / " + site['check_uri'].format(account=name))
            t.append(threading.Thread(name='sfp_accounts_' + site['name'],
                                      target=self.checkSite, args=(name, site)))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("sfp_accounts_"):
                    found = True

            if not found:
                running = False

            time.sleep(2) 

        # Return once the scanning has completed
        return self.siteResults

    def batchSites(self, name):
        i = 0
        res = list()
        siteList = list()

        for site in self.sites['sites']:
            if not site['valid'] or 'check_uri' not in site:
                continue
            if i >= self.opts['maxthreads']:
                data = self.threadSites(name, siteList)
                if data == None:
                    return res

                for ret in data.keys():
                    if data[ret]:
                        res.append(ret)
                i = 0
                siteList = list()

            siteList.append(site)
            i += 1

        return res

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        users = list()

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData not in self.results.keys():
            self.results[eventData] = True
        else:
            return None

        if eventName == "DOMAIN_NAME":
            kw = self.sf.domainKeyword(eventData, self.opts['_internettlds'])

            res = self.batchSites(kw)
            for site in res:
                evt = SpiderFootEvent("ACCOUNT_EXTERNAL_OWNED", site,
                                      self.__name__, event)
                self.notifyListeners(evt)
            return None

        if eventName == "EMAILADDR":
            name = eventData.split("@")[0].lower()
            if self.opts['generic'] is list() and name in self.opts['generic']:
                self.sf.debug(name + " is a generic account name, skipping.")
                return None

            if self.opts['ignorenamedict'] and name in self.commonNames:
                self.sf.debug(name + " is found in our name dictionary, skipping.")
                return None

            if self.opts['ignoreworddict'] and name in self.words:
                self.sf.debug(name + " is found in our word dictionary, skipping.")
                return None

            users.append(name)
            if "." in name:
                # steve.micallef -> smicallef
                users.append(str(name[0] + name.split(".")[1]).lower())

            for user in users:
                if user not in self.reportedUsers:
                    evt = SpiderFootEvent("USERNAME", user, self.__name__, event)
                    self.notifyListeners(evt)
                    self.reportedUsers.append(user)

                res = self.batchSites(user)

                for site in res:
                    evt = SpiderFootEvent("ACCOUNT_EXTERNAL_USER_SHARED", site,
                                          self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_accounts class
