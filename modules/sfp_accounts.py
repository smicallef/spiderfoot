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
from queue import Queue, Empty as QueueEmpty
import json
import random
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_accounts(SpiderFootPlugin):
    """Account Finder:Footprint,Passive:Social Media:slow:Look for possible associated accounts on nearly 200 websites like Ebay, Slashdot, reddit, etc."""


    # Default options
    opts = {
        "ignorenamedict": True,
        "ignoreworddict": True,
        "musthavename": True,
        "userfromemail": True,
        "_maxthreads": 50
    }

    # Option descriptions
    optdescs = {
        "ignorenamedict": "Don't bother looking up names that are just stand-alone first names (too many false positives).",
        "ignoreworddict": "Don't bother looking up names that appear in the dictionary.",
        "musthavename": "The username must be mentioned on the social media page to consider it valid (helps avoid false positives).",
        "userfromemail": "Extract usernames from e-mail addresses at all? If disabled this can reduce false positives for common usernames but for highly unique usernames it would result in missed accounts."
    }

    results = None
    reportedUsers = list()
    siteResults = dict()
    sites = list()
    errorState = False
    distrustedChecked = False
    lock = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.commonNames = list()
        self.reportedUsers = list()
        self.errorState = False
        self.distrustedChecked = False
        self.__dataSource__ = "Social Media"
        self.lock = threading.Lock()

        for opt in list(userOpts.keys()):
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

        try:
            self.sites = [site for site in json.loads(content)['sites'] if site['valid']]
        except BaseException as e:
            self.sf.error("Unable to parse social media accounts list.", False)
            self.errorState = True
            return None

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["EMAILADDR", "DOMAIN_NAME", "HUMAN_NAME", "USERNAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["USERNAME", "ACCOUNT_EXTERNAL_OWNED"]

    def checkSite(self, name, site):
        if 'check_uri' not in site:
            return None

        url = site['check_uri'].format(account=name)
        retname = site['name'] + " (Category: " + site['category'] + ")\n<SFURL>" + \
                url + "</SFURL>"

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'], noLog=True, verify=False)

        if not res['content']:
            with self.lock:
                self.siteResults[retname] = False
            return

        if res['code']:
            if res['code'].startswith("4") or res['code'].startswith("5"):
                with self.lock:
                    self.siteResults[retname] = False
                return

        # If we see the existence code and string, then consider the
        # site to be found. Otherwise, assume it's not found. Note that
        # the account_missing_code might be the same as the account_existence_code
        # (e.g. 200).
        found = site.get('account_existence_code') == res['code'] \
            and site.get('account_existence_string') in res['content']

        if found and self.opts['musthavename']:
            if name not in res['content']:
                self.sf.debug("Skipping " + site['name'] + " as username not mentioned.")
                found = False

        # Some sites can't handle periods so treat bob.abc and bob as the same
        if found and "." in name:
            firstname = name.split(".")[0]
            if firstname + "<" in res['content'] or firstname + '"' in res['content']:
                found = False

        with self.lock:
            self.siteResults[retname] = found

    def checkSites(self, username, sites=None):
        def processSiteQueue(username, queue):
            try:
                while True:
                    site = queue.get(timeout=0.1)
                    try:
                        self.checkSite(username, site)
                    except Exception as ex:
                        self.sf.debug(f'thread {threading.current_thread().name} exception {ex}')
            except QueueEmpty:
                return

        startTime = time.monotonic()

        # results will be collected in siteResults
        self.siteResults = {}

        sites = self.sites if sites is None else sites

        # load the queue
        queue = Queue()
        for site in sites:
            queue.put(site)

        # start the scan threads
        threads = []
        for i in range(min(len(sites), self.opts['_maxthreads'])):
            thread = threading.Thread(
                name=f'sfp_accounts_scan_{i}',
                target=processSiteQueue,
                args=(username, queue))
            thread.start()
            threads.append(thread)

        # wait for all scan threads to finish
        while threads:
            threads.pop(0).join()

        duration = time.monotonic() - startTime
        scanRate = len(sites) / duration
        self.sf.debug(f'Scan statistics: name={username}, count={len(self.siteResults)}, duration={duration:.2f}, rate={scanRate:.0f}')

        return [site for site, found in self.siteResults.items() if found]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        users = list()

        if self.errorState:
            return None

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        # Skip events coming from me unless they are USERNAME events
        if eventName != "USERNAME" and srcModuleName == "sfp_accounts":
            return None

        if eventData not in list(self.results.keys()):
            self.results[eventData] = True
        else:
            return None

        # If being called for the first time, let's see how trusted the
        # sites are by attempting to fetch a garbage user.
        if not self.distrustedChecked:
            # Check if a state cache exists first, to not have to do this all the time
            content = self.sf.cacheGet("sfaccounts_state_v2", 72)
            if content:
                if content != "None":  # "None" is written to the cached file when no sites are distrusted
                    delsites = list()
                    for line in content.split("\n"):
                        if line == '':
                            continue
                        delsites.append(line)
                    self.sites = [d for d in self.sites if d['name'] not in delsites]
            else:
                randpool = 'abcdefghijklmnopqrstuvwxyz1234567890'
                randuser = ''.join([random.SystemRandom().choice(randpool) for x in range(10)])
                res = self.checkSites(randuser)
                if res:
                    delsites = list()
                    for site in res:
                        sitename = site.split(" (Category:")[0]
                        self.sf.debug("Distrusting " + sitename)
                        delsites.append(sitename)
                    self.sites = [d for d in self.sites if d['name'] not in delsites]
                else:
                    # The caching code needs *some* content
                    delsites = "None"
                self.sf.cachePut("sfaccounts_state_v2", delsites)

            self.distrustedChecked = True

        if eventName == "HUMAN_NAME":
            names = [ eventData.lower().replace(" ", ""), eventData.lower().replace(" ", ".") ]
            for name in names:
                users.append(name)

        if eventName == "DOMAIN_NAME":
            kw = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
            if not kw:
                return None

            users.append(kw)

        if eventName == "EMAILADDR":
            name = eventData.split("@")[0].lower()
            users.append(name)

        if eventName == "USERNAME":
            users.append(eventData)

        for user in users:
            adduser = True
            if user in self.opts['_genericusers'].split(","):
                self.sf.debug(user + " is a generic account name, skipping.")
                continue

            if self.opts['ignorenamedict'] and user in self.commonNames:
                self.sf.debug(user + " is found in our name dictionary, skipping.")
                continue

            if self.opts['ignoreworddict'] and user in self.words:
                self.sf.debug(user + " is found in our word dictionary, skipping.")
                continue

            if user not in self.reportedUsers and eventData != user:
                evt = SpiderFootEvent("USERNAME", user, self.__name__, event)
                self.notifyListeners(evt)
                self.reportedUsers.append(user)

        # Only look up accounts when we've received a USERNAME event (possibly from
        # ourselves), since we want them to have gone through some verification by
        # this module, and we don't want duplicates (one based on EMAILADDR and another
        # based on USERNAME).
        if eventName == "USERNAME":
            res = self.checkSites(user)
            for site in res:
                evt = SpiderFootEvent("ACCOUNT_EXTERNAL_OWNED", site,
                                      self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_accounts class
