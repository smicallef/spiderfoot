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

import json
import random
import threading
import time
from queue import Empty as QueueEmpty
from queue import Queue

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_accounts(SpiderFootPlugin):

    meta = {
        'name': "Account Finder",
        'summary': "Look for possible associated accounts on nearly 200 websites like Ebay, Slashdot, reddit, etc.",
        'useCases': ["Footprint", "Passive"],
        'categories': ["Social Media"]
    }

    # Default options
    opts = {
        "ignorenamedict": True,
        "ignoreworddict": True,
        "musthavename": True,
        "userfromemail": True,
        "permutate": False,
        "_maxthreads": 20
    }

    # Option descriptions
    optdescs = {
        "ignorenamedict": "Don't bother looking up names that are just stand-alone first names (too many false positives).",
        "ignoreworddict": "Don't bother looking up names that appear in the dictionary.",
        "musthavename": "The username must be mentioned on the social media page to consider it valid (helps avoid false positives).",
        "userfromemail": "Extract usernames from e-mail addresses at all? If disabled this can reduce false positives for common usernames but for highly unique usernames it would result in missed accounts.",
        "permutate": "Look for the existence of account name permutations. Useful to identify fraudulent social media accounts or account squatting.",
        "_maxthreads": "Maximum threads"
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
                self.error(f"Unable to fetch {url}")
                self.errorState = True
                return

            content = data['content']
            self.sf.cachePut("sfaccounts", content)

        try:
            self.sites = [site for site in json.loads(content)['sites'] if site['valid']]
        except Exception as e:
            self.error(f"Unable to parse social media accounts list: {e}")
            self.errorState = True
            return

    def watchedEvents(self):
        return ["EMAILADDR", "DOMAIN_NAME", "HUMAN_NAME", "USERNAME"]

    def producedEvents(self):
        return ["USERNAME", "ACCOUNT_EXTERNAL_OWNED",
                "SIMILAR_ACCOUNT_EXTERNAL"]

    def checkSite(self, name, site):
        if 'check_uri' not in site:
            return

        url = site['check_uri'].format(account=name)
        if 'pretty_uri' in site:
            ret_url = site['pretty_uri'].format(account=name)
        else:
            ret_url = url
        retname = f"{site['name']} (Category: {site['category']})\n<SFURL>{ret_url}</SFURL>"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
            noLog=True,
            verify=False
        )

        if not res['content']:
            with self.lock:
                self.siteResults[retname] = False
            return

        if res['code'] != site.get('account_existence_code'):
            with self.lock:
                self.siteResults[retname] = False
            return

        if site.get('account_existence_string') not in res['content']:
            with self.lock:
                self.siteResults[retname] = False
            return

        if self.opts['musthavename']:
            if name.lower() not in res['content'].lower():
                self.debug(f"Skipping {site['name']} as username not mentioned.")
                with self.lock:
                    self.siteResults[retname] = False
                return

        # Some sites can't handle periods so treat bob.abc and bob as the same
        # TODO: fix this once WhatsMyName has support for usernames with '.'
        if "." in name:
            firstname = name.split(".")[0]
            if firstname + "<" in res['content'] or firstname + '"' in res['content']:
                with self.lock:
                    self.siteResults[retname] = False
                return

        with self.lock:
            self.siteResults[retname] = True

    def checkSites(self, username, sites=None):
        def processSiteQueue(username, queue):
            try:
                while True:
                    site = queue.get(timeout=0.1)
                    try:
                        self.checkSite(username, site)
                    except Exception as e:
                        self.debug(f'Thread {threading.current_thread().name} exception: {e}')
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
        self.debug(f'Scan statistics: name={username}, count={len(self.siteResults)}, duration={duration:.2f}, rate={scanRate:.0f}')

        return [site for site, found in self.siteResults.items() if found]

    def generatePermutations(self, username):
        permutations = list()
        prefixsuffix = ['_', '-']
        replacements = {
            'a': ['4', 's'],
            'b': ['v', 'n'],
            'c': ['x', 'v'],
            'd': ['s', 'f'],
            'e': ['w', 'r'],
            'f': ['d', 'g'],
            'g': ['f', 'h'],
            'h': ['g', 'j', 'n'],
            'i': ['o', 'u', '1'],
            'j': ['k', 'h', 'i'],
            'k': ['l', 'j'],
            'l': ['i', '1', 'k'],
            'm': ['n'],
            'n': ['m'],
            'o': ['p', 'i', '0'],
            'p': ['o', 'q'],
            'r': ['t', 'e'],
            's': ['a', 'd', '5'],
            't': ['7', 'y', 'z', 'r'],
            'u': ['v', 'i', 'y', 'z'],
            'v': ['u', 'c', 'b'],
            'w': ['v', 'vv', 'q', 'e'],
            'x': ['z', 'y', 'c'],
            'y': ['z', 'x'],
            'z': ['y', 'x'],
            '0': ['o'],
            '1': ['l'],
            '2': ['5'],
            '3': ['e'],
            '4': ['a'],
            '5': ['s'],
            '6': ['b'],
            '7': ['t'],
            '8': ['b'],
            '9': []
        }
        pairs = {
            'oo': ['00'],
            'll': ['l1l', 'l1l', '111', '11'],
            '11': ['ll', 'lll', 'l1l', '1l1']
        }

        # Generate a set with replacements, then
        # add suffixes and prefixes.
        pos = 0
        for c in username:
            if c not in replacements:
                continue
            if len(replacements[c]) == 0:
                continue
            npos = pos + 1
            for xc in replacements[c]:
                newuser = username[0:pos] + xc + username[npos:len(username)]
                permutations.append(newuser)

            pos += 1

        # Search for common double-letter replacements
        for p in pairs:
            if p in username:
                for r in pairs[p]:
                    permutations.append(username.replace(p, r))

        # Search for prefixed and suffixed usernames
        for c in prefixsuffix:
            permutations.append(username + c)
            permutations.append(c + username)

        # Search for double character usernames
        pos = 0
        for c in username:
            permutations.append(username[0:pos] + c + c + username[(pos + 1):len(username)])
            pos += 1

        return list(set(permutations))

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        users = list()

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Skip events coming from me unless they are USERNAME events
        if eventName != "USERNAME" and srcModuleName == "sfp_accounts":
            self.debug(f"Ignoring {eventName}, from self.")
            return

        if eventData in list(self.results.keys()):
            return

        self.results[eventData] = True

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
                        self.debug(f"Distrusting {sitename}")
                        delsites.append(sitename)
                    self.sites = [d for d in self.sites if d['name'] not in delsites]
                else:
                    # The caching code needs *some* content
                    delsites = "None"
                self.sf.cachePut("sfaccounts_state_v2", delsites)

            self.distrustedChecked = True

        if eventName == "HUMAN_NAME":
            names = [eventData.lower().replace(" ", ""), eventData.lower().replace(" ", ".")]
            for name in names:
                users.append(name)

        if eventName == "DOMAIN_NAME":
            kw = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
            if not kw:
                return

            users.append(kw)

        if eventName == "EMAILADDR" and self.opts['userfromemail']:
            name = eventData.split("@")[0].lower()
            users.append(name)

        if eventName == "USERNAME":
            users.append(eventData)

        for user in set(users):
            if user in self.opts['_genericusers'].split(","):
                self.debug(f"{user} is a generic account name, skipping.")
                continue

            if self.opts['ignorenamedict'] and user in self.commonNames:
                self.debug(f"{user} is found in our name dictionary, skipping.")
                continue

            if self.opts['ignoreworddict'] and user in self.words:
                self.debug(f"{user} is found in our word dictionary, skipping.")
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
                evt = SpiderFootEvent(
                    "ACCOUNT_EXTERNAL_OWNED",
                    site,
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)

            if self.opts['permutate']:
                permutations = self.generatePermutations(user)
                for puser in permutations:
                    res = self.checkSites(puser)
                    for site in res:
                        evt = SpiderFootEvent(
                            "SIMILAR_ACCOUNT_EXTERNAL",
                            site,
                            self.__name__,
                            event
                        )
                        self.notifyListeners(evt)
# End of sfp_accounts class
