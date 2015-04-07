# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_accounts`
# Purpose:      Identify the existence of a given acount on various sites.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     18/02/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

externals = [
    "YouTube", "Wikipedia", "LinkedIn", "Twitter", "Ebay", "Tumblr", "Pinterest", "Blogger", "Flickr",
    "DailyMotion", "reddit", "Cnet", "vimeo", "SlideShare", "ThemeForest", "DeviantArt", "LiveJournal", "Yelp",
    "StumbleUpon", "askfm", "Sourceforge", "WikiHow", "soundcloud", "Photobucket", "weebly", "scribd", "ImageShack",
    "Disqus", "Tagged", "Elance", "Typepad", "foursquare", "steam", "MySpace", "Gawker", "Gamespot",
    "MetaCafe", "LastFM", "hi5", "myfitnesspal", "Delicious", "Dribbble", "Gravatar", "Crunchbase", "FriendFeed",
    "Technorati", "Slashdot", "Metacritic", "uservoice", "BitLy"
]


class sfp_accounts(SpiderFootPlugin):
    """Accounts:Look for possible associated accounts on over 50 websites like Ebay, Slashdot, reddit, etc."""

    # Default options
    opts = {
        "generic": ["root", "abuse", "sysadm", "sysadmin", "noc", "support", "admin",
                    "contact", "help", "flame", "test", "info", "sales", "hostmaster"],
        "ignoredict": True
    }

    # Option descriptions
    optdescs = {
        "generic": "Generic internal accounts to not bother looking up externally.",
        "ignoredict": "Don't bother looking up internal names externally that are just stand-alone first names."
    }

    results = {}

    def setup(self, sfc, userOpts={}):
        self.sf = sfc
        self.results = {}
        self.commonnames = []

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

            names = open(self.sf.myPath() + "/ext/ispell/names.list", 'r')
            lines = names.readlines()
            for item in lines:
                self.commonnames.append(item.strip())
            names.close()

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["EMAILADDR", "DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["ACCOUNT_EXTERNAL_OWNED", "ACCOUNT_EXTERNAL_USER_SHARED"]

    def checkSites(self, name):
        global externals
        ret = []

        for site in externals:
            if self.checkForStop():
                return None

            url = "http://checkusernames.com/usercheckv2.php?target=" + site + \
                  "&username=" + name + "&time=" + str(int(time.time()) * 100) + "1"
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'],
                                   headers={"X-Requested-With": "XMLHttpRequest",
                                            "Referer": "http://www.checkusernames.com/"}
                                   )

            if res['content'] is None:
                self.sf.debug("Unable to check the status of account " + name + " on " + site)
            else:
                if "Sorry," in res['content']:
                    ret.append(site)

        return ret

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        users = []

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData not in self.results.keys():
            self.results[eventData] = True
        else:
            return None

        if eventName == "DOMAIN_NAME":
            kw = self.sf.domainKeyword(eventData, self.opts['_internettlds'])

            sites = self.checkSites(kw)
            if sites is None:
                return None

            for site in sites:
                evt = SpiderFootEvent("ACCOUNT_EXTERNAL_OWNED", kw + " (" + site + ")",
                                      self.__name__, event)
                self.notifyListeners(evt)
            return None

        if eventName == "EMAILADDR":
            name = eventData.split("@")[0]
            if self.opts['generic'] is list() and name in self.opts['generic']:
                self.sf.debug(name + " is a generic account name, skipping.")
                return None

            if self.opts['ignoredict'] and name in self.commonnames:
                self.sf.debug(name + " is found in our name dictionary, skipping.")
                return None

            users.append(name)
            if "." in name:
                # steve.micallef -> smicallef
                users.append(name[0] + name.split(".")[1])

            for user in users:
                sites = self.checkSites(user)
                if sites is None:
                    return None

                for site in sites:
                    evt = SpiderFootEvent("ACCOUNT_EXTERNAL_USER_SHARED", user + " (" + site + ")",
                                          self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_accounts class
