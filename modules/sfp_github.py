# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_github
# Purpose:      Identifies public code repositories in Github associated with 
#               your target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     21/07/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_github(SpiderFootPlugin):
    """Github:Footprint,Passive:Social Media::Identify associated public code repositories on Github."""


    # Default options
    opts = {
        'namesonly':    True
    }

    # Option descriptions
    optdescs = {
        'namesonly':    "Match repositories by name only, not by their descriptions. Helps reduce false positives."
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "USERNAME", "SOCIAL_MEDIA"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["RAW_RIR_DATA", "GEOINFO", "PUBLIC_CODE_REPO"]

    # Build up repo info for use as an event
    def buildRepoInfo(self, item):
        repo_info = None

        # Get repos matching the name
        if item.get('name') == None:
            self.sf.debug("Incomplete Github information found (name).")
            return None
        if item.get('html_url') == None:
            self.sf.debug("Incomplete Github information found (url).")
            return None
        if item.get('description') == None:
            self.sf.debug("Incomplete Github information found (description).")
            return None

        repo_info = "Name: " + item['name'] + "\n" + "URL: " + item['html_url'] + \
                    "\n" + "Description: " + item['description']

        return repo_info


    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            self.sf.debug("Already did a search for " + eventData + ", skipping.")
            return None
        else:
            self.results[eventData] = True

        # Extract name and location from profile
        if eventName == "SOCIAL_MEDIA":
            try:
                network = eventData.split(": ")[0]
                url = eventData.split(": ")[1]
            except BaseException as e:
                self.sf.error("Unable to parse SOCIAL_MEDIA: " +
                              eventData + " (" + str(e) + ")", False)
                return None

            if not network == "Github":
                self.sf.debug("Skipping social network profile, " + url + ", as not a Github profile")
                return None

            try:
                bits = url.split("/")
                name = bits[len(bits)-1]
            except BaseException as e:
                self.sf.debug("Couldn't get a username out of " + url)
                return None

            res = self.sf.fetchUrl("https://api.github.com/users/" + name, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

            if res['content'] is None:
                return None

            try:
                json_data = json.loads(res['content'])
            except BaseException as e:
                self.sf.debug("Error processing JSON response.")
                return None

            if not json_data.get('login'):
                self.sf.debug(name + " is not a valid Github profile")
                return None

            if not json_data.get('name'):
                self.sf.debug(name + " is not a valid Github profile")
                return None

            e = SpiderFootEvent("RAW_RIR_DATA", "Possible full name: " + json_data['name'], self.__name__, event)
            self.notifyListeners(e)

            location = json_data.get('location')

            if location is None:
                return None

            if len(location) < 3 or len(location) > 100:
                self.sf.debug("Skipping likely invalid location: " + location)
                return None

            e = SpiderFootEvent("GEOINFO", location, self.__name__, event)
            self.notifyListeners(e)

            return None

        if eventName == "DOMAIN_NAME":
            name = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
        if eventName == "USERNAME":
            name = eventData

        self.sf.debug("Looking at " + name)
        failed = False
        # Get all the repositories based on direct matches with the 
        # name identified
        url = "https://api.github.com/search/repositories?q=" + name
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        if res['content'] == None:
            self.sf.error("Unable to fetch " + url, False)
            failed = True

        try:
            ret = json.loads(res['content'])
        except BaseException as e:
            ret = None

        if ret == None:
            self.sf.error("Unable to process empty response from Github for: " + \
                          name, False)
            failed = True

        if not failed:
            if ret.get('total_count', "0") == "0" or len(ret['items']) == 0:
                self.sf.debug("No Github information for " + name)
                failed = True

        if not failed:
            for item in ret['items']:
                repo_info = self.buildRepoInfo(item)
                if repo_info != None:
                    if self.opts['namesonly'] and name not in item['name']:
                        continue

                    evt = SpiderFootEvent("PUBLIC_CODE_REPO", repo_info, 
                                          self.__name__, event)
                    self.notifyListeners(evt)

        # Now look for users matching the name found
        failed = False
        url = "https://api.github.com/search/users?q=" + name
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        if res['content'] == None:
            self.sf.error("Unable to fetch " + url, False)
            failed = True

        if not failed:
            try:
                ret = json.loads(res['content'])
                if ret == None:
                    self.sf.error("Unable to process empty response from Github for: " + \
                                  name, False)
                    failed = True
            except BaseException as e:
                self.sf.error("Unable to process invalid response from Github for: " + \
                              name, False)
                failed = True

        if not failed:
            if ret.get('total_count', "0") == "0" or len(ret['items']) == 0:
                self.sf.debug("No Github information for " + name)
                failed = True

        if not failed:
            # For each user matching the name, get their repos
            for item in ret['items']:
                if item.get('repos_url') == None:
                    self.sf.debug("Incomplete Github information found (repos_url).")
                    continue

                url = item['repos_url']
                res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
	                               useragent=self.opts['_useragent'])
    
    	        if res['content'] == None:
                    self.sf.error("Unable to fetch " + url, False)
                    continue

                try:
                    repret = json.loads(res['content'])
                except BaseException as e:
                    self.sf.error("Invalid JSON returned from Github.", False)
                    continue

                if repret == None:
                    self.sf.error("Unable to process empty response from Github for: " + \
                                  name, False)
                    continue

                for item in repret:
                    if type(item) != dict:
                        self.sf.debug("Encountered an unexpected or empty response from Github.")
                        continue 

                    repo_info = self.buildRepoInfo(item)
                    if repo_info != None:
                        if self.opts['namesonly'] and name not in item['name']:
                            continue

                        evt = SpiderFootEvent("PUBLIC_CODE_REPO", repo_info, 
                                              self.__name__, event)
                        self.notifyListeners(evt)


# End of sfp_github class
