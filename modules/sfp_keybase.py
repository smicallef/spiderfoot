# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_keybase
# Purpose:      Spiderfoot plugin to query KeyBase API
#               to gather additional information about username 
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     22/05/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
import json
import re
class sfp_keybase(SpiderFootPlugin):
    """Keybase:Footprint,Investigate,Passive:Public Registries::Obtain additional information about target username"""

    # Tracking results can be helpful to avoid reporting/processing duplicates
    results = None

    # Tracking the error state of the module can be useful to detect when a third party
    # has failed and you don't wish to process any more events.
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["USERNAME", "LINKED_URL_EXTERNAL"]

    def producedEvents(self):
        return ["RAW_RIR_DATA"]

    def queryUsername(self, qry):

        params = {
            'usernames': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
        }

        headers = {
            'Accept' : "application/json",
        }

        res = self.sf.fetchUrl(
          'https://keybase.io/_/api/1.0/user/lookup.json' + urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        # In this case, it will always be 200 if keybase is queried
        # The actual response codes are stored in status tag of the response
        if not res['code'] == '200':
            return None
        
        status = json.loads(res.get('status'))

        code = status.get('code')
        if not code == '0':
            return None

        return res

    # Handle events sent to this module
    def handleEvent(self, event):

        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        self.results[eventData] = True

        userName = eventData

        # Extract username if a Keybase link is received 
        if eventName == "LINKED_URL_EXTERNAL":
            linkRegex = "keybase.io\/[A-Za-z0-9]"  
            link = re.findall(linkRegex, eventData)

            if len(link) == 0:
                self.sf.debug("Not a keybase link")
                return None

            userName = link.split("/")[1] 

        res = self.queryUsername(userName)

        if res is None:
            self.sf.debug("No data found for username")
            return None
        
        evt = SpiderFootEvent("RAW_RIR_DATA", str(res), self.__name__, event)
        self.notifyListeners(evt) 

        if eventName == "LINKED_URL_EXTERNAL":
            evt = SpiderFootEvent("USERNAME", str(userName), self.__name__, event)
            self.notifyListeners(evt)    
    
        data = json.loads(str(res))

        them = json.loads(str(data.get('them')))

        basics = json.loads(str(them.get('basics')))

        profile = json.loads(str(them.get('profile')))

        # Will never occur, failsafe
        if not username == basics.get('username'):
            self.sf.error("Username does not match, skipping", False)
            return None
        
        # Get and report full name of user
        fullName = profile.get('full_name')
        if fullName is not None:
            evt = SpiderFootEvent("HUMAN_NAME", str(fullName), self.__name__, event)
            self.notifyListeners(evt)
        
        # Get and report location of user
        location = profile.get('location')
        if location is not None:
            evt = SpiderFootEvent("GEOINFO", str(location), self.__name__, event)
            self.notifyListeners(evt)
        
        # Extract social media information from JSON response
        socialMediaLinksRegex = ["github.com\/[A-Za-z0-9]", "twitter.com\/[A-Za-z0-9]", 
            "facebook.com\/[A-Za-z0-9]"]
        
        for socialMediaLinkRegex in socialMediaLinksRegex:
            link = re.findall(socialMediaLinkRegex, str(data))

            if len(link) == 0:
                continue

            evt = SpiderFootEvent("SOCIAL_MEDIA", str(link[0]), self.__name__, event)
            self.notifyListeners(evt)
        

       return None
# End of sfp_keybase class
