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
import urllib.request, urllib.parse, urllib.error
import json
import re
class sfp_keybase(SpiderFootPlugin):
    """Keybase:Footprint,Investigate,Passive:Public Registries::Obtain additional information about target username"""

    opts = {
    }

    optdescs = {
    }

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
        return ["RAW_RIR_DATA", "SOCIAL_MEDIA", "USERNAME",
            "HUMAN_NAME", "GEOINFO", "BITCOIN_ADDRESS", 
            "PGP_KEY"]

    def queryUsername(self, qry):

        params = {
            'usernames': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
        }

        headers = {
            'Accept' : "application/json",
        }

        res = self.sf.fetchUrl(
          'https://keybase.io/_/api/1.0/user/lookup.json?' + urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        # In this case, it will always be 200 if keybase is queried 
        # The actual response codes are stored in status tag of the response
        if not res['code'] == '200':
            return None
        
        # Replacing null with "None"
        content = json.loads(str(res['content']).replace(":null", ":\"None\""))

        status = content.get('status')
        if status is None:
            return None

        code = status.get('code')
        if code is None:
            return None
        
        try:
            if not int(code) == 0:
                return None
        except:
            self.sf.error("Invalid code returned as response", False)
            return None

        return content

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
            linkRegex = "keybase.io\/[A-Za-z0-9-_.]+"  
            link = re.findall(linkRegex, eventData)

            if len(link) == 0:
                self.sf.debug("Not a keybase link")
                return None

            userName = link.split("/")[1]

            if userName in self.results:
                return None
            self.results[userName] = True

        content = self.queryUsername(userName)

        if content is None:
            self.sf.debug("No data found for username")
            return None
        
        evt = SpiderFootEvent("RAW_RIR_DATA", str(content), self.__name__, event)
        self.notifyListeners(evt) 

        if eventName == "LINKED_URL_EXTERNAL":
            evt = SpiderFootEvent("USERNAME", str(userName), self.__name__, event)
            self.notifyListeners(evt)    
    
        
        # Replacing string values that are not enclosed within double quotes
        # Also replacing values like True and False to their corresponding numeric values
        # If the above steps aren't performed, json.loads() fails
        
        # Checking with == "None" in addition to is None, because null values are replaced with "None"

        # Contains all data about the target username
        try:
            them = json.loads(str(content.get('them')[0]).replace("'", "\"").replace("True", "1").replace("False", "0"))
        except:
            them = None

        if them is None or them == "None":
            self.sf.debug("No data found for username")
            return None

        # Basic information about the username
        try:
            basics = json.loads(str(them.get('basics')).replace("'", "\""))
        except:
            basics = None

        # Profile information about the username
        try:
            profile = json.loads(str(them.get('profile')).replace("'", "\""))
        except:
            profile = None

        # Failsafe to prevent reporting any wrongly received data
        if basics:
            responseUserName = basics.get('username')
            if not userName == responseUserName:
                self.sf.error("Username does not match received response, skipping", False)
                return None
        
        if profile:
            # Get and report full name of user
            fullName = profile.get('full_name')
            if not (fullName is None or fullName == "None"):
                evt = SpiderFootEvent("HUMAN_NAME", str(fullName), self.__name__, event)
                self.notifyListeners(evt)
            
            # Get and report location of user
            location = profile.get('location')
            if not (location is None or location == "None"):
                evt = SpiderFootEvent("GEOINFO", str(location), self.__name__, event)
                self.notifyListeners(evt)
            
            # Extract social media information from JSON response           
            socialMediaRegexDict = {
                "Github": "https:\/\/github.com\/[A-Za-z0-9-_.]+",
                "Twitter": "https:\/\/twitter.com\/[A-Za-z0-9-_.]+",
                "Facebook": "https:\/\/facebook.com\/[A-Za-z0-9-_.]+"
            }

            for socialMediaName, socialMediaLinkRegex in socialMediaRegexDict.items():
                links = re.findall(socialMediaLinkRegex, str(content))
                
                if len(links) == 0:
                    continue
                
                for link in links:

                    if link in self.results:
                        continue
                    self.results[link] = True
                    
                    socialMedia = socialMediaName + ": " + "<SFURL>" + link + "</SFURL>"

                    evt = SpiderFootEvent("SOCIAL_MEDIA", str(socialMedia), self.__name__, event)
                    self.notifyListeners(evt)

        # Get cryptocurrency addresses 
        cryptoAddresses = json.loads(str(them.get('cryptocurrency_addresses')).replace("'", "\""))
        
        # Extract and report bitcoin addresses if any
        if cryptoAddresses:
            bitcoinAddresses = json.loads(str(cryptoAddresses.get('bitcoin')).replace("'", "\""))
            if bitcoinAddresses:
                for bitcoinAddress in bitcoinAddresses:
                    btcAddress = bitcoinAddress.get('address')
                    if btcAddress is None:
                        continue
                    evt = SpiderFootEvent("BITCOIN_ADDRESS", str(btcAddress), self.__name__, event)
                    self.notifyListeners(evt)
        
        # Extract PGP Keys
        pgpRegex = "-----BEGIN\s*PGP\s*(?:PUBLIC?)\s*KEY\s*BLOCK-----(.*?)-----END\s*PGP\s*(?:PUBLIC?)\s*KEY\s*BLOCK-----"

        pgpKeys = re.findall(pgpRegex, str(content))
        
        for pgpKey in pgpKeys:

            if len(pgpKey) < 300:
                self.sf.debug("Likely invalid public key.")
                continue
            
            pgpKey = pgpKey.replace("\\n", "")

            evt = SpiderFootEvent("PGP_KEY", pgpKey, self.__name__, event)
            self.notifyListeners(evt)

        return None

# End of sfp_keybase class
