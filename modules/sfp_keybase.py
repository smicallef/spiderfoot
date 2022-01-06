# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_keybase
# Purpose:     Spiderfoot plugin to query KeyBase API
#              to gather additional information about domain names and identified
#              usernames.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     22/05/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_keybase(SpiderFootPlugin):

    meta = {
        'name': "Keybase",
        'summary': "Obtain additional information about domain names and identified usernames.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://keybase.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://keybase.io/docs/api/1.0/call/user/lookup",
            ],
            'favIcon': "https://keybase.io/images/icons/icon-keybase-logo-48.png",
            'logo': "https://keybase.io/images/icons/icon-keybase-logo-48.png",
            'description': "Keybase is a key directory that maps social media identities to encryption keys "
            "in a publicly auditable manner.",
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["USERNAME", "LINKED_URL_EXTERNAL", "DOMAIN_NAME"]

    def producedEvents(self):
        return [
            "RAW_RIR_DATA", "SOCIAL_MEDIA", "USERNAME",
            "GEOINFO", "BITCOIN_ADDRESS", "PGP_KEY"
        ]

    def query(self, selector: str, qry: str) -> str:
        """Search Keybase for a domain name or username.

        Args:
            selector (str): query type ("usernames" | "domain")
            qry (str): username

        Returns:
            str: Search results as JSON string
        """
        if not selector:
            return None

        if not qry:
            return None

        params = {
            selector: qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }

        headers = {
            'Accept': "application/json"
        }

        res = self.sf.fetchUrl(
            'https://keybase.io/_/api/1.0/user/lookup.json?' + urllib.parse.urlencode(params),
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        # In this case, it will always be 200 if keybase is queried
        # The actual response codes are stored in status tag of the response
        if res['code'] != '200':
            self.error(f"Unexpected reply from Keybase: {res['code']}")
            return None

        try:
            content = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        status = content.get('status')
        if not status:
            return None

        code = status.get('code')

        if code != 0:
            self.error(f"Unexpected JSON response code reply from Keybase: {code}")
            return None

        them = content.get('them')
        if not isinstance(them, list):
            return None

        return them

    def handleEvent(self, event) -> None:
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Extract username if a Keybase link is received
        if eventName == "LINKED_URL_EXTERNAL":
            linkRegex = r"^https?://keybase.io\/[A-Za-z0-9\-_\.]+"
            links = re.findall(linkRegex, eventData)

            if len(links) == 0:
                self.debug(f"Skipping URL {eventData}, as not a keybase link")
                return

            userName = links[0].split("/")[3]

            data = self.query('usernames', userName)
        elif eventName == "USERNAME":
            data = self.query('usernames', eventData)
        elif eventName == "DOMAIN_NAME":
            data = self.query('domain', eventData)
        else:
            return

        if not data:
            self.debug(f"No data found for {eventName}: {eventData}")
            return

        for user in data:
            if not user:
                continue

            # Basic information about the username
            basics = user.get('basics')
            if not basics:
                continue

            username = basics.get('username')
            if not username:
                continue

            # Failsafe to prevent reporting any wrongly received data
            if eventName == "USERNAME":
                if eventData.lower() != username.lower():
                    self.error("Username does not match received response, skipping")
                    continue

            # For newly discovereed usernames, create a username event to be used as a source event
            if eventName in ['LINKED_URL_EXTERNAL', 'DOMAIN_NAME']:
                if username in self.results:
                    self.debug(f"Skipping {userName}, already checked.")
                    continue

                source_event = SpiderFootEvent("USERNAME", username, self.__name__, event)
                self.notifyListeners(source_event)
                self.results[username] = True
            else:
                source_event = event

            evt = SpiderFootEvent("RAW_RIR_DATA", str(user), self.__name__, source_event)
            self.notifyListeners(evt)

            # Profile information about the username
            profile = user.get('profile')
            if profile:
                # Get and report full name of user
                fullName = profile.get('full_name')
                if fullName:
                    evt = SpiderFootEvent("RAW_RIR_DATA", f"Possible full name: {fullName}", self.__name__, source_event)
                    self.notifyListeners(evt)

                # Get and report location of user
                location = profile.get('location')
                if location:
                    evt = SpiderFootEvent("GEOINFO", location, self.__name__, source_event)
                    self.notifyListeners(evt)

            # Extract social media information
            proofsSummary = user.get('proofs_summary')

            if proofsSummary:
                socialMediaData = proofsSummary.get('all')

                if socialMediaData:
                    for socialMedia in socialMediaData:
                        socialMediaSite = socialMedia.get('proof_type')
                        socialMediaURL = socialMedia.get('service_url')

                        if socialMediaSite and socialMediaURL:
                            socialMedia = socialMediaSite + ": " + "<SFURL>" + socialMediaURL + "</SFURL>"
                            evt = SpiderFootEvent("SOCIAL_MEDIA", socialMedia, self.__name__, source_event)
                            self.notifyListeners(evt)

            # Get cryptocurrency addresses
            cryptoAddresses = user.get('cryptocurrency_addresses')

            # Extract and report bitcoin addresses if any
            if cryptoAddresses:
                bitcoinAddresses = cryptoAddresses.get('bitcoin')

                if bitcoinAddresses:
                    for bitcoinAddress in bitcoinAddresses:
                        btcAddress = bitcoinAddress.get('address')

                        if not btcAddress:
                            continue

                        evt = SpiderFootEvent("BITCOIN_ADDRESS", btcAddress, self.__name__, source_event)
                        self.notifyListeners(evt)

            # Extract PGP Keys
            pgpRegex = r"-----BEGIN\s*PGP\s*(?:PUBLIC?)\s*KEY\s*BLOCK-----(.*?)-----END\s*PGP\s*(?:PUBLIC?)\s*KEY\s*BLOCK-----"

            pgpKeys = re.findall(pgpRegex, str(user))

            for pgpKey in pgpKeys:
                if len(pgpKey) < 300:
                    self.debug(f"PGP key size ({len(pgpKey)} bytes) is likely invalid (smaller than 300 bytes), skipping.")
                    continue

                # Remove unescaped \n literals
                pgpKey = pgpKey.replace("\\n", "\n")

                # Avoid reporting of duplicate keys
                pgpKeyHash = self.sf.hashstring(pgpKey)

                if pgpKeyHash in self.results:
                    continue

                self.results[pgpKeyHash] = True

                evt = SpiderFootEvent("PGP_KEY", pgpKey, self.__name__, source_event)
                self.notifyListeners(evt)

# End of sfp_keybase class
