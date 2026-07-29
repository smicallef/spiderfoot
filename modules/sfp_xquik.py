# -------------------------------------------------------------------------------
# Name:         sfp_xquik
# Purpose:      Query Xquik for X/Twitter profile information.
#
# Author:       SpiderFoot contributors
#
# Created:      2026-06-13
# Copyright:    (c) SpiderFoot contributors 2026
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_xquik(SpiderFootPlugin):

    meta = {
        'name': "Xquik",
        'summary': "Gather X/Twitter user profile details from Xquik.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://xquik.com/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://docs.xquik.com/api-reference/x/twitter-profile-lookup"
            ],
            'apiKeyInstructions': [
                "Visit https://xquik.com/",
                "Create or sign in to your account",
                "Add credits or activate a subscription",
                "Create an API key from the dashboard"
            ],
            'favIcon': "https://xquik.com/icon.svg",
            'logo': "https://xquik.com/icon.svg",
            'description': "Xquik provides X data APIs for profile lookup, search, monitoring, and automation. "
            "Xquik is an independent third-party service. Not affiliated with X Corp. "
            "\"Twitter\" and \"X\" are trademarks of X Corp.",
        }
    }

    opts = {
        'api_key': '',
    }

    optdescs = {
        'api_key': "Xquik API key.",
    }

    handle_re = re.compile(r"^[A-Za-z0-9_]{1,15}$")
    reserved_paths = {
        "about",
        "compose",
        "download",
        "explore",
        "hashtag",
        "home",
        "i",
        "intent",
        "jobs",
        "login",
        "logout",
        "messages",
        "notifications",
        "privacy",
        "search",
        "settings",
        "share",
        "signup",
        "tos",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "Xquik"
        self.opts = dict(type(self).opts)
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["SOCIAL_MEDIA"]

    def producedEvents(self):
        return ["RAW_RIR_DATA", "USERNAME", "GEOINFO"]

    def extractHandle(self, eventData):
        if not isinstance(eventData, str):
            return None

        try:
            network, value = eventData.split(": ", 1)
        except ValueError:
            return None

        if network.lower() not in ["twitter", "x"]:
            return None

        url = value.replace("<SFURL>", "").replace("</SFURL>", "").strip()

        try:
            parsed = urllib.parse.urlparse(url)
        except ValueError:
            return None

        if parsed.scheme not in ["http", "https"]:
            return None

        if parsed.netloc.lower() not in ["twitter.com", "www.twitter.com", "x.com", "www.x.com"]:
            return None

        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 1:
            return None

        handle = parts[0]
        if not self.handle_re.fullmatch(handle):
            return None

        if handle.lower() in self.reserved_paths:
            return None

        return handle

    def query(self, handle):
        headers = {
            'Accept': "application/json",
            'x-api-key': self.opts['api_key'],
        }
        encoded_handle = urllib.parse.quote(handle, safe="")

        return self.sf.fetchUrl(
            f"https://xquik.com/api/v1/x/users/{encoded_handle}",
            timeout=self.sf.opts['_fetchtimeout'],
            useragent=self.sf.opts['_useragent'],
            headers=headers
        )

    def handleEvent(self, event):
        if self.errorState:
            return

        handle = self.extractHandle(event.data)
        if handle is None:
            return

        lookup_key = handle.lower()
        if lookup_key in self.results:
            return

        self.results[lookup_key] = True

        if not self.opts['api_key']:
            self.error("Xquik API key missing. Configure the module first.")
            self.errorState = True
            return

        res = self.query(handle)
        if not res or res.get('content') is None:
            return

        code = str(res.get('code'))
        if code == '401':
            self.error("Xquik authentication failed. Check the API key.")
            self.errorState = True
            return

        if code == '402':
            self.error("Xquik subscription or credits required. Check billing first.")
            self.errorState = True
            return

        if code == '403':
            self.error("Xquik access denied. Check the API key permissions.")
            self.errorState = True
            return

        if code == '429':
            self.error("Xquik rate limit reached. Retry later.")
            self.errorState = True
            return

        if code != '200':
            self.debug(f"Xquik API request failed with HTTP {code}.")
            return

        try:
            data = json.loads(res['content'])
        except (TypeError, ValueError) as e:
            self.debug(f"Error processing JSON response from Xquik: {e}")
            return

        if not isinstance(data, dict):
            self.debug("Unexpected JSON response from Xquik.")
            return

        username = data.get('username')
        if not isinstance(username, str):
            return

        if not self.handle_re.fullmatch(username):
            return

        if username.lower() != lookup_key:
            self.debug(f"Xquik returned a different username for {handle}.")
            return

        evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data, sort_keys=True), self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent("USERNAME", username, self.__name__, event)
        self.notifyListeners(evt)

        location = data.get('location')
        if not isinstance(location, str):
            return

        location = location.strip()
        if len(location) < 3 or len(location) > 100:
            self.debug("Skipping likely invalid location.")
            return

        evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_xquik class
