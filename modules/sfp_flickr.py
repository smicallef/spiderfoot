# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_flickr
# Purpose:      SpiderFoot plug-in for retrieving email addresses belonging
#               to your target from Flickr.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-08
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
try:
    import re2 as re
except ImportError as e:
    import re

import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_flickr(SpiderFootPlugin):
    """Flickr:Footprint,Investigate,Passive:Social Media::Look up e-mail addresses on Flickr."""

    # Default options
    opts = {
        'pause': 1,      # number of seconds to pause between fetches
        'per_page': 200, # max number of results per page
        'maxpages': 20   # max number of pages to fetch
    }

    # Option descriptions
    optdescs = {
        'pause': "Number of seconds to pause between fetches.",                                                                                                                                                    
        'per_page': "Maximum number of results per page.",
        'maxpages': "Maximum number of pages of results to fetch."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['INTERNET_NAME', "DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR"]

    # Retrieve API key
    def retrieveApiKey(self):
        res = self.sf.fetchUrl("https://www.flickr.com/", timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            return None

        keys = re.findall(r'YUI_config.flickr.api.site_key = "([a-zA-Z0-9]+)"', res['content'])

        if not keys:
            return None

        return keys[0]

    # Query the REST API
    def query(self, qry, api_key, page=1, per_page=200):
        output = "json"
        url = "https://api.flickr.com/services/rest?"
        url += "sort=relevance&parse_tags=1&content_type=7&extras=description,owner_name,path_alias,realname&"
        url += "hermes=1&hermesClient=1&reqId=&nojsoncallback=1&viewerNSID=&method=flickr.photos.search&csrf=&lang=en-US&"
        url += "per_page=" + str(per_page) + "&page=" + str(page) + "&text=" + qry + "&api_key=" + api_key + "&format=" + output

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        return res['content']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Retrieve API key
        api_key = self.retrieveApiKey()

        if not api_key:
            self.sf.error("Failed to obtain API key", False)
            return None

        self.sf.debug("Retrieved API key: " + api_key)

        # Get e-mail addresses for this domain
        page = 1
        pages = self.opts['maxpages']
        per_page = self.opts['per_page']
        while page <= pages:
            if self.checkForStop():
                return None

            res = self.query("@"+eventData, api_key, page=page, per_page=per_page)

            if res is None:
                return None

            # Parse response content as JSON
            try:
                data = json.loads(res)
            except Exception as e:
                self.sf.debug("Error processing JSON response.")
                return None

            # Check the response is ok
            if not data['stat'] == "ok":
                self.sf.debug("Error retrieving search results.")
                return None

            if 'photos' not in data:
                return None

            if 'pages' not in data['photos']:
                return None

            # Calculate number of pages to retrieve
            result_pages = int(data['photos']['pages'])

            if result_pages < pages:
                pages = result_pages

            if 'max_allowed_pages' in data['photos']:
                allowed_pages = int(data['photos']['max_allowed_pages'])
                if pages > allowed_pages:
                    pages = allowed_pages

            self.sf.info("Parsing page " + str(page) + " of " + str(pages))

            # Extract emails
            for photo in data['photos']['photo']:
                emails = self.sf.parseEmails(str(photo).decode('unicode-escape'))
                for email in emails:
                    # Skip unrelated emails
                    mailDom = email.lower().split('@')[1]
                    if not self.getTarget().matches(mailDom, includeChildren=True, includeParents=True):
                        self.sf.debug("Skipped address: " + email)
                        continue

                    if email not in self.results:
                        self.sf.info("Found e-mail address: " + email)
                        evt = SpiderFootEvent("EMAILADDR", email, self.__name__, event)
                        self.notifyListeners(evt)
                        self.results[email] = True

            page += 1
            time.sleep(self.opts['pause'])                                                                                                                                                                             

# End of sfp_flickr class
