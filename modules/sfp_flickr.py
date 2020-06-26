# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_flickr
# Purpose:     Search Flickr API for domains, URLs and emails related to the
#              specified domain.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-08
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import time
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_flickr(SpiderFootPlugin):
    """Flickr:Footprint,Investigate,Passive:Social Media::Search Flickr for domains, URLs and emails related to the specified domain."""

    # Default options
    opts = {
        'pause': 1,
        'per_page': 100,
        'maxpages': 20,
        'dns_resolve': True,
    }

    # Option descriptions
    optdescs = {
        'pause': "Number of seconds to pause between fetches.",
        'per_page': "Maximum number of results per page.",
        'maxpages': "Maximum number of pages of results to fetch.",
        'dns_resolve': "DNS resolve each identified domain.",
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR", "EMAILADDR_GENERIC", "INTERNET_NAME", 
                "DOMAIN_NAME", "LINKED_URL_INTERNAL"]

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
        params = {
            "sort": "relevance",
            "parse_tags": "1",
            "content_type": "7",
            "extras": "description,owner_name,path_alias,realname",
            "hermes": "1",
            "hermesClient": "1",
            "reqId": "",
            "nojsoncallback": "1",
            "viewerNSID": "",
            "method": "flickr.photos.search",
            "csrf": "",
            "lang": "en-US",
            "per_page": str(per_page),
            "page": str(page),
            "text": qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            "api_key": api_key,
            "format": "json"
        }

        res = self.sf.fetchUrl("https://api.flickr.com/services/rest?" + urllib.parse.urlencode(params),
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        time.sleep(self.opts['pause'])

        try:
            data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug("Error processing JSON response: " + str(e))
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if srcModuleName == 'sfp_flickr':
            self.sf.debug("Ignoring " + eventData + ", from self.")
            return None

        # Retrieve API key
        api_key = self.retrieveApiKey()

        if not api_key:
            self.sf.error("Failed to obtain API key", False)
            return None

        self.sf.debug("Retrieved API key: " + api_key)

        # Query API for event data
        hosts = list()
        page = 1
        pages = self.opts['maxpages']
        per_page = self.opts['per_page']
        while page <= pages:
            if self.checkForStop():
                return None

            if self.errorState:
                return None

            data = self.query(eventData, api_key, page=page, per_page=per_page)

            if data is None:
                return None

            # Check the response is ok
            if data.get('stat') != "ok":
                self.sf.debug("Error retrieving search results.")
                return None

            photos = data.get('photos')

            if not photos:
                return None

            # Calculate number of pages to retrieve
            result_pages = int(photos.get('pages', 0))

            if result_pages < pages:
                pages = result_pages

            if 'max_allowed_pages' in photos:
                allowed_pages = int(photos.get('max_allowed_pages', 0))
                if pages > allowed_pages:
                    pages = allowed_pages

            self.sf.info("Parsing page " + str(page) + " of " + str(pages))

            # Extract data
            for photo in photos.get('photo', list()):
                emails = self.sf.parseEmails(str(photo))
                for email in emails:
                    if email in self.results:
                        continue

                    mail_domain = email.lower().split('@')[1]

                    if not self.getTarget().matches(mail_domain, includeChildren=True, includeParents=True):
                        self.sf.debug("Skipped unrelated address: " + email)
                        continue

                    self.sf.info("Found e-mail address: " + email)
                    if email.split("@")[0] in self.opts['_genericusers'].split(","):
                        evttype = "EMAILADDR_GENERIC"
                    else:
                        evttype = "EMAILADDR"

                    evt = SpiderFootEvent(evttype, email, self.__name__, event)
                    self.notifyListeners(evt)
                    self.results[email] = True

                links = self.sf.extractUrls(str(photo))
                for link in links:
                    if link in self.results:
                        continue

                    host = self.sf.urlFQDN(link)

                    if not self.getTarget().matches(host, includeChildren=True, includeParents=True):
                        self.sf.debug("Skipped unrelated link: " + link)
                        continue

                    hosts.append(host)

                    self.sf.debug("Found a URL: " + link)
                    evt = SpiderFootEvent('LINKED_URL_INTERNAL', link, self.__name__, event)
                    self.notifyListeners(evt)
                    self.results[link] = True

            page += 1

        for host in set(hosts):
            if self.checkForStop():
                return None

            if self.errorState:
                return None

            if self.opts['dns_resolve'] and not self.sf.resolveHost(host):
                self.sf.debug("Host " + host + " could not be resolved")
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, event)
                self.notifyListeners(evt)
                continue

            evt = SpiderFootEvent("INTERNET_NAME", host, self.__name__, event)
            self.notifyListeners(evt)
            if self.sf.isDomain(host, self.opts["_internettlds"]):
                evt = SpiderFootEvent("DOMAIN_NAME", host, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_flickr class
