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
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_flickr(SpiderFootPlugin):

    meta = {
        'name': "Flickr",
        'summary': "Search Flickr for domains, URLs and emails related to the specified domain.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://www.flickr.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.flickr.com/services/api/",
                "https://www.flickr.com/services/developer/api/",
                "https://code.flickr.net/"
            ],
            'favIcon': "https://combo.staticflickr.com/pw/favicon.ico",
            'logo': "https://combo.staticflickr.com/pw/favicon.ico",
            'description': "Flickr is almost certainly the best online photo management and sharing application in the world.\n "
                           "On Flickr, members upload photos, share them securely, supplement their photos with "
                           "metadata like license information, geo-location, people, tags, etc., "
                           "and interact with their family, friends, contacts or anyone in the community. "
                           "Practically all the features on Flickr's various platforms -- web, mobile and desktop -- "
                           "are accompanied by a longstanding API program. "
                           "Since 2005, developers have collaborated on top of Flickr's APIs to build fun, creative, "
                           "and gorgeous experiences around photos that extend beyond Flickr.",
        }
    }

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

        keys = re.findall(r'YUI_config.flickr.api.site_key = "([a-zA-Z0-9]+)"', str(res['content']))

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
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked")
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if srcModuleName == 'sfp_flickr':
            self.debug(f"Ignoring {eventData}, from self.")
            return

        # Retrieve API key
        api_key = self.retrieveApiKey()

        if not api_key:
            self.error("Failed to obtain API key")
            return

        self.debug(f"Retrieved API key: {api_key}")

        # Query API for event data
        hosts = list()
        page = 1
        pages = self.opts['maxpages']
        per_page = self.opts['per_page']
        while page <= pages:
            if self.checkForStop():
                return

            if self.errorState:
                return

            data = self.query(eventData, api_key, page=page, per_page=per_page)

            if data is None:
                return

            # Check the response is ok
            if data.get('stat') != "ok":
                self.debug("Error retrieving search results.")
                return

            photos = data.get('photos')

            if not photos:
                self.debug("No search results.")
                return

            # Calculate number of pages to retrieve
            result_pages = int(photos.get('pages', 0))

            if result_pages < pages:
                pages = result_pages

            if 'max_allowed_pages' in photos:
                allowed_pages = int(photos.get('max_allowed_pages', 0))
                if pages > allowed_pages:
                    pages = allowed_pages

            self.info(f"Parsing page {page} of {pages}")

            # Extract data
            for photo in photos.get('photo', list()):
                emails = self.sf.parseEmails(str(photo))
                for email in emails:
                    if email in self.results:
                        continue

                    mail_domain = email.lower().split('@')[1]

                    if not self.getTarget().matches(mail_domain, includeChildren=True, includeParents=True):
                        self.debug(f"Skipped unrelated address: {email}")
                        continue

                    self.info("Found e-mail address: " + email)
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
                        self.debug(f"Skipped unrelated URL: {link}")
                        continue

                    hosts.append(host)

                    self.debug(f"Found a URL: {link}")
                    evt = SpiderFootEvent('LINKED_URL_INTERNAL', link, self.__name__, event)
                    self.notifyListeners(evt)
                    self.results[link] = True

            page += 1

        for host in set(hosts):
            if self.checkForStop():
                return

            if self.errorState:
                return

            if self.opts['dns_resolve'] and not self.sf.resolveHost(host) and not self.sf.resolveHost6(host):
                self.debug(f"Host {host} could not be resolved")
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, event)
                self.notifyListeners(evt)
                continue

            evt = SpiderFootEvent("INTERNET_NAME", host, self.__name__, event)
            self.notifyListeners(evt)
            if self.sf.isDomain(host, self.opts["_internettlds"]):
                evt = SpiderFootEvent("DOMAIN_NAME", host, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_flickr class
