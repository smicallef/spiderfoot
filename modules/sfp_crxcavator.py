# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_crxcavator
# Purpose:     Query CRXcavator for Chrome extensions.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2020-09-19
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_crxcavator(SpiderFootPlugin):

    meta = {
        'name': "CRXcavator",
        'summary': "Search CRXcavator for Chrome extensions.",
        'flags': [],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://crxcavator.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'favIcon': "https://crxcavator.io/favicon-32x32.png",
            'logo': "https://crxcavator.io/apple-touch-icon.png",
            'description': "CRXcavator automatically scans the entire Chrome Web "
                "Store every 3 hours and produces a quantified risk score for "
                "each Chrome Extension based on several factors.",
        }
    }

    opts = {
        "verify": True,
    }

    optdescs = {
        "verify": "Verify identified hostnames resolve.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'DOMAIN_NAME'
        ]

    def producedEvents(self):
        return [
            'APPSTORE_ENTRY',
            'INTERNET_NAME',
            'INTERNET_NAME_UNRESOLVED',
            'LINKED_URL_INTERNAL',
            'AFFILIATE_INTERNET_NAME',
            'AFFILIATE_INTERNET_NAME_UNRESOLVED',
            'PHYSICAL_ADDRESS'
        ]

    def query(self, qry):
        params = urllib.parse.urlencode({
            'q': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        })

        res = self.sf.fetchUrl(
            f"https://api.crxcavator.io/v1/search?{params}",
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout']
        )

        time.sleep(1)

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from CRXcavator: {e}")
            return None

        if not data:
            self.debug(f"No results found for {qry}")
            return None

        return data

    def queryExtension(self, extension_id):
        res = self.sf.fetchUrl(
            f"https://api.crxcavator.io/v1/report/{extension_id}",
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout']
        )

        time.sleep(1)

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from CRXcavator: {e}")
            return None

        if not data:
            self.debug(f"No results found for extension {extension_id}")
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if eventName not in self.watchedEvents():
            return

        self.results[eventData] = True

        domain_keyword = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
        results = self.query(domain_keyword)

        if not results:
            self.info(f"No results found for {domain_keyword}")
            return

        evt = SpiderFootEvent('RAW_RIR_DATA', json.dumps(results), self.__name__, event)
        self.notifyListeners(evt)

        urls = list()
        hosts = list()
        locations = list()

        for result in results:
            if not isinstance(result, dict):
                continue

            extension_id = result.get('extension_id')

            if not extension_id:
                continue

            if '@' in extension_id:
                continue

            extensions = self.queryExtension(extension_id)

            if not extensions:
                continue

            evt = SpiderFootEvent('RAW_RIR_DATA', json.dumps(extensions), self.__name__, event)
            self.notifyListeners(evt)

            for extension in extensions:
                data = extension.get('data')

                if not data:
                    continue

                manifest = data.get('manifest')

                if not manifest:
                    continue

                version = manifest.get('version')

                if not version:
                    continue

                webstore = data.get('webstore')

                if not webstore:
                    continue

                name = webstore.get('name')

                if not name:
                    continue

                app_full_name = f"{name} {version} ({extension_id})"

                privacy_policy = webstore.get('privacy_policy')
                support_site = webstore.get('support_site')
                offered_by = webstore.get('offered_by')
                website = webstore.get('website')

                if not privacy_policy and not support_site and not offered_by and not website:
                    continue

                if (
                    not self.getTarget().matches(self.sf.urlFQDN(privacy_policy), includeChildren=True, includeParents=True)
                    and not self.getTarget().matches(self.sf.urlFQDN(website), includeChildren=True, includeParents=True)
                    and not self.getTarget().matches(self.sf.urlFQDN(offered_by), includeChildren=True, includeParents=True)
                    and not self.getTarget().matches(self.sf.urlFQDN(support_site), includeChildren=True, includeParents=True)
                ):
                    self.debug(f"Extension {app_full_name} does not match {eventData}, skipping")
                    continue

                app_data = f"{name} {version}\n<SFURL>https://chrome.google.com/webstore/detail/{extension_id}</SFURL>"

                evt = SpiderFootEvent('APPSTORE_ENTRY', app_data, self.__name__, event)
                self.notifyListeners(evt)

                if privacy_policy:
                    urls.append(privacy_policy)

                if support_site:
                    urls.append(support_site)

                if website:
                    urls.append(website)

                if offered_by:
                    urls.append(offered_by)

                address = webstore.get('address')

                if address and len(address) > 10:
                    locations.append(address)

        for url in set(urls):
            if not url:
                continue

            host = self.sf.urlFQDN(url)

            if not host:
                continue

            if self.getTarget().matches(host, includeChildren=True, includeParents=True):
                evt = SpiderFootEvent('LINKED_URL_INTERNAL', url, self.__name__, event)
                self.notifyListeners(evt)

            hosts.append(host)

        for host in set(hosts):
            if not host:
                continue

            if self.getTarget().matches(host, includeChildren=True, includeParents=True):
                evt_type = 'INTERNET_NAME'
            else:
                evt_type = 'AFFILIATE_INTERNET_NAME'

            if self.opts['verify'] and not self.sf.resolveHost(host) and not self.sf.resolveHost6(host):
                self.debug(f"Host {host} could not be resolved")
                evt_type += '_UNRESOLVED'

            evt = SpiderFootEvent(evt_type, host, self.__name__, event)
            self.notifyListeners(evt)

        for location in set(locations):
            evt = SpiderFootEvent("PHYSICAL_ADDRESS", location, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_crxcavator class
