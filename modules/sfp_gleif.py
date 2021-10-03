# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_gleif
# Purpose:     Search the Global LEI Index for company information using
#              Global Legal Entity Identifier Foundation (GLEIF) search API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-06-21
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_gleif(SpiderFootPlugin):

    meta = {
        'name': "GLEIF",
        'summary': "Look up company information from Global Legal Entity Identifier Foundation (GLEIF).",
        'flags': [],
        'useCases': ["Passive", "Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://search.gleif.org/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://www.gleif.org/en/lei-data/gleif-api",
                "https://api.gleif.org/docs",
            ],
            'favIcon': "https://www.gleif.org/favicon.ico",
            'logo': "https://search.gleif.org/static/img/gleif-logo.svg",
            'description': "The Global Legal Entity Identifier Foundation (GLEIF) Global LEI Index contains "
            "historical and current LEI records including related reference data in one authoritative, central repository."
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["COMPANY_NAME", "LEI"]

    def producedEvents(self):
        return ["COMPANY_NAME", "LEI", "PHYSICAL_ADDRESS", "RAW_RIR_DATA"]

    def searchLegalName(self, qry):
        """Fuzzy search for legal entity by name

        Args:
            qry (str): legal entity name

        Returns:
            dict: search results
        """

        params = urllib.parse.urlencode({
            'q': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'field': "entity.legalName"
        })

        headers = {
            'Accept': 'application/vnd.api+json'
        }

        res = self.sf.fetchUrl(
            f"https://api.gleif.org/api/v1/fuzzycompletions?{params}",
            timeout=30,
            headers=headers,
            useragent=self.opts['_useragent']
        )

        if res['code'] == "429":
            self.error("You are being rate-limited by GLEIF.")
            return None

        try:
            results = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        data = results.get('data')
        if not data:
            return None
        if not len(data):
            return None

        return data

    def searchAutocompletions(self, qry):
        """Search for legal entity name autocompletions

        Args:
            qry (str): legal entity name

        Returns:
            dict: search results
        """

        params = urllib.parse.urlencode({
            'q': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'field': "fulltext"
        })

        headers = {
            'Accept': 'application/vnd.api+json'
        }

        res = self.sf.fetchUrl(
            f"https://api.gleif.org/api/v1/autocompletions?{params}",
            timeout=30,
            headers=headers,
            useragent=self.opts['_useragent']
        )

        if res['code'] == "429":
            self.error("You are being rate-limited by GLEIF.")
            return None

        try:
            results = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        data = results.get('data')
        if not data:
            return None
        if not len(data):
            return None

        return data

    def retrieveRecord(self, lei):
        headers = {
            'Accept': 'application/vnd.api+json'
        }

        res = self.sf.fetchUrl(
            f"https://api.gleif.org/api/v1/lei-records/{lei}",
            timeout=self.opts['_fetchtimeout'],
            headers=headers,
            useragent=self.opts['_useragent']
        )

        if res['code'] == "404":
            self.error(f"No record for LEI: {lei}")
            return None

        if res['code'] == "429":
            self.error("You are being rate-limited by GLEIF.")
            return None

        try:
            results = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        data = results.get('data')

        if not len(data):
            return None
        if not data:
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        leis = list()

        if eventName == "LEI":
            leis.append(eventData)
        elif eventName == "COMPANY_NAME":
            res = self.searchAutocompletions(eventData)

            if res is None:
                self.debug(f"Found no results for {eventData}")
                return

            e = SpiderFootEvent("RAW_RIR_DATA", str(res), self.__name__, event)
            self.notifyListeners(e)

            for record in res:
                relationships = record.get('relationships')
                if not relationships:
                    continue

                lei_records = relationships.get('lei-records')
                if not lei_records:
                    continue

                data = lei_records.get('data')
                if not data:
                    continue

                lei = data.get('id')
                if not SpiderFootHelpers.validLEI(lei):
                    continue

                leis.append(lei)

            self.info(f"Found {len(leis)} LEIs matching {eventData}")

        for lei in set(leis):
            if lei in self.results:
                continue

            if not SpiderFootHelpers.validLEI(lei):
                continue

            e = SpiderFootEvent("LEI", lei, self.__name__, event)
            self.notifyListeners(e)

            self.results[lei] = True

            res = self.retrieveRecord(lei)
            if not res:
                self.debug(f"Found no results for {eventData}")
                return

            attributes = res.get('attributes')
            if not attributes:
                continue

            entity = attributes.get('entity')
            if not entity:
                continue

            legal_name = entity.get('legalName')
            if legal_name:
                entity_name = legal_name.get('value')
                if entity_name:
                    e = SpiderFootEvent("COMPANY_NAME", entity_name, self.__name__, event)
                    self.notifyListeners(e)

            addresses = list()

            address = entity.get('legalAddress')
            if address.get('addressLines'):
                address_lines = ', '.join(filter(None, address.get('addressLines')))
                location = ', '.join(
                    filter(
                        None,
                        [
                            address_lines,
                            address.get('city'),
                            address.get('region'),
                            address.get('country'),
                            address.get('postalCode')
                        ]
                    )
                )

                if location:
                    addresses.append(location)

            address = entity.get('headquartersAddress')
            if address.get('addressLines'):
                address_lines = ', '.join(filter(None, address.get('addressLines')))
                location = ', '.join(
                    filter(
                        None,
                        [
                            address_lines,
                            address.get('city'),
                            address.get('region'),
                            address.get('country'),
                            address.get('postalCode')
                        ]
                    )
                )

                if location:
                    addresses.append(location)

            for address in set(addresses):
                e = SpiderFootEvent("PHYSICAL_ADDRESS", address, self.__name__, event)
                self.notifyListeners(e)

# End of sfp_gleif class
