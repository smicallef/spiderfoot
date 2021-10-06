# -------------------------------------------------------------------------------
# Name:         sfp_iknowwhatyoudownload
# Purpose:      Query iknowwhatyoudownload.com for IP addresses using torrents.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     03/09/2018
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_iknowwhatyoudownload(SpiderFootPlugin):

    meta = {
        'name': "Iknowwhatyoudownload.com",
        'summary': "Check iknowwhatyoudownload.com for IP addresses that have been using torrents.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Secondary Networks"],
        'dataSource': {
            'website': "https://iknowwhatyoudownload.com/en/peer/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://iknowwhatyoudownload.com/en/api/",
                "https://iknowwhatyoudownload.com/en/link/",
                "https://iknowwhatyoudownload.com/en/peer/"
            ],
            'apiKeyInstructions': [
                "Visit https://iknowwhatyoudownload.com/en/api/",
                "Request Demo Key with email id",
                "The API key will be sent to your email"
            ],
            'favIcon': "https://iknowwhatyoudownload.com/assets/img/utorrent2.png",
            'logo': "https://iknowwhatyoudownload.com/assets/img/logo.png",
            'description': "Our system collects torrent files in two ways: parsing torrent sites, and listening DHT network. "
            "The system contains more than 7 million torrents (as of Oct 2021) which were classified and which are using now "
            "for collecting peer sharing facts (up to 200.000.000 daily).",
        }
    }

    opts = {
        "daysback": 30,
        "api_key": ""
    }

    optdescs = {
        "daysback": "How far back (in days) to look for activity.",
        "api_key": "Iknowwhatyoudownload.com API key."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS"]

    def producedEvents(self):
        return ["MALICIOUS_IPADDR"]

    def query(self, qry):
        """Search iknowwhatyoudownload.com for an IPv4/IPv6 address.

        Args:
            qry: IPv4/IPv6 address

        Returns:
            dict: JSON response containing dowloaded content
        """
        params = urllib.parse.urlencode({
            'ip': qry,
            'days': self.opts['daysback'],
            'key': self.opts['api_key'],
        })

        res = self.sf.fetchUrl(
            f"https://api.antitor.com/history/peer/?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from iknowwhatyoudownload.com.")
            return None

        if res['content'] is None:
            self.info(f"No results for {qry} from iknowwhatyoudownload.com")
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from iknowwhatyoudownload.com: {e}")
            return None

        error = data.get('error')
        if error and error == "INVALID_DAYS":
            self.errorState = True
            self.error(f"The number of days you have configured ({self.opts['daysback']}) was not accepted. If you have the demo key, try 30 days or less.")
            return None

        contents = data.get('contents')

        if not contents:
            return None

        return contents

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_iknowwhatyoudownload but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)

        if not data:
            return

        retdata = [f"<SFURL>https://iknowwhatyoudownload.com/en/peer/?ip={eventData}</SFURL>"]

        for d in data:
            torrent = d.get('torrent')

            if not torrent:
                continue

            download_name = torrent.get('name')
            download_date = d.get("endDate", "Date unknown")
            retdata.append(f"{download_name} ({download_date})")

        e = SpiderFootEvent("MALICIOUS_IPADDR", "\n".join(retdata), self.__name__, event)
        self.notifyListeners(e)

# End of sfp_iknowwhatyoudownload class
