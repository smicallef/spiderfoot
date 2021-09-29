# -------------------------------------------------------------------------------
# Name:        sfp_gravatar
# Purpose:     SpiderFoot plug-in to search Gravatar API for an email address
#              and retrieve user information, including username, name, phone
#              numbers, additional email addresses, and social media usernames.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-05-26
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import hashlib
import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_gravatar(SpiderFootPlugin):

    meta = {
        'name': "Gravatar",
        'summary': "Retrieve user information from Gravatar API.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://secure.gravatar.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://secure.gravatar.com/site/implement/"
            ],
            'favIcon': "https://secure.gravatar.com/favicon.ico",
            'logo': "https://secure.gravatar.com/favicon.ico",
            'description': "Your Gravatar is an image that follows you from site to site "
            "appearing beside your name when you do things like comment or post on a blog.\n"
            "A Gravatar is a Globally Recognized Avatar. You upload it and create your profile just once, "
            "and then when you participate in any Gravatar-enabled site, your Gravatar image will automatically follow you there.",
        }
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None
    reportedUsers = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.reportedUsers = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['EMAILADDR']

    # What events this module produces
    def producedEvents(self):
        return ['RAW_RIR_DATA', 'USERNAME',
                'EMAILADDR', 'EMAILADDR_GENERIC', 'PHONE_NUMBER', 'GEOINFO',
                'ACCOUNT_EXTERNAL_OWNED', 'SOCIAL_MEDIA']

    # Query Gravatar API for the specified email address
    # https://secure.gravatar.com/site/implement/
    # https://secure.gravatar.com/site/implement/profiles/
    def query(self, qry):
        email_hash = hashlib.md5(qry.encode('utf-8', errors='replace').lower()).hexdigest()  # noqa: DUO130
        output = 'json'

        res = self.sf.fetchUrl("https://secure.gravatar.com/" + email_hash + '.' + output,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.debug('No response from gravatar.com')
            return None

        if res['code'] != '200':
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        if data.get('entry') is None or len(data.get('entry')) == 0:
            return None

        return data.get('entry')[0]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        data = self.query(eventData)

        if data is None:
            self.debug("No user information found for " + eventData)
            return

        evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

        if data.get('preferredUsername') is not None:
            un = data.get('preferredUsername')
            evt = SpiderFootEvent("USERNAME", un, self.__name__, event)
            self.notifyListeners(evt)
            self.reportedUsers[un] = True

        names = list()
        if data.get('name') is not None:
            if type(data.get('name')) != list:
                names.append(data.get('name'))
            else:
                names = data.get('name')

            for name in names:
                full_name = name.get('formatted')
                if full_name:
                    evt = SpiderFootEvent("RAW_RIR_DATA", f"Possible full name: {full_name}", self.__name__, event)
                    self.notifyListeners(evt)

        # TODO: re-enable once location validation is implemented
        # location can not be trusted
        # if data.get('currentLocation') is not None:
        #     location = data.get('currentLocation')
        #     if len(location) < 3 or len(location) > 100:
        #         self.debug("Skipping likely invalid location.")
        #     else:
        #         evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
        #         self.notifyListeners(evt)

        if data.get('phoneNumbers') is not None:
            for number in data.get('phoneNumbers'):
                if number.get('value') is not None:
                    evt = SpiderFootEvent("PHONE_NUMBER", number.get('value'), self.__name__, event)
                    self.notifyListeners(evt)

        if data.get('emails') is not None:
            for email in data.get('emails'):
                em = email.get('value')
                if not em:
                    continue
                if self.sf.validEmail(em) and em != eventData:
                    if em.split("@")[0] in self.opts['_genericusers'].split(","):
                        evttype = "EMAILADDR_GENERIC"
                    else:
                        evttype = "EMAILADDR"

                    evt = SpiderFootEvent(evttype, em, self.__name__, event)
                    self.notifyListeners(evt)

        if data.get('ims') is not None:
            for im in data.get('ims'):
                v = im.get('value')
                if v is None:
                    continue
                t = im.get('type').capitalize() + " (Instant Messenger)\n" + v
                evt = SpiderFootEvent("ACCOUNT_EXTERNAL_OWNED", t, self.__name__, event)
                self.notifyListeners(evt)
                if v not in self.reportedUsers:
                    evt = SpiderFootEvent("USERNAME", v, self.__name__, event)
                    self.notifyListeners(evt)
                    self.reportedUsers[v] = True

        if data.get('accounts') is not None:
            for account in data.get('accounts'):
                url = account.get('url')
                platform = account.get('shortname')
                if platform is not None and url is not None:
                    t = platform.capitalize() + ": <SFURL>" + url + "</SFURL>"
                    evt = SpiderFootEvent("SOCIAL_MEDIA", t, self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_gravatar class
