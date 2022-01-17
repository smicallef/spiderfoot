# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_stackoverflow
# Purpose:      Search StackOverflow for any mentions of a target domain name
#
# Author:      Jess Williams <jesscia_williams0@protonmail.com>
#
# Created:     2021-12-12
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import time
from modules.sfp_names import sfp_names


from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_stackoverflow(SpiderFootPlugin):

    meta = {
        'name': "StackOverflow",
        'summary': "Search StackOverflow for any mentions of a target domain. Returns potentially related information.",
        'flags': ["errorprone", "apikey"],
        'useCases': ["Passive"],
        'categories': ["Content Analysis"],
        'dataSource': {
            'website': "https://www.stackecxchange.com",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://api.stackexchange.com/docs"
            ],
            'apiKeyInstructions': [
                "Visit https://stackapps.com/apps/oauth/register",
                "Fill out the details in the form with as much details as you're comfortable with.",
                "The OAuth Domain can either be a valid domain you own or control, or stackexchange.com."
                "Select 'Register Your Application'."
                "Under the Title 'Key' is your API key, use this for an increased request quota."
            ],
            'favIcon': "https://cdn.sstatic.net/Sites/stackoverflow/Img/favicon.ico?v=ec617d715196",
            'logo': "https://cdn.sstatic.net/Sites/stackoverflow/Img/apple-touch-icon.png",
            'description': "StackOverflow is a knowledge sharing public platform for IT professionals"
            "and students where users can post questions and get answers from other users."
        }
    }

    # Default Options
    opts = {
        'api_key': '',
    }

    # Option descriptions
    optdescs = {
        "api_key": "StackApps has an optional API key. Using an API key will increase the amount of requests allowed."
    }

    # Results Tracking
    results = None

    # Tracking the error state of the module
    errorState = False

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
        return ["RAW_RIR_DATA",
                "EMAILADDR",
                "AFFILIATE_EMAILADDR",
                "USERNAME",
                "IP_ADDRESS",
                "IPV6_ADDRESS",
                "HUMAN_NAME"
                ]

    def query(self, qry, qryType):
        # The Stackoverflow excerpts endpoint will search the site for mentions of a keyword and returns a snippet of relevant results
        if qryType == "excerpts":
            try:
                res = self.sf.fetchUrl(
                    f"https://api.stackexchange.com/2.3/search/excerpts?order=desc&q={qry}&site=stackoverflow",
                    timeout=self.opts['_fetchtimeout'],
                    useragent="SpiderFoot"
                )
                time.sleep(1)
            except Exception as e:
                self.error(f"Error querying StackExchange API: {e}")
                self.errorState = True
                return None

        # Questions profile endpoint, used to return displayname
        if qryType == "questions":
            try:
                res = self.sf.fetchUrl(
                    f"https://api.stackexchange.com/2.3/questions/{qry}?order=desc&sort=activity&site=stackoverflow",
                    timeout=self.opts['_fetchtimeout'],
                    useragent="SpiderFoot"
                )
                time.sleep(1)
            except Exception as e:
                self.error(f"Error querying StackExchange API: {e}")
                self.errorState = True
                return None

        if res['content'] is None:
            self.info(f"No Stackoverflow info found for {qry}")
            return None

        if res['code'] == '502':
            self.error("Throttling Error. To increase requests, use an API key.")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Stackoverflow: {e}")
            self.errorState = True
            return None

    def extractUsername(self, questionId):
        # Need to query the questions endpoint with the question_id to find the username
        query_results = self.query(questionId, "questions")

        items = query_results.get('items')

        if items is None:
            return None

        for item in items:
            owner = item['owner']
            username = owner.get('display_name')

        return str(username)

    def extractIP4s(self, text):
        ips = set()

        matches = re.findall(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', text)

        if matches:
            for match in matches:
                if self.sf.validIP(match) and not(self.sf.isValidLocalOrLoopbackIP(match)):
                    ips.add(match)
            return list(ips)
        else:
            return None

    def extractIP6s(self, text):
        ips = set()

        matches = re.findall(r'(?:^|(?<=\s))(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?=\s|$)', text)

        if matches:
            for match in matches:
                if self.sf.validIP6(match) and not(self.sf.isValidLocalOrLoopbackIP(match)):
                    ips.add(match)
            return list(ips)
        else:
            return None

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        query_results = self.query(eventData, "excerpts")
        items = query_results.get('items')
        allEmails = []
        allUsernames = []
        allIP4s = []
        allIP6s = []

        if items is None:
            return
        # Iterate through all results from query, creating raw_rir_data events and extracting emails
        for item in items:
            if self.checkForStop():
                return

            body = item["body"]
            excerpt = item["excerpt"]
            question = item["question_id"]
            text = body + excerpt

            # create raw_rir_data event
            e = SpiderFootEvent('RAW_RIR_DATA',
                                str("<SFURL>https://stackoverflow.com/questions/") + str(question) + str("</SFURL>") + str("\n") + str(item), self.__name__, event)
            self.notifyListeners(e)

            emails = self.sf.parseEmails(text)
            if emails is not None:
                for email in emails:
                    allEmails.append(str(email))

            questionId = item["question_id"]
            username = self.extractUsername(questionId)
            if username is not None:
                allUsernames.append(username)

            ip4s = self.extractIP4s(text)
            if ip4s is not None:
                allIP4s.append(ip4s)

            ip6s = self.extractIP6s(text)
            if ip6s is not None:
                allIP6s.append(ip6s)

        # create events for emails, username and IPs
        for email in allEmails:
            email = str(email).lower()
            if self.getTarget().matches(email):
                e = SpiderFootEvent('EMAILADDR', email, self.__name__, event)
                self.notifyListeners(e)
            else:
                e = SpiderFootEvent('AFFILIATE_EMAILADDR', email, self.__name__, event)
                self.notifyListeners(e)

        for username in allUsernames:
            if " " in username:
                # Send to sfp_names to identify if username is actually a human name
                e = SpiderFootEvent('RAW_RIR_DATA', 'Possible full name: ' + username, self.__name__, event)
                self.notifyListeners(e)

                opts = {
                    'algolimit': 70,
                    'emailtoname': False,
                    'filterjscss': False
                }

                sfp_names.setup(self, self.sf, opts)
                sfp_names.handleEvent(self, e)
            else:
                e = SpiderFootEvent('USERNAME', username, self.__name__, event)
                self.notifyListeners(e)

        for ip in allIP4s:
            ip = str(ip)
            e = SpiderFootEvent('IP_ADDRESS', ip, self.__name__, event)
            self.notifyListeners(e)

        for ip in allIP6s:
            ip = str(ip)
            e = SpiderFootEvent('IPV6_ADDRESS', ip, self.__name__, event)
            self.notifyListeners(e)
# End of sfp_stackoverflow class
