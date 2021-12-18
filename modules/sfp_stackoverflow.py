# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_stackoverflow
# Purpose:      Example module to use for new modules.
#
# Author:      Jess Williams <jesscia_williams0@protonmail.com>
#
# Created:     2021-12-12
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_stackoverflow(SpiderFootPlugin):

    meta = {
        'name': "Stackoverflow",
        'summary': "Search StackOverflow for any mentions of a target domain. Returns potentially related information.",
        'flags': ["errorprone"],
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
            ],
            'favIcon': "https://cdn.sstatic.net/Sites/stackoverflow/Img/favicon.ico?v=ec617d715196",
            'logo': "https://cdn.sstatic.net/Sites/stackoverflow/Img/apple-touch-icon.png",
            'description': "A paragraph of text with details about the data source / services. "
            "Keep things neat by breaking the text up across multiple lines as "
            "has been done here. If line breaks are needed for breaking up "
            "multiple paragraphs, use \n.",
        }
    }

    # Default Options
    opts = {
        'api_key': '',
    }

    # Option descriptions.
    optdescs = {
        "api_key": "StackApps Optional API Key."
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
        return [
                "DOMAIN_NAME", 
                "HUMAN_NAME", 
                "BITCOIN_ADDRESS", 
                "COMPANY_NAME",
                "IP_ADDRESS",
                "USERNAME"
                ]

    # What events this module produces
    def producedEvents(self):
        return ["RAW_RIR_DATA", "EMAILADDR"]

    def query(self, qry, ):
        # The Stackoverflow excerpts endpoint will search the site for mentions of a keyword and returns a snippet of relevant results
        res = self.sf.fetchUrl(
                f"https://api.stackexchange.com/2.3/search/excerpts?order=desc&q={qry}&site=stackoverflow",
                timeout=self.opts['_fetchtimeout'],
                useragent="SpiderFoot"
            )

        # # User profile endpoint
        # if search == "user":
        #     res = self.sf.fetchUrl(
        #         f"https://api.stackexchange.com/2.3/search/excerpts?order=desc&q={qry}&site=stackoverflow",
        #         timeout=self.opts['_fetchtimeout'],
        #         useragent="SpiderFoot"
        #     )

        if res['content'] is None:
            self.info(f"No Stackoverflow info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Stackoverflow: {e}")
        return None

    def extractEmail(self, text):
        emails = set()

        #remove span class highlight, automatically added by stackoverflow to highlight search text
        newText = text.replace("<span class=\"highlight\">","")
        matches = re.findall(r'([\%a-zA-Z\.0-9_\-\+]+@[a-zA-Z\.0-9\-]+\.[a-zA-Z\.0-9\-]+)', newText)

        for match in matches:
            if self.sf.validEmail(match):
                emails.add(match)

        return list(emails)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        query_results = self.query(eventData)
        items = query_results.get('items')

        allEmails = []

        #iterate through all results from query, creating raw_rir_data events and extracting emails      
        for item in items:
            if self.checkForStop():
                return

            # return raw_rir_data event
            body = item["body"]
            excerpt = item["excerpt"]
            question = item["question_id"]
            e = SpiderFootEvent('RAW_RIR_DATA',
                                str("<SFURL>https://stackoverflow.com/questions/")+str(question)+str("</SFURL>")+str("\n")+str(body)+str(excerpt), 
                                self.__name__, event)
            self.notifyListeners(e)

            #Extract email addresses and add to the allEmails list
            text = body+excerpt
            emails = self.extractEmail(text)
            allEmails.append(emails)

        if emails:
            for email in emails:
                e = SpiderFootEvent('EMAILADDR', email, self.__name__, event)
                self.notifyListeners(e)


        
# End of sfp_stackoverflow class
