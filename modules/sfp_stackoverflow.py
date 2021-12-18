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
import netaddr


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
                ]

    # What events this module produces
    def producedEvents(self):
        return ["RAW_RIR_DATA", "EMAILADDR", "USERNAME"]

    def query(self, qry, qryType):
        # The Stackoverflow excerpts endpoint will search the site for mentions of a keyword and returns a snippet of relevant results
        if qryType == "excerpts":
            res = self.sf.fetchUrl(
                    f"https://api.stackexchange.com/2.3/search/excerpts?order=desc&q={qry}&site=stackoverflow",
                    timeout=self.opts['_fetchtimeout'],
                    useragent="SpiderFoot"
                )

        # User profile endpoint
        if qryType == "questions":
            res = self.sf.fetchUrl(
                f"https://api.stackexchange.com/2.3/questions/{qry}?order=desc&sort=activity&site=stackoverflow",
                timeout=self.opts['_fetchtimeout'],
                useragent="SpiderFoot"
            )

        if res['content'] is None:
            self.info(f"No Stackoverflow info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Stackoverflow: {e}")
        return None

    def extractEmails(self, text):
        emails = set()

        #remove span class highlight, automatically added by stackoverflow to highlight search text
        newText = text.replace("<span class=\"highlight\">","")
        matches = re.findall(r'([\%a-zA-Z\.0-9_\-\+]+@[a-zA-Z\.0-9\-]+\.[a-zA-Z\.0-9\-]+)', newText)

        if matches:
            for match in matches:
                if self.sf.validEmail(match):
                    emails.add(match)
            return list(emails)
        else:
            return 
    
    def extractUsername(self, questionId):
        #need to query the questions endpoint with the question_id to find the username
        query_results = self.query(questionId, "questions")
        items = query_results.get('items')

        if query_results is None:
            return 

        for item in items:
            owner = item['owner']
            username = owner.get('display_name')
        
        return str(username)
    
    def extractIPs(self, text):
        ips = set()

        matches = re.findall(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', text)
        
        if matches:
            for match in matches:
                if self.sf.validIP(match) and not(netaddr.IPAddress(match).is_loopback()):
                    ips.add(match)
            return list(ips)
        else:
            return

    def handleEvent(self, event):
        eventName = event.eventType
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
        allIPs = []

        #iterate through all results from query, creating raw_rir_data events and extracting emails      
        for item in items:
            if self.checkForStop():
                return
            
            # create raw_rir_data event
            body = item["body"]
            excerpt = item["excerpt"]
            question = item["question_id"]
            e = SpiderFootEvent('RAW_RIR_DATA',
                                str("<SFURL>https://stackoverflow.com/questions/")+str(question)+str("</SFURL>")+str("\n")+str(body)+str(excerpt), 
                                self.__name__, event)
            self.notifyListeners(e)
            
            text = body+excerpt
            #Extract other interesting events
            emails = self.extractEmails(text)
            if emails is not None:
                allEmails.append(emails)

            questionId = item["question_id"]
            username = self.extractUsername(questionId)
            if username is not None:
                allUsernames.append(username)

            ips = self.extractIPs(text)
            if ips is not None:
                allIPs.append(ips)

        # create events for all other events
        for email in allEmails:
            email = str(email)
            e = SpiderFootEvent('EMAILADDR', email, self.__name__, event)
            self.notifyListeners(e)

        for username in allUsernames:
            e = SpiderFootEvent('USERNAME', username, self.__name__, event)
            self.notifyListeners(e)

        for ip in allIPs:
            ip = str(ip)
            e = SpiderFootEvent('IP_ADDRESS', ip, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_stackoverflow class