#-------------------------------------------------------------------------------
# Name:         sfp_vuln
# Purpose:      Query external vulnerability sources to see if our target appears.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     04/10/2015
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import time
import datetime
import re
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_vuln(SpiderFootPlugin):
    """Vulnerable:Footprint,Investigate:Check external vulnerability scanning services (XSSposed.org, punkspider.org) to see if the target is listed."""

    # Default options
    opts = {
        "cutoff": 0
    }

    # Option descriptions
    optdescs = {
        "cutoff": "The maximum age in days of a vulnerbility for it to be included. 0 = unlimited."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME"]

    # What events this module produces
    def producedEvents(self):
        ret = ["VULNERABILITY"]

        return ret

    # Query XSSposed.org
    def queryXss(self, qry):
        ret = list()
        base = "https://www.xssposed.org"
        url = "https://www.xssposed.org/search/?search=" + qry + "&type=host"
        res = self.sf.fetchUrl(url, timeout=30, 
            useragent="SpiderFoot")

        if res['content'] is None:
            self.sf.debug("No content returned from xssposed.org")
            return None

        try:
            if "XSS mirror(s) match" in res['content']:
                """ Expected:
                        <td>
                            <div class="cell1"><a href="/incidents/12345/">blah.com</a></div>
                        </td>
                        <td>
                            <div class="cell2"> <i>xxxx</i></div>
                        </td>
                        <td>
                            <div class="cell3">01/01/2010</div>
                        </td>
                    </tr>
                """

                rx = re.compile("class=.cell1.><a href=\"(.[^>]+)\">(.[^<]+).*?cell3.>(.*?)</div>", 
                    re.IGNORECASE|re.DOTALL)
                for m in rx.findall(res['content']):
                    if self.opts['cutoff'] == 0:
                        # Report it
                        if m[1] == qry or m[1].endswith("."+qry):
                            ret.append("From XSSposed.org: <SFURL>" + base + m[0] + "</SFURL>")
                    else:
                        ts = time.strftime("%s", time.strptime(m[2], "%d/%m/%Y"))
                        if int(ts) > int(time.time())-(86400*self.opts['cutoff']) and \
                            (m[1] == qry or m[1].endswith("."+qry)):
                            # Report it
                            #print "calc: " + str(ts) + " > " + str(int(time.time())-(86400*self.opts['cutoff']))
                            #print "MADE IT past cut-off " + str(self.opts['cutoff']) + ": " + str(m)
                            ret.append("From XSSposed.org: <SFURL>" + base + m[0] + "</SFURL>")
        except Exception as e:
            self.sf.error("Error processing response from XSSposed.org: " + str(e), False)
            return None
        return ret

    # Query punkspider.org
    def queryPunk(self, qry):
        ret = list()
        base = "https://www.punkspider.org/#searchkey=url&searchvalue=.{0}&pagenumber=1&filterType=or&filters=bsqli,sqli,xss,trav,mxi,osci,xpathi"
        url = "https://www.punkspider.org/service/search/domain/"
        post = '{"searchKey":"url","searchValue":".' + qry + '","pageNumber":1,"filterType":"or","filters":["bsqli","mxi","osci","sqli","trav","xpathi","xss"]}\n\r'

        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/json; charset=UTF-8'
        }
        res = self.sf.fetchUrl(url, timeout=60,
            useragent="SpiderFoot", postData=post, headers=headers)

        if res['content'] is None:
            self.sf.debug("No content returned from punkspider.org")
            return None

        if "timestamp\":" in res['content']:
            """ Expected:
            {"input": {"searchKey": "url", "filterType": "or", "searchValue": "cnn.com", "pageNumber": 1, "filters": ["bsqli", "mxi", "osci", "sqli", "trav", "xpathi", "xss"]}, "output": {"domainSummaryDTOs": [{"xpathi": "0", "xss": "1", "domain": "www.domain.com", "osci": "0", "title": "Title not found", "url": "www.domain.com", "timestamp": "2014-05-18T12:30:55Z", "exploitabilityLevel": 1, "sqli": "0", "trav": "0", "mxi": "0", "id": "www.domain.com", "bsqli": "0"}], "qTime": 9745, "rowsFound": 1, "numberOfPages": 1}}
            """

            try:
                data = json.loads(res['content'])
                for rec in data['output']['domainSummaryDTOs']:
                    if self.opts['cutoff'] == 0:
                        ret.append("From Punkspider.org: " + rec['url'] + "\n<SFURL>" + base.format(qry) + "</SFURL>")
                    else:
                        ts = rec['timestamp']
                        nts = time.strftime("%s", time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
                        if int(nts) > int(time.time())-(86400*self.opts['cutoff']):
                            # Report it
                            #print "calc: " + str(nts) + " > " + str(int(time.time())-(86400*self.opts['cutoff']))
                            #print "MADE IT past cut-off " + str(self.opts['cutoff']) + ": " + str(ts)
                            ret.append("From Punkspider.org: " + rec['url'] + "\n<SFURL>" + base.format(qry) + "</SFURL>")
            except Exception as e:
                self.sf.error("Error processing response from Punkspider.org: " + str(e), False)
                return None
        return ret

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        data = list()

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

       # Don't look up stuff twice
        if self.results.has_key(eventData):
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        xss = self.queryXss(eventData)
        if xss:
            data.extend(xss)

        punk = self.queryPunk(eventData)
        if punk:
            data.extend(punk)

        for n in data:
            # Notify other modules of what you've found
            e = SpiderFootEvent("VULNERABILITY", n, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_vuln class
