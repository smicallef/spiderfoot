# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_shodan
# Purpose:      Query SHODAN for identified IP addresses.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     19/03/2014
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import sys
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.common.keys import Keys
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
import time


class sfp_registrar(SpiderFootPlugin):
    """Registrar Scan:Scan for personal details:Get the person who registered the domain, currently only SIDN for .nl domains"""

    # Default options
    opts = {}

    # Option descriptions
    optdescs = {}

    results = dict()

    driver = webdriver

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.start_webdriver()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["HUMAN_NAME"]

    def querySIDN(self, qry):
        try:
            self.sf.info("[+] Starting query for: " + qry)
            #Set the page load timeout to 20 seconds
            self.driver.set_page_load_timeout(20)
            #Open the search page
            
            #Open the search page
            self.driver.get('https://www.sidn.nl/whois')
            #Find the search box
            searchBox = self.driver.find_element_by_id('domain-search-input')
            #Fill in the host name
            searchBox.send_keys(qry)
            time.sleep(1)
            searchBox.send_keys(Keys.RETURN)
            #wait a second
            time.sleep(1)
            #agree with the terms
            self.driver.find_element_by_class_name('icon-checkmark').click()
            #sleep for  second
            time.sleep(1)
            #Click the confirm button
            self.driver.find_element_by_id('confirm-button').click()

            #Now the results load
            registrantName = self.driver.find_element_by_class_name('whois_registrant').find_element_by_tag_name('span').get_attribute("innerHTML")

            registrantEmail = self.driver.find_element_by_class_name('whois_adminc').find_element_by_tag_name('span').get_attribute("innerHTML")

            return registrantName, registrantEmail

        except Exception, e:
            self.sf.info("[+] Caught error while executing query for: " + qry + " - " + str(e))
            return None

    def start_webdriver(self):
        try:
            self.sf.info("[+] Starting webdriver...")
            dcap = dict(DesiredCapabilities.PHANTOMJS)

            #Set a browser user agent so we dont get identified as a crawler
            dcap["phantomjs.page.settings.userAgent"] = (
                'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:44.0) Gecko/20100101 Firefox/44.0'
            )

            #Fetch files in current dir and select phantomjs, so it doesnt matter whether you run this on windows or linux
            phantomjsLoaded = False

            fileName = "/root/spiderfoot/phantomjs"
            #Allow ssl errors just in case oh and dont download the images cuz we cant see em anyways
            self.driver = webdriver.PhantomJS(fileName,service_args=["--ignore-ssl-errors=true", "--load-images=false"],desired_capabilities=dcap)
            phantomjsLoaded = True
            if phantomjsLoaded == False:
                self.sf.info("[+] Could not load phantomjs, make sure the binary is in the folder")
                return None

            self.sf.info("[+] Succesfully started webdriver")


        except Exception, e:
            message = "[+] Got error while starting webdriver: " + str(e)
            self.sf.info(message)
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

            # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        #Execute function based on TLD
        if ".nl" in eventData:
            registrantName, registrantEmail = self.querySIDN(eventData)
        else:
            return None

        if self.checkForStop():
            return None

        if registrantName is not None and registrantEmail is not None:
            # Notify other modules of what you've found
            self.sf.info("Found Owner for " + eventData)
            evt = SpiderFootEvent("HUMAN_NAME", registrantName , self.__name__, event)
            self.notifyListeners(evt)
            evt = SpiderFootEvent("EMAILADDR", registrantEmail , self.__name__, event)
            self.notifyListeners(evt)

        #self.driver.close()
        #self.sf.info("[+] Stopped the webdriver)
        return None

# End of sfp_registrar class
