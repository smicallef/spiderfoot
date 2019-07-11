#-------------------------------------------------------------------------------
# Name:         sfp_deviantart
# Purpose:      Query DeviantArt profile name, age, and location information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-05-10
# Copyright:   (c) bcoles 2019
# Licence:     GPL
#-------------------------------------------------------------------------------

from datetime import datetime
import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_deviantart(SpiderFootPlugin):
    """DeviantArt:Footprint,Investigate,Passive:Social Media::Gather name, date of birth, and location from DeviantArt profiles."""

    # Default options
    opts = { 
    }

    # Option descriptions
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "DeviantArt"
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ "SOCIAL_MEDIA" ]

    # What events this module produces
    def producedEvents(self):
        return [ "RAW_RIR_DATA", "GEOINFO", "DATE_HUMAN_DOB" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Retrieve profile
        try:
            network = eventData.split(": ")[0]
            username = eventData.split(": ")[1]
        except BaseException as e:
            self.sf.error("Unable to parse SOCIAL_MEDIA: " +
                          eventData + " (" + str(e) + ")", False)
            return None

        if not network == "DeviantArt":
            self.sf.debug("Skipping social network profile, " + username + ", as not a DeviantArt profile")
            return None

        res = self.sf.fetchUrl("https://deviantart.com/" + username, timeout=self.opts['_fetchtimeout'], 
                               useragent=self.opts['_useragent'])

        if res['content'] is None:
            return None

        # Check if the profile is valid and extract human name
        human_name_match = re.findall(r'<strong class="f realname">(.+?)</strong>', res['content'])

        if not human_name_match:
            self.sf.debug(username + " is not a valid DeviantArt profile")
            return None

        human_name = human_name_match[0].strip()

        if not username.lower() == human_name.lower():
            e = SpiderFootEvent("RAW_RIR_DATA", "Possible full name: " + human_name, self.__name__, event)
            self.notifyListeners(e)

        # Retrieve location (country)
        location_match = re.findall(r'id="aboutme-personal-info">(.+?)<', res['content'], re.MULTILINE | re.DOTALL)
        if location_match:
            location = location_match[0].strip()

            if len(location) < 3 or len(location) > 100:
                self.sf.debug("Skipping likely invalid location.")
            else:
                e = SpiderFootEvent("GEOINFO", location, self.__name__, event)
                self.notifyListeners(e)

        # Retrieve full date of birth
        birthday_match = re.findall(r'<dt class="f h">Birthday</dt><dd class="f h">([A-Z][a-z]+ \d{1,2}, \d{4})<', res['content'])
        if birthday_match:
            birthday = birthday_match[0].strip()

            try:
                dob = datetime.strptime(birthday, '%B %d, %Y').strftime('%Y-%m-%d')
                e = SpiderFootEvent("DATE_HUMAN_DOB", dob, self.__name__, event)
                self.notifyListeners(e)
            except:
                self.sf.debug("Skipping birth date, " + birthday + ", as not a valid date")

# End of sfp_deviantart class
