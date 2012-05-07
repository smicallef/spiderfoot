#-------------------------------------------------------------------------------
# Name:         sfp_googlesearch
# Purpose:      Searches Google for content related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in __init__)
sf = None

class sfp_googlesearch(SpiderFootPlugin):
    # Default options
    opts = {
        # These must always be set
        '_debug':       True,
        '_debugfilter': '',
        '_useragent':   'Mozilla/5.0 (Windows NT 6.1; rv:11.0) Gecko/20100101 Firefox/11.0'
    }

    # URL this instance is working on
    seedUrl = None
    baseDomain = None # calculated from the URL in __init__

    def __init__(self, url, userOpts=dict()):
        global sf
        self.seedUrl = url

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # For error reporting, debug, etc.
        sf = SpiderFoot(self.opts)

         # Extract the 'meaningful' part of the FQDN from the URL
        self.baseDomain = sf.urlBaseDom(self.seedUrl)
        sf.debug('Base Domain: ' + self.baseDomain)

    # What events is this module interested in for input
    def watchedEvents(self):
        return None

    def start(self):
        sf.googleIterate("site:binarypool.com", {'pause': True})

# End of sfp_googlesearch class

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "You must specify a domain to start searching for."
        exit(-1)

    sfp = sfp_googlesearch(sys.argv[1])
    sfp.start()
