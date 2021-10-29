# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_subfinder
# Purpose:      SpiderFoot plug-in for using the 'Subfinder' tool.
#
# Author:      Ángel Pérez Raya <angelperezhuelva2@gmail.com>
#
# Created:     29/09/2021
# Copyright:   (c) Ángel Pérez Raya 2021
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import subprocess, os.path

class sfp_tool_subfinder(SpiderFootPlugin):

    meta = {
        'name': "Tool - Subfinder",
        'summary': "Performs an enumeration of subdomains associated with the given domain using Subfinder",
        'flags': ["tool"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Passive DNS"],
        'toolDetails': {
            'name': 'Subfinder',
            'description': 'Subfinder is a tool that is used to discover valid subdomains for websites by using passive online sources.',
            'website': 'https://github.com/projectdiscovery/subfinder',
            'repository': 'https://github.com/projectdiscovery/subfinder'
        },
    }

    # Default options
    opts = {
        'gopath': "go",
        'subfinderpath': ""
    }

    # Option descriptions
    optdescs = {
        'gopath': "Path to go interpreter to use for Subfinder. If just 'go' then it must be in your PATH.",
        'subfinderpath': "Path to the where the subfinder file lives. Must be set."
    }

    results = None
    
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME","INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["INTERNET_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Normalize path
        if self.opts['subfinderpath'].endswith('subfinder'):
            exe = self.opts['subfinderpath']    
        elif self.opts['subfinderpath'].endswith('/'):
            exe = self.opts['subfinderpath'] + "subfinder"
        else:
            exe = self.opts['subfinderpath'] + "/subfinder"

        printf(f"exe: {exe}")

        # If tool is not found, abort
        if not os.path.isfile(exe):
            self.error("You enabled sfp_tool_subfinder but did not install the tool!")
            self.errorState = True
            return

        try:
            self.sf.debug(f"We use the data: {eventData}")
       
            # Run subfinder
            data = subprocess.run([exe+' -d '+eventData], shell=True, capture_output=True, text=True)
            output = str(data.stdout)

            # Parsing the information
            allSubdomains = output.split('\n')

            # Saving the information
            subdomains = list()
            for subdomain in allSubdomains:
                if eventData in subdomain:
                    subdomains.append(subdomain)

            if not subdomains:
                self.sf.error("Unable to perform SFP_TOOL_SUBFINDER on " + eventData)
                return
            else:
                for x in subdomains:
                    evt = SpiderFootEvent(eventName, x, self.__name__, event)
                    self.notifyListeners(evt)

        except Exception as e:
            self.sf.error("Unable to perform the SFP_TOOL_SUBFINDER on " + eventData + ": " + str(e))
            return

# End of sfp_subfinder class