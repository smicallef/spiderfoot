#-------------------------------------------------------------------------------
# Name:         sf
# Purpose:      Main wrapper for calling all SpiderFoot modules
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     03/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import imp

# URL to start from. This will be set either by the CLI or UI
seedUrl = 'http://www.binarypool.com'

# These are all hard-coded for now, but will eventually
# be set by the UI or CLI
# 'Global' configuration options
# These can be overriden on a per-module basis
sfConfig = {
    '_debug':           True, # Debug
    '_debugfilter':     'pageinfo', # Filter out debug strings
    '_blocknotif':      False, # Block notifications
    '_useragent':       'SpiderFoot/2.0', # User-Agent to use for HTTP requests
    '_fetchtimeout':    1, # number of seconds before giving up on a fetch
}

# Each module will have defaults configured. This will override defaults.
# This would typically be set in the UI/CLI.
moduleConfig = {
    'sfp_spider': {
        'enabled':  True,
        'pause':    1
    },
    'sfp_mail': {
        'enabled':  False
    },
    'sfp_websvr': {
        'enabled':  False
    },
    'sfp_stor_print': {
        'enabled':  True
    },
    'sfp_subdomain': {
        'enabled':  False
    },
    'sfp_xref': {
        'enabled':  False
    },
    'sfp_similar': {
        'enabled':  False
    },
    'sfp_pageinfo': {
        'enabled':  True
    }
}

def main(url):
    moduleInstances = dict()

    # Loop through all modules that are enabled in moduleConfig
    for modName in moduleConfig.keys():
        if not moduleConfig[modName]['enabled']:
            print "Skipping module " + modName + " as not enabled."
            continue

        # Load the plug-in module
        mod = __import__('modules.' + modName, globals(), locals(), [modName])

        # Build up config to consist of general and module-specific config
        # to override defaults within the module itself
        modConfig = sfConfig
        modConfig.update(moduleConfig[modName])

        # Instantiate the module
        modInstance = getattr(mod, modName)(url, modConfig)
        # Keep track of the module object so it can be referenced later
        moduleInstances[modName] = modInstance

    # Register listener modules and then start all modules sequentially
    for module in moduleInstances.values():
        for listenerModule in moduleInstances.values():
            # Careful not to register twice or you will get duplicate events
            if listenerModule in module._listenerModules:
                continue
            if listenerModule != module and listenerModule.watchedEvents() != None:
                module.registerListener(listenerModule)

    # Start the modules sequentially.
    for module in moduleInstances.values():
        module.start()

if __name__ == '__main__':
    main(seedUrl)
