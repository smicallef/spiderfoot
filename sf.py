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
import sys
import time
import cherrypy
import os
from sflib import SpiderFoot
from sfdb import SpiderFootDb
from sfwebui import SpiderFootWebUi

# These are all hard-coded for now, but will eventually
# be set by the UI or CLI
# 'Global' configuration options
# These can be overriden on a per-module basis
sfConfig = {
    '_debug':           True, # Debug
    '_debugfilter':     '', # Filter out debug strings
    '_blocknotif':      False, # Block notifications
    '_useragent':       'SpiderFoot/2.0', # User-Agent to use for HTTP requests
    '_fetchtimeout':    1, # number of seconds before giving up on a fetch
    '_database':        'spiderfoot.db',
    '_webaddr':         '0.0.0.0',
    '_webport':         5001,
    '__guid__':         None # unique ID of scan. Will be set after start-up
}

# Each module will have defaults configured. This will override defaults.
# This would typically be set in the UI/CLI.
moduleConfig = {
    'sfp_spider': {
        'enabled':  True,
        'pause':    1
    },
    'sfp_stor_db': {
        'enabled':  True
    },
    'sfp_mail': {
        'enabled':  True
    },
    'sfp_dns': {
    'enabled': True
    },
    'sfp_websvr': {
        'enabled':  True
    },
    'sfp_stor_print': {
        'enabled':  False
    },
    'sfp_subdomain': {
        'enabled':  True
    },
    'sfp_xref': {
        'enabled': True
    },
    'sfp_similar': {
        'enabled':  False
    },
    'sfp_pageinfo': {
        'enabled':  True
    },
    'sfp_googlesearch': {
        'enabled':  True
    }
}

def main(url):
    moduleInstances = dict()

    # Create a unique ID for this scan and create it in the back-end DB.
    sfConfig['__guid__'] = sfdb.scanInstanceGenGUID(seedUrl)
    sfdb.scanInstanceCreate(sfConfig['__guid__'], 'No name', seedUrl)
    sfdb.scanInstanceSet(sfConfig['__guid__'], time.time() * 1000, None, 'STARTED')

    # Loop through all modules that are enabled in moduleConfig
    for modName in moduleConfig.keys():
        if not moduleConfig[modName]['enabled']:
            sf.debug("Skipping module " + modName + " as not enabled.")
            continue

        # Load the plug-in module
        mod = __import__('modules.' + modName, globals(), locals(), [modName])

        # Build up config to consist of general and module-specific config
        # to override defaults within the module itself
        modConfig = sfConfig
        modConfig.update(moduleConfig[modName])

        # A bit hacky: we pass the database object as part of the config. This
        # object should only be used by the internal SpiderFoot modules writing
        # to the database, which at present is only sfp_stor_db.
        # Individual modules cannot create their own SpiderFootDb instance or
        # we'll get database locking issues, so it all goes through this.
        modConfig['__sfdb__'] = sfdb

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

    sfdb.scanInstanceSet(sfConfig['__guid__'], None, time.time() * 1000, 'FINISHED')
    sfdb.close()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print "You must specify a target URL."
        sys.exit(-1)

    # Process command-line options here (more advanced eventually..)
    seedUrl = sys.argv[1]

    sf = SpiderFoot(sfConfig)
    sfdb = SpiderFootDb(sfConfig)

    # Start the web server so you can start looking at results
    print "Starting web server at http://" + sfConfig['_webaddr'] + \
        ":" + str(sfConfig['_webport']) + "..."

    cherrypy.config.update({
        'server.socket_host': sfConfig['_webaddr'],
        'server.socket_port': sfConfig['_webport']
    })

    # Enable access to static files via the web directory
    currentDir = os.path.dirname(os.path.abspath(__file__))
    conf = { '/static': { 
        'tools.staticdir.on': True,
        'tools.staticdir.dir': os.path.join(currentDir, 'static')
    }}
                        
    cherrypy.quickstart(SpiderFootWebUi(sfConfig), config=conf)

    # Start scanning...
    main(seedUrl)
