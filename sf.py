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
from sfwebui import SpiderFootWebUi, SpiderFootWebUiMini

# 'Global' configuration options
# These can be overriden on a per-module basis, and some will
# be overridden from saved configuration settings stored in the DB.
sfConfig = {
    '_debug':            False, # Debug
    '__blocknotif':      False, # Block notifications
    '_useragent':        'SpiderFoot/2.0', # User-Agent to use for HTTP requests
    '_fetchtimeout':     5, # number of seconds before giving up on a fetch
    '__database':        'spiderfoot.db',
    '__webaddr':         '0.0.0.0',
    '__webport':         5001,
    '__guid__':          None, # unique ID of scan. Will be set after start-up.
    '__modules__':       None # List of modules. Will be set after start-up.
}

sfOptdescs = {
    '_debug':       "Enable debugging?",
    '_useragent':   "Default User-Agent string to use for HTTP requests. Can be overridden by individual modules.",
    '_fetchtimeout':    "Number of seconds before giving up on a HTTP request.",
    '_modulesenabled':  "Modules enabled for the scan." # This is a hack to get a description for
                                                        # an option not actually available.
}

if __name__ == '__main__':
    if len(sys.argv) > 1:
        (addr, port) = sys.argv[1].split(":")
        sfConfig['__webaddr'] = addr
        sfConfig['__webport'] = int(port)

    sf = SpiderFoot(sfConfig)
    sfModules = dict()

    # Go through each module in the modules directory with a .py extension
    for filename in os.listdir(sf.myPath() + '/modules/'):
        if filename.startswith("sfp_") and filename.endswith(".py"):
            # Skip the module template and debugging modules
            if filename == "sfp_template.py" or filename == 'sfp_stor_print.py':
                continue
            modName = filename.split('.')[0]

            # Load and instantiate the module
            sfModules[modName] = dict()
            mod = __import__('modules.' + modName, globals(), locals(), [modName])
            sfModules[modName]['object'] = getattr(mod, modName)()
            sfModules[modName]['descr'] = sfModules[modName]['object'].__doc__
            if hasattr(sfModules[modName]['object'], 'opts'):
                sfModules[modName]['opts'] = sfModules[modName]['object'].opts
            if hasattr(sfModules[modName]['object'], 'optdescs'):
                sfModules[modName]['optdescs'] = sfModules[modName]['object'].optdescs

    if len(sfModules.keys()) < 1:
        print "No modules found in the modules directory."
        sys.exit(-1)
    
    # Add module info to sfConfig so it can be used by the UI
    sfConfig['__modules__'] = sfModules
    # Add descriptions of the global config options
    sfConfig['__globaloptdescs__'] = sfOptdescs

    # Start the web server so you can start looking at results
    print "Starting web server at http://" + sfConfig['__webaddr'] + \
        ":" + str(sfConfig['__webport']) + "..."

    cherrypy.config.update({
        'server.socket_host': sfConfig['__webaddr'],
        'server.socket_port': sfConfig['__webport']
    })

    # Disable auto-reloading of content
    cherrypy.engine.autoreload.unsubscribe()

    # Enable access to static files via the web directory
    currentDir = os.path.abspath(sf.myPath())
    conf = { '/static': { 
        'tools.staticdir.on': True,
        'tools.staticdir.dir': os.path.join(currentDir, 'static')
    }}
                        
    # Try starting the web server. If it fails due to a database being
    # missing, start a smaller web server just for setting up the DB.
    try:
        cherrypy.quickstart(SpiderFootWebUi(sfConfig), config=conf)
    except BaseException as e:
        cherrypy.quickstart(SpiderFootWebUiMini(sfConfig), config=conf)

