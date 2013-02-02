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
    '__guid__':         None, # unique ID of scan. Will be set after start-up.
    '__modules__':        None # List of modules. Will be set after start-up.
}

if __name__ == '__main__':
    sf = SpiderFoot(sfConfig)
    sfModules = dict()

    # Go through each module in the modules directory with a .py extension
    for filename in os.listdir(os.path.dirname(__file__) + '/modules/'):
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

    if len(sfModules.keys()) < 1:
        print "No modules found in the modules directory."
        sys.exit(-1)
    
    # Add module info to sfConfig so it can be used by the UI
    sfConfig['__modules__'] = sfModules

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
