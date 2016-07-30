#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sf
# Purpose:      Main wrapper for calling all SpiderFoot modules
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     03/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

import sys
import os
import inspect

# Look under ext ford 3rd party dependencies
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile(inspect.currentframe()))[0], "ext")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

deps = ['M2Crypto', 'netaddr', 'dns', 'cherrypy', 'mako', 'socks',
        'pyPdf', 'metapdf', 'openxmllib', 'stem', 'bs4', 'gexf', 'phonenumbers']
for mod in deps:
    try:
        if mod.startswith("ext."):
            modname = mod.split('.')
            __import__('ext', fromlist=[modname[1]])
        else:
            __import__(mod)
    except ImportError as e:
        print ""
        print "Critical Start-up Failure: " + str(e)
        print "================================="
        print "It appears you are missing a module required for SpiderFoot"
        print "to function. Please refer to the documentation for the list"
        print "of dependencies and install them."
        print ""
        print "Python modules required are: "
        for mod in deps:
            print " - " + mod
        print ""
        print "If you are running on Windows and getting this error, please"
        print "report this as a bug to support@spiderfoot.net."
        print ""
        sys.exit(-1)

import os
import os.path
import cherrypy
import random
from cherrypy.lib import auth_digest
from sflib import SpiderFoot
from sfwebui import SpiderFootWebUi

# 'Global' configuration options
# These can be overriden on a per-module basis, and some will
# be overridden from saved configuration settings stored in the DB.
sfConfig = {
    '_debug': False,  # Debug
    '__blocknotif': False,  # Block notifications
    '_useragent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20100101 Firefox/23.0',  # User-Agent to use for HTTP requests
    '_dnsserver': '',  # Override the default resolver
    '_fetchtimeout': 5,  # number of seconds before giving up on a fetch
    '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
    '_internettlds_cache': 72,
    '__database': 'spiderfoot.db',
    '__webaddr': '127.0.0.1',
    '__webport': 5001,
    '__docroot': '',  # don't put trailing /
    '__modules__': None,  # List of modules. Will be set after start-up.
    '_socks1type': '',
    '_socks2addr': '',
    '_socks3port': '',
    '_socks4user': '',
    '_socks5pwd': '',
    '_socks6dns': True,
    '_torctlport': 9051
}

sfOptdescs = {
    '_debug': "Enable debugging?",
    '_internettlds': "List of Internet TLDs.",
    '_internettlds_cache': "Hours to cache the Internet TLD list. This can safely be quite a long time given that the list doesn't change too often.",
    '_useragent': "User-Agent string to use for HTTP requests. Prefix with an '@' to randomly select the User Agent from a file containing user agent strings for each request, e.g. @C:\useragents.txt or @/home/bob/useragents.txt. Or supply a URL to load the list from there.",
    '_dnsserver': "Override the default resolver with another DNS server. For example, 8.8.8.8 is Google's open DNS server.",
    '_fetchtimeout': "Number of seconds before giving up on a HTTP request.",
    '_socks1type': "SOCKS Server Type. Can be '4', '5', 'HTTP' or 'TOR'",
    '_socks2addr': 'SOCKS Server IP Address.',
    '_socks3port': 'SOCKS Server TCP Port. Usually 1080 for 4/5, 8080 for HTTP and 9050 for TOR.',
    '_socks4user': 'SOCKS Username. Valid only for SOCKS4 and SOCKS5 servers.',
    '_socks5pwd': "SOCKS Password. Valid only for SOCKS5 servers.",
    '_socks6dns': "Resolve DNS through the SOCKS proxy? Has no affect when TOR is used: Will always be True.",
    '_torctlport': "The port TOR is taking control commands on. This is necessary for SpiderFoot to tell TOR to re-circuit when it suspects anonymity is compromised.",
    '_modulesenabled': "Modules enabled for the scan."  # This is a hack to get a description for an option not actually available.
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
            sfModules[modName]['name'] = sfModules[modName]['object'].__doc__.split(":", 5)[0]
            sfModules[modName]['cats'] = sfModules[modName]['object'].__doc__.split(":", 5)[1].split(",")
            sfModules[modName]['group'] = sfModules[modName]['object'].__doc__.split(":", 5)[2]
            sfModules[modName]['labels'] = sfModules[modName]['object'].__doc__.split(":", 5)[3].split(",")
            sfModules[modName]['descr'] = sfModules[modName]['object'].__doc__.split(":", 5)[4]
            sfModules[modName]['provides'] = sfModules[modName]['object'].producedEvents()
            sfModules[modName]['consumes'] = sfModules[modName]['object'].watchedEvents()
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
          ":" + str(sfConfig['__webport']) + sfConfig['__docroot'] + " ..."

    cherrypy.config.update({
        'server.socket_host': sfConfig['__webaddr'],
        'server.socket_port': sfConfig['__webport']
    })

    # Disable auto-reloading of content
    cherrypy.engine.autoreload.unsubscribe()

    # Enable access to static files via the web directory
    currentDir = os.path.abspath(sf.myPath())
    conf = {'/static': {
        'tools.staticdir.on': True,
        'tools.staticdir.dir': os.path.join(currentDir, 'static')
    }}

    if os.path.isfile(sf.myPath() + '/passwd'):
        secrets = dict()
        pw = file(sf.myPath() + '/passwd', 'r')
        for line in pw.readlines():
            u, p = line.strip().split(":")
            if None in [u, p]:
                print "Incorrect format of passwd file, must be username:password on each line."
                sys.exit(-1)
            secrets[u] = p

        print "Enabling authentication based on supplied passwd file."
        conf['/'] = {
            'tools.auth_digest.on': True,
            'tools.auth_digest.realm': sfConfig['__webaddr'],
            'tools.auth_digest.get_ha1': auth_digest.get_ha1_dict_plain(secrets),
            'tools.auth_digest.key': random.randint(0, 99999999)
        }

    if os.path.isfile(sf.myPath() + '/spiderfoot.key') and \
       os.path.isfile(sf.myPath() + '/spiderfoot.crt'):
        print "Enabling SSL based on supplied key and certificate file."
        cherrypy.server.ssl_module = 'builtin'
        cherrypy.server.ssl_certificate = sf.myPath() + '/spiderfoot.crt'
        cherrypy.server.ssl_private_key = sf.myPath() + '/spiderfoot.key'

    # Try starting the web server. If it fails due to a database being
    # missing, start a smaller web server just for setting up the DB.
    cherrypy.quickstart(SpiderFootWebUi(sfConfig), script_name=sfConfig['__docroot'], config=conf)
