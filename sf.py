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
import signal
import time
import argparse
from copy import deepcopy

# Look under ext ford 3rd party dependencies
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile(inspect.currentframe()))[0], "lib")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

deps = ['M2Crypto', 'netaddr', 'dns', 'cherrypy', 'mako', 'socks', 'whois',
        'PyPDF2', 'openxmllib', 'stem', 'bs4', 'gexf', 'phonenumbers', 'ipaddr',
        'ipwhois']
for mod in deps:
    try:
        if mod.startswith("lib."):
            modname = mod.split('.')
            __import__('lib', fromlist=[modname[1]])
        else:
            __import__(mod)
    except ImportError as e:
        print("")
        print("Critical Start-up Failure: " + str(e))
        print("=================================")
        print("It appears you are missing a module required for SpiderFoot")
        print("to function. Please refer to the documentation for the list")
        print("of dependencies and install them.")
        print("")
        print("Python modules required are: ")
        for mod in deps:
            print(" - " + mod)
        print("")
        print("****************************************************************")
        print("Please note that if you are seeing this after doing a git pull")
        print("then you just need to do a `pip install -r requirements.txt` as")
        print("dependencies previously bundled with SpiderFoot are now")
        print("unbundled.")
        print("****************************************************************")
        print("")
        sys.exit(-1)

import os
import os.path
import cherrypy
import random
from cherrypy.lib import auth_digest
from sflib import SpiderFoot
from sfdb import SpiderFootDb
from sfwebui import SpiderFootWebUi
from sfscan import SpiderFootScanner

# 'Global' configuration options
# These can be overriden on a per-module basis, and some will
# be overridden from saved configuration settings stored in the DB.
sfConfig = {
    '_debug': False,  # Debug
    '__logging': True, # Logging in general
    '__outputfilter': None, # Event types to filter from modules' output
    '__blocknotif': False,  # Block notifications
    '_fatalerrors': False,
    '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',  # User-Agent to use for HTTP requests
    '_dnsserver': '',  # Override the default resolver
    '_fetchtimeout': 5,  # number of seconds before giving up on a fetch
    '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
    '_internettlds_cache': 72,
    '__version__': '3.0',
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
    '_torctlport': 9051,
    '__logstdout': False
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
    '_fatalerrors': "Abort the scan when modules encounter exceptions.",
    '_modulesenabled': "Modules enabled for the scan."  # This is a hack to get a description for an option not actually available.
}

scanId = None
dbh = None

def handle_abort(signal, frame):
    print("[*] Aborting...")
    if scanId and dbh:
        dbh.scanInstanceSet(scanId, None, None, "ABORTED")
    sys.exit(-1)

if __name__ == '__main__':
    # Legacy way to run the server
    args = None
    if (len(sys.argv) > 1 and ":" in sys.argv[1]) or len(sys.argv) == 1:
        if len(sys.argv) > 1:
            (addr, port) = sys.argv[1].split(":")
            sfConfig['__webaddr'] = addr
            sfConfig['__webport'] = int(port)
            sfConfig['__logstdout'] = False
    else:
        p = argparse.ArgumentParser(description='SpiderFoot 3.0: Open Source Intelligence Automation.')
        p.add_argument("-d", "--debug", action='store_true', help="Enable debug output.")
        p.add_argument("-m", metavar="mod1,mod2,...", type=str, help="Modules to enable.")
        p.add_argument("-M", "--modules", action='store_true', help="List available modules.")
        p.add_argument("-s", metavar="TARGET", help="Target for the scan.")
        p.add_argument("-t", metavar="type1,type2,...", type=str, help="Event types to collect.")
        p.add_argument("-T", "--types", action='store_true', help="List available event types.")
        p.add_argument("-o", metavar="tab|csv|json", type=str, help="Output format. Tab is default.")
        p.add_argument("-n", action='store_true', help="Strip newlines from data.")
        p.add_argument("-r", action='store_true', help="Include the source data field in tab/csv output.")
        p.add_argument("-S", metavar="LENGTH", type=int, help="Maximum data length to display. By default, all data is shown.")
        p.add_argument("-D", metavar='DELIMITER', type=str, help="Delimiter to use for CSV output. Default is ,.")
        p.add_argument("-f", action='store_true', help="Filter out other event types that weren't requested with -t.")
        p.add_argument("-F", metavar="FILTER", type=str, help="Filter out a set of event types.")
        p.add_argument("-x", action='store_true', help="STRICT MODE. Will only enable modules that can directly consume your target, and if -t was specified only those events will be consumed by modules. This overrides -t and -m options.")
        p.add_argument("-q", action='store_true', help="Disable logging.")
        args = p.parse_args()

        sfConfig['__logstdout'] = True
            
        if args.debug:
            sfConfig['_debug'] = True
        else:
            sfConfig['_debug'] = False

        if args.q:
            sfConfig['__logging'] = False


    sfModules = dict()
    sft = SpiderFoot(sfConfig)
    # Go through each module in the modules directory with a .py extension
    for filename in os.listdir(sft.myPath() + '/modules/'):
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
        print("No modules found in the modules directory.")
        sys.exit(-1)

    # Add module info to sfConfig so it can be used by the UI
    sfConfig['__modules__'] = sfModules
    # Add descriptions of the global config options
    sfConfig['__globaloptdescs__'] = sfOptdescs

    sf = SpiderFoot(sfConfig)
    dbh = SpiderFootDb(sfConfig, init=True)

    if args:
        if args.modules:
            print("Modules available:")
            for m in sorted(sfModules.keys()):
                if "__" in m:
                    continue
                print('{0:25}  {1}'.format(m, sfModules[m]['descr']))
            sys.exit(0)

        if args.types:
            print("Types available:")
            typedata = dbh.eventTypes()
            types = dict()
            for r in typedata:
                types[r[1]] = r[0]

            for t in sorted(types.keys()):
                print('{0:45}  {1}'.format(t, types[t]))
            sys.exit(0)

        if not args.s:
            print("You must specify a target when running in scan mode. Try sf.py --help for guidance.")
            sys.exit(-1)

        if args.x and not args.t:
            print("-x can only be used with -t. Use --help for guidance.")
            sys.exit(-1)

        if args.x and args.m:
            print("-x can only be used with -t and not with -m. Use --help for guidance.")
            sys.exit(-1)

        if args.r and (args.o and args.o not in ["tab", "csv"]):
            print("-r can only be used when your output format is tab or csv.")
            sys.exit(-1)

        if args.D and args.o != "csv":
            print("-D can only be used when using the csv output format.")
            sys.exit(-1)

        target = args.s
        targetType = sf.targetType(args.s)

        modlist = list()
        if not args.t and not args.m:
            print("WARNING: You didn't specify any modules or types, so all will be enabled.")
            for m in sfModules.keys():
                if "__" in m:
                    continue
                modlist.append(m)

        signal.signal(signal.SIGINT, handle_abort)
        # If the user is scanning by type..
        # 1. Find modules producing that type
        if args.t:
            types = args.t
            modlist = sf.modulesProducing(types)
            newmods = deepcopy(modlist)
            newmodcpy = deepcopy(newmods)

            # 2. For each type those modules consume, get modules producing
            while len(newmodcpy) > 0:
                for etype in sf.eventsToModules(newmodcpy):
                    xmods = sf.modulesProducing([etype])
                    for mod in xmods:
                        if mod not in modlist:
                            modlist.append(mod)
                            newmods.append(mod)
                newmodcpy = deepcopy(newmods)
                newmods = list()

        # Easier if scanning by module
        if args.m:
            modlist = args.m.split(",")

        # Add sfp__stor_stdout to the module list
        outputformat = "tab"
        typedata = dbh.eventTypes()
        types = dict()
        for r in typedata:
            types[r[1]] = r[0]

        sfConfig['__modules__']['sfp__stor_stdout']['opts']['_eventtypes'] = types
        if args.f:
            if args.f and not args.t:
                print("You can only use -f with -t. Use --help for guidance.")
                sys.exit(-1)
            sfConfig['__modules__']['sfp__stor_stdout']['opts']['_showonlyrequested'] = True
        if args.F:
            sfConfig['__modules__']['sfp__stor_stdout']['opts']['_requested'] = args.F.split(",")
            sfConfig['__modules__']['sfp__stor_stdout']['opts']['_showonlyrequested'] = True
        if args.o:
            sfConfig['__modules__']['sfp__stor_stdout']['opts']['_format'] = args.o
        if args.t:
            sfConfig['__modules__']['sfp__stor_stdout']['opts']['_requested'] = args.t.split(",")
        if args.n:
            sfConfig['__modules__']['sfp__stor_stdout']['opts']['_stripnewline'] = True
        if args.r:
            sfConfig['__modules__']['sfp__stor_stdout']['opts']['_showsource'] = True
        if args.S:
            sfConfig['__modules__']['sfp__stor_stdout']['opts']['_maxlength'] = args.S
        if args.D:
            sfConfig['__modules__']['sfp__stor_stdout']['opts']['_csvdelim'] = args.D
        if args.x:
            tmodlist = list()
            modlist = list()
            xmods = sf.modulesConsuming([targetType])
            for mod in xmods:
                if mod not in modlist:
                    tmodlist.append(mod)

            # Remove any modules not producing the type requested
            rtypes = args.t.split(",")
            for mod in tmodlist:
                for r in rtypes:
                    if not sfModules[mod]['provides']:
                        continue
                    if r in sfModules[mod].get('provides', []) and mod not in modlist:
                        modlist.append(mod)

        if len(modlist) == 0:
            print("Based on your criteria, no modules were enabled.")
            sys.exit(-1)

        modlist += ["sfp__stor_db", "sfp__stor_stdout"]

        # Run the scan
        if not args.q:
            print("[*] Modules enabled (" + str(len(modlist)) + "): " + ",".join(modlist))
        cfg = sf.configUnserialize(dbh.configGet(), sfConfig)
        scanId = sf.genScanInstanceGUID(target)

        # Debug mode is a variable that gets stored to the DB, so re-apply it
        if args.debug:
            cfg['_debug'] = True
        else:
            cfg['_debug'] = False

        # If strict mode is enabled, filter the output from modules.
        if args.x and args.t:
            cfg['__outputfilter'] = args.t.split(",")

        t = SpiderFootScanner(target, target, targetType, scanId,
            modlist, cfg, dict())
        t.daemon = True
        t.start()

        while True:
            info = dbh.scanInstanceGet(scanId)
            if not info:
                time.sleep(1)
                continue
            if info[5] in [ "ERROR-FAILED", "ABORT-REQUESTED", "ABORTED", "FINISHED" ]:
                if not args.q:
                    print("[*] Scan completed with status " + info[5])
                sys.exit(0)
            time.sleep(1)

        sys.exit(0)

    # Start the web server so you can start looking at results
    url = 'http://' + sfConfig['__webaddr'] + ":" + str(sfConfig['__webport']) + sfConfig['__docroot']
    print('Starting web server at %s ...' % url)

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

    passwd_file = sf.myPath() + '/passwd'
    if os.path.isfile(passwd_file):
        if not os.access(passwd_file, os.R_OK):
            print("Could not read passwd file. Permission denied.")
            sys.exit(-1)

        secrets = dict()

        pw = file(passwd_file, 'r')

        for line in pw.readlines():
            if ':' not in line:
                print("Incorrect format of passwd file, must be username:password on each line.")
                sys.exit(-1)

            u = line.strip().split(":")[0]
            p = ':'.join(line.strip().split(":")[1:])

            if not u or not p:
                print("Incorrect format of passwd file, must be username:password on each line.")
                sys.exit(-1)

            secrets[u] = p

        if secrets:
            print("Enabling authentication based on supplied passwd file.")
            conf['/'] = {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': sfConfig['__webaddr'],
                'tools.auth_digest.get_ha1': auth_digest.get_ha1_dict_plain(secrets),
                'tools.auth_digest.key': random.SystemRandom().randint(0, 99999999)
            }
        else:
            print("Warning: passwd file contains no passwords. Authentication disabled.")

    key_path = sf.myPath() + '/spiderfoot.key'
    crt_path = sf.myPath() + '/spiderfoot.crt'
    if os.path.isfile(key_path) and os.path.isfile(crt_path):
        if not os.access(crt_path, os.R_OK):
            print("Could not read spiderfoot.crt file. Permission denied.")
            sys.exit(-1)

        if not os.access(key_path, os.R_OK):
            print("Could not read spiderfoot.key file. Permission denied.")
            sys.exit(-1)

        print("Enabling SSL based on supplied key and certificate file.")
        cherrypy.server.ssl_module = 'builtin'
        cherrypy.server.ssl_certificate = crt_path
        cherrypy.server.ssl_private_key = key_path

    # Try starting the web server. If it fails due to a database being
    # missing, start a smaller web server just for setting up the DB.
    cherrypy.quickstart(SpiderFootWebUi(sfConfig), script_name=sfConfig['__docroot'], config=conf)
