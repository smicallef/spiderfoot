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
        'pyPdf', 'metapdf', 'openxmllib', 'stem', 'OpenSSL']
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
import cherrypy
import json
from cherrypy.lib import auth_digest
from sflib import SpiderFoot
from sfwebui import SpiderFootWebUi
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join

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

#declare an empty dict
usersDict = {}

#SSL certificate file names
CERT_FILE = "spiderfoot.crt"
KEY_FILE = "spiderfoot.key"

#New SSL cert function
def create_self_signed_cert(cert_dir):
    """
    If datacard.crt and datacard.key don't exist in cert_dir, create a new
    self-signed cert and keypair and write them into that directory.
    """

    if not exists(join(cert_dir, CERT_FILE)) \
            or not exists(join(cert_dir, KEY_FILE)):

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "Alaska"
        cert.get_subject().L = "Anchorage"
        cert.get_subject().O = "SpiderFoot"
        cert.get_subject().OU = "Spiderfoot"
        cert.get_subject().CN = gethostname()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        open(join(cert_dir, CERT_FILE), "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        open(join(cert_dir, KEY_FILE), "wt").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

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
            sfModules[modName]['name'] = sfModules[modName]['object'].__doc__.split(":", 3)[0]
            sfModules[modName]['cats'] = sfModules[modName]['object'].__doc__.split(":", 3)[1].split(",")
            sfModules[modName]['descr'] = sfModules[modName]['object'].__doc__.split(":", 3)[2]
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

    # Load the users from the secrets file
    try:
        userCounter = 0
        data = json.loads(open('secrets').read())
        for user in data["users"]:
            username = (user["username"]).encode('utf-8')
            password = (user["password"]).encode('utf-8')
            usersDict.update({username:password})
            userCounter += 1
        print "Loaded " + str(userCounter) + " users from secrets file"
    except Exception, e:
        print "Caught error while reading secrets file: " + str(e)
        print "Using admin admin login"
        usersDict.update({"admin":"admin"})

    #Create the SSL certificate if you have a valid certificate comment out these lines
    #and set the path to your certificate and key with certPath and keyPath
    currentDir = os.path.realpath(os.path.abspath(os.path.split(inspect.getfile(inspect.currentframe()))[0]))
    create_self_signed_cert(currentDir)
    certPath = currentDir + "/" + CERT_FILE
    keyPath = currentDir + "/" + KEY_FILE

    #Add the certificates to the server
    cherrypy.server.ssl_module = 'builtin'
    cherrypy.server.ssl_certificate = certPath
    cherrypy.server.ssl_private_key = keyPath

    # Enable access to static files via the web directory and add basic auth
    currentDir = os.path.abspath(sf.myPath())
    conf = {'/static': {
        'tools.staticdir.on': True,
        'tools.staticdir.dir': os.path.join(currentDir, 'static')},
        '/': {
        'tools.auth_digest.on': True,
        'tools.auth_digest.realm': sfConfig['__webaddr'],
        'tools.auth_digest.get_ha1': auth_digest.get_ha1_dict_plain(usersDict),
        'tools.auth_digest.key': 'a565c27146791cfb'
    }}

    # Try starting the web server. If it fails due to a database being
    # missing, start a smaller web server just for setting up the DB.
    cherrypy.quickstart(SpiderFootWebUi(sfConfig), script_name=sfConfig['__docroot'], config=conf)
