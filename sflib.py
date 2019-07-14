# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sflib
# Purpose:      Common functions used by SpiderFoot modules.
#               Also defines the SpiderFootPlugin abstract class for modules.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     26/03/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

from stem import Signal
from stem.control import Controller
import inspect
import hashlib
import binascii
import gzip
import gexf
import json
import re
import os
import random
import requests
import socket
import ssl
import sys
import time
import netaddr
import urllib2
import StringIO
import threading
import traceback
from bs4 import BeautifulSoup, SoupStrainer
from copy import deepcopy, copy

# For hiding the SSL warnings coming from the requests lib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SpiderFoot:
    dbh = None
    GUID = None
    savedsock = socket
    urllib2.savedsock = urllib2.socket

    # 'options' is a dictionary of options which changes the behaviour
    # of how certain things are done in this module
    # 'handle' will be supplied if the module is being used within the
    # SpiderFoot GUI, in which case all feedback should be fed back
    def __init__(self, options, handle=None):
        self.handle = handle
        self.opts = deepcopy(options)
        # This is ugly but we don't want any fetches to fail - we expect
        # to encounter unverified SSL certs!
        if sys.version_info >= (2, 7, 9):
            ssl._create_default_https_context = ssl._create_unverified_context

    # Bit of a hack to support SOCKS because of the loading order of
    # modules. sfscan will call this to update the socket reference
    # to the SOCKS one.
    def updateSocket(self, sock):
        socket = sock
        urllib2.socket = sock

    def revertSocket(self):
        socket = self.savedsock
        urllib2.socket = urllib2.savedsock

    # Tell TOR to re-circuit
    def refreshTorIdent(self):
        if self.opts['_socks1type'] != "TOR":
            return None

        try:
            self.info("Re-circuiting TOR...")
            with Controller.from_port(address=self.opts['_socks2addr'], 
                                      port=self.opts['_torctlport']) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                time.sleep(10)
        except BaseException as e:
            self.fatal("Unable to re-circuit TOR: " + str(e))

    # Supplied an option value, return the data based on what the
    # value is. If val is a URL, you'll get back the fetched content,
    # if val is a file path it will be loaded and get back the contents,
    # and if a string it will simply be returned back.
    def optValueToData(self, val, fatal=True, splitLines=True):
        if val.startswith('@'):
            fname = val.split('@')[1]
            try:
                self.info("Loading configuration data from: " + fname)
                f = open(fname, "r")
                if splitLines:
                    arr = f.readlines()
                    ret = list()
                    for x in arr:
                        ret.append(x.rstrip('\n'))
                else:
                    ret = f.read()
                return ret
            except BaseException as b:
                if fatal:
                    self.error("Unable to open option file, " + fname + ".")
                else:
                    return None

        if val.lower().startswith('http://') or val.lower().startswith('https://'):
            try:
                self.info("Downloading configuration data from: " + val)
                res = urllib2.urlopen(val)
                data = res.read()
                if splitLines:
                    return data.splitlines()
                else:
                    return data
            except BaseException as e:
                if fatal:
                    self.error("Unable to open option URL, " + val + ": " + str(e))
                else:
                    return None

        return val

    # Return a format-agnostic collection of tuples to use as the
    # basis for building graphs in various formats.
    def buildGraphData(self, data, flt=list()):
        mapping = set()
        entities = dict()
        parents = dict()

        def get_next_parent_entities(item, pids):
            ret = list()

            for [parent, id] in parents[item]:
                if id in pids:
                    continue
                if parent in entities:
                    ret.append(parent)
                else:
                    pids.append(id)
                    for p in get_next_parent_entities(parent, pids):
                        ret.append(p)
            return ret

        for row in data:
            if row[11] == "ENTITY" or row[11] == "INTERNAL":
                # List of all valid entity values
                if len(flt) > 0:
                    if row[4] in flt or row[11] == "INTERNAL":
                        entities[row[1]] = True
                else:
                    entities[row[1]] = True

            if row[1] not in parents:
                parents[row[1]] = list()
            parents[row[1]].append([row[2], row[8]])

        for entity in entities:
            for [parent, id] in parents[entity]:
                if parent in entities:
                    if entity != parent:
                        #print("Adding entity parent: " + parent)
                        mapping.add((entity, parent))
                else:
                    ppids = list()
                    #print("Checking " + parent + " for entityship.")
                    next_parents = get_next_parent_entities(parent, ppids)
                    for next_parent in next_parents:
                        if entity != next_parent:
                            #print("Adding next entity parent: " + next_parent)
                            mapping.add((entity, next_parent))
        return mapping

    # Convert supplied raw data into GEXF format (e.g. for Gephi)
    # GEXF produced by PyGEXF doesn't work with SigmaJS because
    # SJS needs coordinates for each node. 
    # flt is a list of event types to include, if not set everything is
    # included.
    def buildGraphGexf(self, root, title, data, flt=[]):
        mapping = self.buildGraphData(data, flt)
        g = gexf.Gexf(title, title)
        graph = g.addGraph("undirected", "static", "SpiderFoot Export")

        nodelist = dict()
        ecounter = 0
        ncounter = 0
        for pair in mapping:
            (dst, src) = pair
            col = ["0", "0", "0"]

            # Leave out this special case
            if dst == "ROOT" or src == "ROOT":
                continue
            if dst not in nodelist:
                ncounter = ncounter + 1
                if dst in root:
                    col = ["255", "0", "0"]
                graph.addNode(str(ncounter), unicode(dst, errors="replace"),
                              r=col[0], g=col[1], b=col[2])    
                nodelist[dst] = ncounter

            if src not in nodelist:
                ncounter = ncounter + 1
                if src in root:
                    col = ["255", "0", "0"]
                graph.addNode(str(ncounter), unicode(src, errors="replace"),
                              r=col[0], g=col[1], b=col[2])
                nodelist[src] = ncounter

            ecounter = ecounter + 1
            graph.addEdge(str(ecounter), str(nodelist[src]), str(nodelist[dst]))

        output = StringIO.StringIO()
        g.write(output)
        return output.getvalue()

    # Convert supplied raw data into JSON format for SigmaJS
    def buildGraphJson(self, root, data, flt=list()):
        mapping = self.buildGraphData(data, flt)
        ret = dict()
        ret['nodes'] = list()
        ret['edges'] = list()

        nodelist = dict()
        ecounter = 0
        ncounter = 0
        for pair in mapping:
            (dst, src) = pair
            col = "#000"

            # Leave out this special case
            if dst == "ROOT" or src == "ROOT":
                continue
            if dst not in nodelist:
                ncounter = ncounter + 1
                if dst in root:
                    col = "#f00"
                ret['nodes'].append({'id': str(ncounter), 
                                    'label': unicode(dst, errors="replace"),
                                    'x': random.randint(1,1000),
                                    'y': random.randint(1,1000),
                                    'size': "1",
                                    'color': col
                })
                nodelist[dst] = ncounter

            if src not in nodelist:
                if src in root:
                    col = "#f00"
                ncounter = ncounter + 1
                ret['nodes'].append({'id': str(ncounter), 
                                    'label': unicode(src, errors="replace"),
                                    'x': random.randint(1,1000),
                                    'y': random.randint(1,1000),
                                    'size': "1",
                                    'color': col
                })
                nodelist[src] = ncounter

            ecounter = ecounter + 1
            ret['edges'].append({'id': str(ecounter), 
                                'source': str(nodelist[src]), 
                                'target': str(nodelist[dst])
            })

        return json.dumps(ret)

    # Called usually some time after instantiation
    # to set up a database handle and scan GUID, used
    # for logging events to the database about a scan.
    def setDbh(self, handle):
        self.dbh = handle

    # Set the GUID this instance of SpiderFoot is being
    # used in.
    def setGUID(self, uid):
        self.GUID = uid

    # Generate an globally unique ID for this scan
    def genScanInstanceGUID(self, scanName):
 #       hashStr = hashlib.sha256(
 #           scanName +
 #           str(time.time() * 1000) +
 #           str(random.randint(100000, 999999))
 #       ).hexdigest()
        rstr = str(time.time()) + str(random.randint(100000, 999999))
        hashStr = "%08X" % int(binascii.crc32(rstr) & 0xffffffff)
        return hashStr

    def _dblog(self, level, message, component=None):
        #print(str(self.GUID) + ":" + str(level) + ":" + str(message) + ":" + str(component))
        return self.dbh.scanLogEvent(self.GUID, level, message, component)

    def error(self, error, exception=True):
        if not self.opts['__logging']:
            return None

        if self.dbh is None:
            print('[Error] ' + error)
        else:
            self._dblog("ERROR", error)
        if self.opts.get('__logstdout'):
            print("[Error] " + error)
        if exception:
            raise BaseException("Internal Error Encountered: " + error)

    def fatal(self, error):
        if self.dbh is None:
            print('[Fatal] ' + error)
        else:
            self._dblog("FATAL", error)
        print(str(inspect.stack()))
        sys.exit(-1)

    def status(self, message):
        if not self.opts['__logging']:
            return None

        if self.dbh is None:
            print("[Status] " + message)
        else:
            self._dblog("STATUS", message)
        if self.opts.get('__logstdout'):
            print("[*] " + message)

    def info(self, message):
        if not self.opts['__logging']:
            return None

        frm = inspect.stack()[1]
        mod = inspect.getmodule(frm[0])

        if mod is None:
            modName = "Unknown"
        else:
            if mod.__name__ == "sflib":
                frm = inspect.stack()[2]
                mod = inspect.getmodule(frm[0])
                if mod is None:
                    modName = "Unknown"
                else:
                    modName = mod.__name__
            else:
                modName = mod.__name__

        if self.dbh is None:
            print('[' + modName + '] ' + message)
        else:
            self._dblog("INFO", message, modName)
        if self.opts.get('__logstdout'):
            print("[*] " + message)
        return

    def debug(self, message):
        if not self.opts['_debug']:
            return
        if not self.opts['__logging']:
            return None
        frm = inspect.stack()[1]
        mod = inspect.getmodule(frm[0])

        if mod is None:
            modName = "Unknown"
        else:
            if mod.__name__ == "sflib":
                frm = inspect.stack()[2]
                mod = inspect.getmodule(frm[0])
                if mod is None:
                    modName = "Unknown"
                else:
                    modName = mod.__name__
            else:
                modName = mod.__name__

        if self.dbh is None:
            print('[' + modName + '] ' + message)
        else:
            self._dblog("DEBUG", message, modName)
        if self.opts.get('__logstdout'):
            print("[d:" + modName +"] " + message)
        return

    def myPath(self):
        # This will get us the program's directory, even if we are frozen using py2exe.

        # Determine whether we've been compiled by py2exe
        if hasattr(sys, "frozen"):
            return os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding()))

        return os.path.dirname(unicode(__file__, sys.getfilesystemencoding()))

    def hashstring(self, string):
        s = string
        if type(string) in [list, dict]:
            s = str(string)
        if type(s) == str:
            s = unicode(s, 'utf-8', errors='replace')
        return hashlib.sha256(s.encode('raw_unicode_escape')).hexdigest()

    #
    # Caching
    #

    # Return the cache path
    def cachePath(self):
        path = self.myPath() + '/cache'
        if not os.path.isdir(path):
            os.mkdir(path)
        return path

    # Store data to the cache
    def cachePut(self, label, data):
        pathLabel = hashlib.sha224(label).hexdigest()
        cacheFile = self.cachePath() + "/" + pathLabel
        fp = file(cacheFile, "w")
        if type(data) is list:
            for line in data:
                fp.write(line + '\n')
        else:
            data = data.encode('utf-8')
            fp.write(data)
        fp.close()

    # Retreive data from the cache
    def cacheGet(self, label, timeoutHrs):
        pathLabel = hashlib.sha224(label).hexdigest()
        cacheFile = self.cachePath() + "/" + pathLabel
        try:
            (m, i, d, n, u, g, sz, atime, mtime, ctime) = os.stat(cacheFile)

            if sz == 0:
                return None

            if mtime > time.time() - timeoutHrs * 3600 or timeoutHrs == 0:
                fp = file(cacheFile, "r")
                fileContents = fp.read()
                fp.close()
                fileContents = fileContents.decode('utf-8')
                return fileContents
            else:
                return None
        except BaseException as e:
            return None

    #
    # Configuration process
    #

    # Convert a Python dictionary to something storable
    # in the database.
    def configSerialize(self, opts, filterSystem=True):
        storeopts = dict()

        for opt in opts.keys():
            # Filter out system temporary variables like GUID and others
            if opt.startswith('__') and filterSystem:
                continue

            if type(opts[opt]) is int or type(opts[opt]) is str:
                storeopts[opt] = opts[opt]

            if type(opts[opt]) is bool:
                if opts[opt]:
                    storeopts[opt] = 1
                else:
                    storeopts[opt] = 0
            if type(opts[opt]) is list:
                storeopts[opt] = ','.join(opts[opt])

        if '__modules__' not in opts:
            return storeopts

        for mod in opts['__modules__']:
            for opt in opts['__modules__'][mod]['opts']:
                if opt.startswith('_') and filterSystem:
                    continue

                if type(opts['__modules__'][mod]['opts'][opt]) is int or \
                                type(opts['__modules__'][mod]['opts'][opt]) is str:
                    storeopts[mod + ":" + opt] = opts['__modules__'][mod]['opts'][opt]

                if type(opts['__modules__'][mod]['opts'][opt]) is bool:
                    if opts['__modules__'][mod]['opts'][opt]:
                        storeopts[mod + ":" + opt] = 1
                    else:
                        storeopts[mod + ":" + opt] = 0
                if type(opts['__modules__'][mod]['opts'][opt]) is list:
                    storeopts[mod + ":" + opt] = ','.join(str(x) \
                                                          for x in opts['__modules__'][mod]['opts'][opt])

        return storeopts

    # Take strings, etc. from the database or UI and convert them
    # to a dictionary for Python to process.
    # referencePoint is needed to know the actual types the options
    # are supposed to be.
    def configUnserialize(self, opts, referencePoint, filterSystem=True):
        returnOpts = referencePoint

        # Global options
        for opt in referencePoint.keys():
            if opt.startswith('__') and filterSystem:
                # Leave out system variables
                continue
            if opt in opts:
                if type(referencePoint[opt]) is bool:
                    if opts[opt] == "1":
                        returnOpts[opt] = True
                    else:
                        returnOpts[opt] = False

                if type(referencePoint[opt]) is str:
                    returnOpts[opt] = str(opts[opt])

                if type(referencePoint[opt]) is int:
                    returnOpts[opt] = int(opts[opt])

                if type(referencePoint[opt]) is list:
                    if type(referencePoint[opt][0]) is int:
                        returnOpts[opt] = list()
                        for x in str(opts[opt]).split(","):
                            returnOpts[opt].append(int(x))
                    else:
                        returnOpts[opt] = str(opts[opt]).split(",")

        if '__modules__' not in referencePoint:
            return returnOpts

        # Module options
        # A lot of mess to handle typing..
        for modName in referencePoint['__modules__']:
            for opt in referencePoint['__modules__'][modName]['opts']:
                if opt.startswith('_') and filterSystem:
                    continue
                if modName + ":" + opt in opts:
                    if type(referencePoint['__modules__'][modName]['opts'][opt]) is bool:
                        if opts[modName + ":" + opt] == "1":
                            returnOpts['__modules__'][modName]['opts'][opt] = True
                        else:
                            returnOpts['__modules__'][modName]['opts'][opt] = False

                    if type(referencePoint['__modules__'][modName]['opts'][opt]) is str:
                        returnOpts['__modules__'][modName]['opts'][opt] = \
                            str(opts[modName + ":" + opt])

                    if type(referencePoint['__modules__'][modName]['opts'][opt]) is int:
                        returnOpts['__modules__'][modName]['opts'][opt] = \
                            int(opts[modName + ":" + opt])

                    if type(referencePoint['__modules__'][modName]['opts'][opt]) is list:
                        if type(referencePoint['__modules__'][modName]['opts'][opt][0]) is int:
                            returnOpts['__modules__'][modName]['opts'][opt] = list()
                            for x in str(opts[modName + ":" + opt]).split(","):
                                returnOpts['__modules__'][modName]['opts'][opt].append(int(x))
                        else:
                            returnOpts['__modules__'][modName]['opts'][opt] = \
                                str(opts[modName + ":" + opt]).split(",")

        return returnOpts

    # Return the type for a scan
    def targetType(self, target):
        targetType = None

        regexToType = [
            {"^\d+\.\d+\.\d+\.\d+$": "IP_ADDRESS"},
            {"^\d+\.\d+\.\d+\.\d+/\d+$": "NETBLOCK_OWNER"},
            {"^.*@.*$": "EMAILADDR"},
            {"^\+\d+$": "PHONE_NUMBER"},
            {"^\".*\"$": "HUMAN_NAME"},
            {"^\d+$": "BGP_AS_OWNER"},
            {"^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)+([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$": "INTERNET_NAME"}
        ]

        # Parse the target and set the targetType
        for rxpair in regexToType:
            rx = rxpair.keys()[0]
            if re.match(rx, target, re.IGNORECASE|re.UNICODE):
                targetType = rxpair.values()[0]
                break
        return targetType

    # Return an array of module names for returning the
    # types specified.
    def modulesProducing(self, events):
        modlist = list()
        for mod in self.opts['__modules__'].keys():
            if self.opts['__modules__'][mod]['provides'] is None:
                continue

            for evtype in self.opts['__modules__'][mod]['provides']:
                if evtype in events and mod not in modlist:
                    modlist.append(mod)
                if "*" in events and mod not in modlist:
                    modlist.append(mod)

        return modlist

    # Return an array of modules that consume the types
    # specified.
    def modulesConsuming(self, events):
        modlist = list()
        for mod in self.opts['__modules__'].keys():
            if self.opts['__modules__'][mod]['consumes'] is None:
                continue
            
            if "*" in self.opts['__modules__'][mod]['consumes'] and mod not in modlist:
                modlist.append(mod)

            for evtype in self.opts['__modules__'][mod]['consumes']:
                if evtype in events and mod not in modlist:
                    modlist.append(mod)

        return modlist

    # Return an array of types that are produced by the list
    # of modules supplied.
    def eventsFromModules(self, modules):
        evtlist = list()
        for mod in modules:
            if mod in self.opts['__modules__'].keys():
                if self.opts['__modules__'][mod]['provides'] is not None:
                    for evt in self.opts['__modules__'][mod]['provides']:
                        evtlist.append(evt)

        return evtlist

    # Return an array of types that are consumed by the list
    # of modules supplied.
    def eventsToModules(self, modules):
        evtlist = list()
        for mod in modules:
            if mod in self.opts['__modules__'].keys():
                if self.opts['__modules__'][mod]['consumes'] is not None:
                    for evt in self.opts['__modules__'][mod]['consumes']:
                        evtlist.append(evt)

        return evtlist

    #
    # URL parsing functions
    #

    # Turn a relative path into an absolute path
    def urlRelativeToAbsolute(self, url):
        finalBits = list()

        if '..' not in url:
            return url

        bits = url.split('/')

        for chunk in bits:
            if chunk == '..':
                # Don't pop the last item off if we're at the top
                if len(finalBits) <= 1:
                    continue

                # Don't pop the last item off if the first bits are not the path
                if '://' in url and len(finalBits) <= 3:
                    continue

                finalBits.pop()
                continue

            finalBits.append(chunk)

        #self.debug('xfrmed rel to abs path: ' + url + ' to ' + '/'.join(finalBits))
        return '/'.join(finalBits)

    # Extract the top level directory from a URL
    def urlBaseDir(self, url):

        bits = url.split('/')

        # For cases like 'www.somesite.com'
        if len(bits) == 0:
            #self.debug('base dir of ' + url + ' not identified, using URL as base.')
            return url + '/'

        # For cases like 'http://www.blah.com'
        if '://' in url and url.count('/') < 3:
            #self.debug('base dir of ' + url + ' is: ' + url + '/')
            return url + '/'

        base = '/'.join(bits[:-1])
        #self.debug('base dir of ' + url + ' is: ' + base + '/')
        return base + '/'

    # Extract the scheme and domain from a URL
    # Does not return the trailing slash! So you can do .endswith()
    # checks.
    def urlBaseUrl(self, url):
        if '://' in url:
            bits = re.match('(\w+://.[^/:\?]*)[:/\?].*', url)
        else:
            bits = re.match('(.[^/:\?]*)[:/\?]', url)

        if bits is None:
            return url.lower()

        #self.debug('base url of ' + url + ' is: ' + bits.group(1))
        return bits.group(1).lower()

    # Extract the FQDN from a URL
    def urlFQDN(self, url):
        baseurl = self.urlBaseUrl(url)
        if '://' not in baseurl:
            count = 0
        else:
            count = 2

        # http://abc.com will split to ['http:', '', 'abc.com']
        return baseurl.split('/')[count].lower()

    # Extract the keyword (the domain without the TLD or any subdomains)
    # from a domain.
    def domainKeyword(self, domain, tldList):
        # Strip off the TLD
        tld = '.'.join(self.hostDomain(domain.lower(), tldList).split('.')[1:])
        ret = domain.lower().replace('.' + tld, '')

        # If the user supplied a domain with a sub-domain, return the second part
        if '.' in ret:
            return ret.split('.')[-1]
        else:
            return ret

    # Extract the keywords (the domains without the TLD or any subdomains)
    # from a list of domains.
    def domainKeywords(self, domainList, tldList):
        arr = list()
        for domain in domainList:
            # Strip off the TLD
            tld = '.'.join(self.hostDomain(domain.lower(), tldList).split('.')[1:])
            ret = domain.lower().replace('.' + tld, '')

            # If the user supplied a domain with a sub-domain, return the second part
            if '.' in ret:
                arr.append(ret.split('.')[-1])
            else:
                arr.append(ret)

        self.debug("Keywords: " + str(arr))
        return arr

    # Obtain the domain name for a supplied hostname
    # tldList needs to be an array based on the Mozilla public list
    def hostDomain(self, hostname, tldList):
        ps = PublicSuffixList(tldList)
        return ps.get_public_suffix(hostname)

    # Simple way to verify IPs.
    def validIP(self, address):
        return netaddr.valid_ipv4(address)

    # Clean DNS results to be a simple list
    def normalizeDNS(self, res):
        ret = list()
        for addr in res:
            if type(addr) == list:
                for host in addr:
                    ret.append(unicode(host, 'utf-8', errors='replace'))
            else:
                ret.append(unicode(addr, 'utf-8', errors='replace'))
        return ret

    # Verify input is OK to execute
    def sanitiseInput(self, cmd):
        chars = ['a','b','c','d','e','f','g','h','i','j','k','l','m',
         'n','o','p','q','r','s','t','u','v','w','x','y','z',
         '0','1','2','3','4','5','6','7','8','9','-','.'] 
        for c in cmd:
            if c.lower() not in chars:
                return False

        if '..' in cmd:
            return False

        if cmd.startswith("-"):
            return False

        if len(cmd) < 3:
            return False

        return True

    # Return dictionary words and/or names
    def dictwords(self):
        wd = dict()

        dicts = [ "english", "german", "french", "spanish" ]

        for d in dicts:
            wdct = open(self.myPath() + "/dicts/ispell/" + d + ".dict", 'r')
            dlines = wdct.readlines()

            for w in dlines:
                w = w.strip().lower()
                wd[w.split('/')[0]] = True

        return wd.keys()

    # Return dictionary names
    def dictnames(self):
        wd = dict()

        dicts = [ "names" ]

        for d in dicts:
            wdct = open(self.myPath() + "/dicts/ispell/" + d + ".dict", 'r')
            dlines = wdct.readlines()

            for w in dlines:
                w = w.strip().lower()
                wd[w.split('/')[0]] = True

        return wd.keys()


    # Converts a dictionary of k -> array to a nested
    # tree that can be digested by d3 for visualizations.
    def dataParentChildToTree(self, data):
        def get_children(needle, haystack):
            #print("called")
            ret = list()

            if needle not in haystack.keys():
                return None

            if haystack[needle] is None:
                return None

            for c in haystack[needle]:
                #print("found child of " + needle + ": " + c)
                ret.append({"name": c, "children": get_children(c, haystack)})
            return ret

        # Find the element with no parents, that's our root.
        root = None
        for k in data.keys():
            if data[k] is None:
                continue

            contender = True
            for ck in data.keys():
                if data[ck] is None:
                    continue

                if k in data[ck]:
                    contender = False

            if contender:
                root = k
                break

        if root is None:
            #print("*BUG*: Invalid structure - needs to go back to one root.")
            final = {}
        else:
            final = {"name": root, "children": get_children(root, data)}

        return final

    #
    # General helper functions to automate many common tasks between modules
    #

    # Parse the contents of robots.txt, returns a list of patterns
    # which should not be followed
    def parseRobotsTxt(self, robotsTxtData):
        returnArr = list()

        # We don't check the User-Agent rule yet.. probably should at some stage

        for line in robotsTxtData.splitlines():
            if line.lower().startswith('disallow:'):
                m = re.match('disallow:\s*(.[^ #]*)', line, re.IGNORECASE)
                self.debug('robots.txt parsing found disallow: ' + m.group(1))
                returnArr.append(m.group(1))
                continue

        return returnArr

    # Find all URLs within the supplied content. This does not fetch any URLs!
    # A dictionary will be returned, where each link will have the keys
    # 'source': The URL where the link was obtained from
    # 'original': What the link looked like in the content it was obtained from
    # The key will be the *absolute* URL of the link obtained, so for example if
    # the link '/abc' was obtained from 'http://xyz.com', the key in the dict will
    # be 'http://xyz.com/abc' with the 'original' attribute set to '/abc'
    def parseLinks(self, url, data, domains, parseText=True):
        returnLinks = dict()
        urlsRel = []

        if type(domains) is str:
            domains = [domains]

        tags = {
                    'a': 'href',
                    'img': 'src',
                    'script': 'src',
                    'link': 'href',
                    'area': 'href',
                    'base': 'href',
                    'form': 'action'
        }

        try:
            proto = url.split(":")[0]
        except BaseException as e:
            proto = "http"
        if proto == None:
            proto = "http"

        if data is None or len(data) == 0:
            self.debug("parseLinks() called with no data to parse.")
            return None

        try:
            for t in tags.keys():
                for lnk in BeautifulSoup(data, "lxml",
                    parse_only=SoupStrainer(t)).find_all(t):
                    if lnk.has_attr(tags[t]):
                        urlsRel.append([None, lnk[tags[t]]])
        except BaseException as e:
            self.error("Error parsing with BeautifulSoup: " + str(e), False)
            return None

        # Find potential links that aren't links (text possibly in comments, etc.)
        parsedata = urllib2.unquote(data.lower())

        if parseText:
            # Find chunks of text encapsulating the data we care about
            offset = parsedata.find("http")
            regRelurl = re.compile('()(https?://.[a-zA-Z0-9\-\.\:\/_]+[^<\"\'])')
            while offset >= 0:
                offset = parsedata.find("http", offset)
                #print "found at offset: " + str(offset)
                if offset < 0:
                    break

                # Get the trailing part for urls (some URLs are big..)
                chunkurl = parsedata[offset:(offset+2000)]

                try:
                    m = regRelurl.findall(chunkurl)
                    urlsRel.extend(regRelurl.findall(chunkurl))
                except Exception as e:
                    self.error("Error applying regex3 to data (" + str(e) + ")", False)
                offset += len("http")

        # Internal links
        for domain in domains:
            if parseText:
                # Find chunks of text encapsulating the data we care about
                offset = parsedata.find(domain)
                if offset < 0:
                    #print "skipping " + domain
                    continue

                # If the text started with the domain, then start from after it
                if offset == 0:
                    offset += len(domain)

                try:
                    regRelhost = re.compile('(.)([a-z0-9\-\.]+\.' + domain + ')', re.IGNORECASE)
                    regRelurl = re.compile('([>\"])([a-zA-Z0-9\-\.\:\/]+\.' + domain + '/.[^<\"]+)', re.IGNORECASE)
                except BaseException as e:
                    self.error("Unable to form proper regexp trying to parse " + domain, False)
                    continue

                while offset >= 0:
                    offset = parsedata.find(domain, offset)
                    #print "found at offset: " + str(offset)
                    if offset < 0:
                        break

                    # Get 200 bytes before the domain to try and get hostnames
                    chunkhost = parsedata[(offset-200):(offset+len(domain)+1)]
                    # Get the trailing part for urls (some URLs are big..)
                    chunkurl = parsedata[(offset-200):(offset+len(domain)+2000)]

                    try:
                        urlsRel.extend(regRelhost.findall(chunkhost))
                    except Exception as e:
                        self.error("Error applying regex2 to data (" + str(e) + ")", False)

                    try:
                        urlsRel.extend(regRelurl.findall(chunkurl))
                    except Exception as e:
                        self.error("Error applying regex3 to data (" + str(e) + ")", False)

                    offset += len(domain)

        # Loop through all the URLs/links found
        for linkTuple in urlsRel:
            # Remember the regex will return two vars (two groups captured)
            junk = linkTuple[0]
            link = linkTuple[1]
            if type(link) != unicode:
                link = unicode(link, 'utf-8', errors='replace')
            linkl = link.lower()
            absLink = None

            if len(link) < 1:
                continue

            # Don't include stuff likely part of some dynamically built incomplete
            # URL found in Javascript code (character is part of some logic)
            if link[len(link) - 1] == '.' or link[0] == '+' or \
                            'javascript:' in linkl or '()' in link:
                self.debug('unlikely link: ' + link)
                continue
            # Filter in-page links
            if re.match('.*#.[^/]+', link):
                self.debug('in-page link: ' + link)
                continue

            # Ignore mail links
            if 'mailto:' in linkl:
                self.debug("Ignoring mail link: " + link)
                continue

            # URL decode links
            if '%2f' in linkl:
                link = urllib2.unquote(link)

            # Capture the absolute link:
            # If the link contains ://, it is already an absolute link
            if '://' in link:
                absLink = link

            # If the link starts with a /, the absolute link is off the base URL
            if link.startswith('/'):
                absLink = self.urlBaseUrl(url) + link

            # Protocol relative URLs
            if link.startswith('//'):
                absLink = proto + ':' + link

            # Maybe the domain was just mentioned and not a link, so we make it one
            if absLink is None and domain.lower() in link.lower():
                absLink = proto + '://' + link

            # Otherwise, it's a flat link within the current directory
            if absLink is None:
                absLink = self.urlBaseDir(url) + link

            # Translate any relative pathing (../)
            absLink = self.urlRelativeToAbsolute(absLink)
            returnLinks[absLink] = {'source': url, 'original': link}

        return returnLinks

    def urlEncodeUnicode(self, url):
        return re.sub('[\x80-\xFF]', lambda c: '%%%02x' % ord(c.group(0)), url)

    # Fetch a URL, return the response object
    def fetchUrl(self, url, fatal=False, cookies=None, timeout=30,
                 useragent="SpiderFoot", headers=None, noLog=False, 
                 postData=None, dontMangle=False, sizeLimit=None,
                 headOnly=False, verify=False):
        result = {
            'code': None,
            'status': None,
            'content': None,
            'headers': None,
            'realurl': url
        }

        if url is None:
            return None

        # Clean the URL
        if type(url) != unicode:
            url = unicode(url, 'utf-8', errors='replace')

        # Convert any unicode chars in the URL
        url = str(self.urlEncodeUnicode(url))

        try:
            header = dict()
            if type(useragent) is list:
                header['User-Agent'] = random.choice(useragent)
            else:
                header['User-Agent'] = useragent

            # Add custom headers
            if headers is not None:
                for k in headers.keys():
                    header[k] = headers[k]

            if sizeLimit or headOnly:
                if not noLog:
                    self.info("Fetching (HEAD only): " + url + \
                          " [timeout: " + \
                          str(timeout) + "]")

                hdr = requests.head(url, headers=header, verify=verify, timeout=timeout)
                size = int(hdr.headers.get('content-length', 0))
                result['realurl'] = hdr.headers.get('location', url)
                result['code'] = str(hdr.status_code)

                if headOnly:
                    return result

                if size > sizeLimit:
                    return result

                if result['realurl'] != url:
                    if not noLog:
                       self.info("Fetching (HEAD only): " + url + \
                              " [timeout: " + \
                              str(timeout) + "]")

                    hdr = requests.head(result['realurl'], headers=header, verify=verify)
                    size = int(hdr.headers.get('content-length', 0))
                    result['realurl'] = hdr.headers.get('location', result['realurl'])
                    result['code'] = str(hdr.status_code)

                    if size > sizeLimit:
                        return result

            req = urllib2.Request(url, postData, header)
            if cookies is not None:
                req.add_header('cookie', cookies)
                if not noLog:
                    self.info("Fetching (incl. cookies): " + url + \
                          " [timeout: " + \
                          str(timeout) + "]")
            else:
                if not noLog:
                    self.info("Fetching: " + url + " [timeout: " + str(timeout) + "]")


            result['headers'] = dict()
            opener = urllib2.build_opener(SmartRedirectHandler())
            fullPage = opener.open(req, timeout=timeout)
            content = fullPage.read()

            for k, v in fullPage.info().items():
                result['headers'][k.lower()] = v

            # Content is compressed
            if 'gzip' in result['headers'].get('content-encoding', ''):
                content = gzip.GzipFile(fileobj=StringIO.StringIO(content)).read()

            if dontMangle:
                result['content'] = content
            else:
                result['content'] = unicode(content, 'utf-8', errors='replace')

            #print("FOR: " + url)
            #print("HEADERS: " + str(result['headers']))
            result['realurl'] = fullPage.geturl()
            result['code'] = str(fullPage.getcode())
            result['status'] = 'OK'
        except urllib2.HTTPError as h:
            if not noLog:
                self.info("HTTP code " + str(h.code) + " encountered for " + url)
            # Capture the HTTP error code
            result['code'] = str(h.code)
            for k, v in h.info().items():
                result['headers'][k.lower()] = v
            if fatal:
                self.fatal('URL could not be fetched (' + str(h.code) + ')')
        except urllib2.URLError as e:
            if not noLog:
                self.info("Error fetching " + url + "(" + str(e) + ")")
            result['status'] = str(e)
            if fatal:
                self.fatal('URL could not be fetched (' + str(e) + ')')
        except Exception as x:
            if not noLog:
                self.info("Unexpected exception occurred fetching: " + url + " (" + str(x) + ")")
            result['content'] = None
            result['status'] = str(x)
            if fatal:
                self.fatal('URL could not be fetched (' + str(x) + ')')

        return result

    # Check if wildcard DNS is enabled by looking up two random hostnames
    def checkDnsWildcard(self, target):
        randpool = 'bcdfghjklmnpqrstvwxyz3456789'
        randhost = ''.join([random.choice(randpool) for x in range(10)])

        # An exception will be raised if the resolution fails
        try:
            addrs = socket.gethostbyname_ex(randhost + "." + target)
            return True
        except BaseException as e:
            return False

    # Scrape Google for content, starting at startUrl and iterating through
    # results based on options supplied. Will return a dictionary of all pages
    # fetched and their contents {page => content}.
    # Options accepted:
    # limit: number of search result pages before returning, default is 10
    # nopause: don't randomly pause between fetches
    # useragent: User-Agent string to use
    # timeout: Fetch timeout
    def googleIterate(self, searchString, opts=dict()):
        limit = 10
        fetches = 0
        returnResults = dict()

        if 'limit' in opts:
            limit = opts['limit']

        # We attempt to make the URL look as authentically human as possible
        seedUrl = u"https://www.google.com/search?q={0}".format(searchString) + \
                  u"&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:en-US:official&client=firefox-a"

        attempts = 0
        failed = False
        while attempts < 3:
            firstPage = self.fetchUrl(seedUrl, timeout=opts['timeout'],
                                      useragent=opts['useragent'])
            if firstPage['code'] == "403" or firstPage['code'] == "503":
                self.error("Google doesn't like us right now..", False)
                failed = True

            if firstPage['content'] is None:
                self.error("Failed to fetch content from Google.", False)
                failed = True
            else:
                if "name=\"captcha\"" in firstPage['content']:
                    self.error("Google returned a CAPTCHA.", False)
                    failed = True

            if failed:
                self.refreshTorIdent()
                attempts += 1
                failed = False
            else:
                break

        if attempts == 3:
            return None
                                
        returnResults[seedUrl] = firstPage['content']
        pat = re.compile("(\/search\S+start=\d+.[^\'\"]*sa=N)", re.IGNORECASE)
        matches = re.findall(pat, firstPage['content'])

        while matches > 0 and fetches < limit:
            nextUrl = None
            fetches += 1
            for match in matches:
                # Google moves in increments of 10
                if "start=" + str(fetches * 10) in match:
                    nextUrl = match.replace("&amp;", "&")

            if nextUrl is None:
                self.debug("Nothing left to scan for in Google results.")
                return returnResults
            self.info("Next Google URL: " + nextUrl)

            # Wait for a random number of seconds between fetches
            if 'nopause' not in opts:
                pauseSecs = random.randint(4, 15)
                self.info("Pausing for " + str(pauseSecs))
                time.sleep(pauseSecs)

            attempts = 0
            failed = False
            while attempts < 3:
                nextPage = self.fetchUrl(u'https://www.google.com' + nextUrl,
                                         timeout=opts['timeout'], useragent=opts['useragent'])
                if nextPage['code'] == "403" or nextPage['code'] == "503":
                    self.error("Google doesn't like us right now..", False)
                    failed = True

                if nextPage['content'] is None:
                    self.error("Failed to fetch subsequent content from Google.", False)
                    failed = True
                else:
                    if "name=\"captcha\"" in nextPage['content']:
                        self.error("Google returned a CAPTCHA.", False)
                        failed = True

                if failed:
                    self.refreshTorIdent()
                    attempts += 1
                    failed = False
                else:
                    break

            if attempts == 3:
                return returnResults

            returnResults[nextUrl] = nextPage['content']
            pat = re.compile("(\/search\S+start=\d+.[^\'\"]*)", re.IGNORECASE)
            matches = re.findall(pat, nextPage['content'])

        return returnResults

    # Scrape Bing for content, starting at startUrl and iterating through
    # results based on options supplied. Will return a dictionary of all pages
    # fetched and their contents {page => content}.
    # Options accepted:
    # limit: number of search result pages before returning, default is 10
    # nopause: don't randomly pause between fetches
    # useragent: User-Agent string to use
    # timeout: Fetch timeout
    def bingIterate(self, searchString, opts=dict()):
        limit = 10
        fetches = 0
        returnResults = dict()

        if 'limit' in opts:
            limit = opts['limit']

        # We attempt to make the URL look as authentically human as possible
        seedUrl = u"http://www.bing.com/search?q={0}".format(searchString) + \
                  u"&pc=MOZI"

        attempts = 0
        failed = False
        while attempts < 3:
            firstPage = self.fetchUrl(seedUrl, timeout=opts['timeout'],
                                      useragent=opts['useragent'])
            if firstPage['code'] == "400":
                self.error("Bing doesn't like us right now..", False)
                failed = True

            if firstPage['content'] is None:
                self.error("Failed to fetch content from Bing.", False)
                failed = True
            else:
                if "/challengepic?" in firstPage['content']:
                    self.error("Bing returned a CAPTCHA.", False)
                    failed = True

            if failed:
                self.refreshTorIdent()
                attempts += 1
                failed = False
            else:
                break

        if attempts == 3:
            return None

        returnResults[seedUrl] = firstPage['content']
        pat = re.compile("(\/search\S+first=\d+.[^\'\"]*FORM=\S+)", re.IGNORECASE)
        matches = re.findall(pat, firstPage['content'])
        while matches > 0 and fetches < limit:
            nextUrl = None
            fetches += 1
            for match in matches:
                # Bing moves in increments of 10
                if "first=" + str((fetches * 10) + 1) in match:
                    nextUrl = match.replace("&amp;", "&").replace("%3a", ":")

            if nextUrl is None:
                self.debug("Nothing left to scan for in Bing results.")
                return returnResults
            self.info("Next Bing URL: " + nextUrl)

            # Wait for a random number of seconds between fetches
            if 'nopause' not in opts:
                pauseSecs = random.randint(4, 15)
                self.info("Pausing for " + str(pauseSecs))
                time.sleep(pauseSecs)

            attempts = 0
            while attempts < 3:
                nextPage = self.fetchUrl(u'https://www.bing.com' + nextUrl,
                                         timeout=opts['timeout'], useragent=opts['useragent'])
                if nextPage['code'] == "400":
                    self.error("Bing doesn't like us any more..", False)
                    failed = True

                if nextPage['content'] is None:
                    self.error("Failed to fetch subsequent content from Bing.", False)
                    failed = True
                else:
                    if "/challengepic?" in firstPage['content']:
                        self.error("Bing returned a CAPTCHA.", False)
                        failed = True

                if failed:
                    self.refreshTorIdent()
                    attempts += 1
                    failed = False
                else:
                    break

            if attempts == 3:
                return returnResults

            returnResults[nextUrl] = nextPage['content']
            pat = re.compile("(\/search\S+first=\d+.[^\'\"]*)", re.IGNORECASE)
            matches = re.findall(pat, nextPage['content'])

        return returnResults

# SpiderFoot plug-in module base class
#
class SpiderFootPlugin(object):
    # Will be set to True by the controller if the user aborts scanning
    _stopScanning = False
    # Modules that will be notified when this module produces events
    _listenerModules = list()
    # Current event being processed
    _currentEvent = None
    # Target currently being acted against
    _currentTarget = None
    # Name of this module, set at startup time
    __name__ = "module_name_not_set!"
    # Direct handle to the database - not to be directly used
    # by modules except the sfp__stor_db module.
    __sfdb__ = None
    # ID of the scan the module is running against
    __scanId__ = None
    # (Unused) tracking of data sources
    __dataSource__ = None
    # If set, events not matching this list are dropped
    __outputFilter__ = None

    # Not really needed in most cases.
    def __init__(self):
        pass

    # Hack to override module's use of socket, replacing it with
    # one that uses the supplied SOCKS server
    def _updateSocket(self, sock):
        socket = sock
        urllib2.socket = sock

    # Used to clear any listener relationships, etc. This is needed because
    # Python seems to cache local variables even between threads.
    def clearListeners(self):
        self._listenerModules = list()
        self._stopScanning = False

    # Will always be overriden by the implementer.
    def setup(self, sf, userOpts=dict()):
        pass

    # Hardly used, only in special cases where a module can find
    # aliases for a target.
    def enrichTarget(self, target):
        pass

    # Assigns the current target this module is acting against
    def setTarget(self, target):
        self._currentTarget = target

    # Used to set the database handle, which is only to be used
    # by modules in very rare/exceptional cases (e.g. sfp__stor_db)
    def setDbh(self, dbh):
        self.__sfdb__ = dbh

    # Set the scan ID
    def setScanId(self, id):
        self.__scanId__ = id

    # Get the scan ID
    def getScanId(self):
        return self.__scanId__

    # Gets the current target this module is acting against
    def getTarget(self):
        if self._currentTarget is None:
            print("Internal Error: Module called getTarget() but no target set.")
            sys.exit(-1)
        return self._currentTarget

    # Listener modules which will get notified once we have data for them to
    # work with.
    def registerListener(self, listener):
        self._listenerModules.append(listener)

    def setOutputFilter(self, types):
        self.__outputFilter__ = types

    # For SpiderFoot HX compatability of modules
    def tempStorage(self):
        return dict()

    # Call the handleEvent() method of every other plug-in listening for
    # events from this plug-in. Remember that those plug-ins will be called
    # within the same execution context of this thread, not on their own.
    def notifyListeners(self, sfEvent):
        eventName = sfEvent.eventType

        if self.__outputFilter__:
            # Be strict about what events to pass on, unless they are
            # the ROOT event or the event type of the target.
            if eventName != 'ROOT' and eventName != self.getTarget().getType() \
                and eventName not in self.__outputFilter__:
                return None

        # Convert strings to unicode
        if type(sfEvent.data) == str:
            sfEvent.data = unicode(sfEvent.data, 'utf-8', errors='replace')

        storeOnly = False  # Under some conditions, only store and don't notify

        if sfEvent.data is None or (type(sfEvent.data) is unicode and len(sfEvent.data) == 0):
            #print("No data to send for " + eventName + " to " + listener.__module__)
            return None

        if self.checkForStop():
            return None

        # Look back to ensure the original notification for an element
        # is what's linked to children. For instance, sfp_dns may find
        # xyz.abc.com, and then sfp_ripe obtains some raw data for the
        # same, and then sfp_dns finds xyz.abc.com in there, we should
        # suppress the notification of that to other modules, as the
        # original xyz.abc.com notification from sfp_dns will trigger
        # those modules anyway. This also avoids messy iterations that
        # traverse many many levels.

        # storeOnly is used in this case so that the source to dest
        # relationship is made, but no further events are triggered
        # from dest, as we are already operating on dest's original
        # notification from one of the upstream events.

        prevEvent = sfEvent.sourceEvent
        while prevEvent is not None:
            if prevEvent.sourceEvent is not None:
                if prevEvent.sourceEvent.eventType == sfEvent.eventType and \
                                prevEvent.sourceEvent.data.lower() == sfEvent.data.lower():
                    #print("Skipping notification of " + sfEvent.eventType + " / " + sfEvent.data)
                    storeOnly = True
                    break
            prevEvent = prevEvent.sourceEvent

        self._listenerModules.sort()
        for listener in self._listenerModules:
            #print(listener.__module__ + ": " + listener.watchedEvents().__str__())
            if eventName not in listener.watchedEvents() and '*' not in listener.watchedEvents():
                #print(listener.__module__ + " not listening for " + eventName)
                continue

            if storeOnly and "__stor" not in listener.__module__:
                #print("Storing only for " + sfEvent.eventType + " / " + sfEvent.data)
                continue

            #print("Notifying " + eventName + " to " + listener.__module__)
            listener._currentEvent = sfEvent

            # Check if we've been asked to stop in the meantime, so that
            # notifications stop triggering module activity.
            if self.checkForStop():
                return None

            #print("EVENT: " + str(sfEvent))
            try:
                listener.handleEvent(sfEvent)
            except BaseException as e:
                f = open("sferror.log", "a")
                f.write("Module (" + listener.__module__ + ") encountered an error: " + str(e) + "\n")
                
                exc_type, exc_value, exc_traceback = sys.exc_info()
                f.write(repr(traceback.format_exception(exc_type, exc_value, exc_traceback)))
                f.close()

    # For modules to use to check for when they should give back control
    def checkForStop(self):
        global globalScanStatus

        if globalScanStatus.getStatus(self.__scanId__) == "ABORT-REQUESTED":
            return True
        return False

    # Return a list of the default configuration options for the module.
    def defaultOpts(self):
        return self.opts

    # What events is this module interested in for input. The format is a list
    # of event types that are applied to event types that this module wants to
    # be notified of, or * if it wants everything.
    # Will usually be overriden by the implementer, unless it is interested
    # in all events (default behavior).
    def watchedEvents(self):
        return ['*']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return None

    # Handle events to this module
    # Will usually be overriden by the implementer, unless it doesn't handle
    # any events.
    def handleEvent(self, sfEvent):
        return None

    # Kick off the work (for some modules nothing will happen here, but instead
    # the work will start from the handleEvent() method.
    # Will usually be overriden by the implementer.
    def start(self):
        return None


# Class for targets
class SpiderFootTarget(object):
    _validTypes = ["IP_ADDRESS", "NETBLOCK_OWNER", "INTERNET_NAME",
                   "EMAILADDR", "HUMAN_NAME", "BGP_AS_OWNER", 'PHONE_NUMBER']
    targetType = None
    targetValue = None
    targetAliases = list()

    def __init__(self, targetValue, typeName):
        if typeName in self._validTypes:
            self.targetType = typeName
            if type(targetValue) != unicode:
                self.targetValue = unicode(targetValue, 'utf-8', errors='replace').lower()
            else:
                self.targetValue = targetValue
            self.targetAliases = list()
        else:
            print("Internal Error: Invalid target type.")
            sys.exit(-1)

    def getType(self):
        return self.targetType

    def getValue(self):
        return self.targetValue

    # Specify other hostnames, IPs, etc. that are aliases for
    # this target.
    # For instance, if the user searched for an ASN, a module
    # might supply all the nested subnets as aliases.
    # Or, if a user searched for an IP address, a module
    # might supply the hostname as an alias.
    def setAlias(self, value, typeName):
        if {'type': typeName, 'value': value} in self.targetAliases:
            return None

        self.targetAliases.append(
            {'type': typeName, 'value': value.lower()}
        )

    def getAliases(self):
        return self.targetAliases

    def _getEquivalents(self, typeName):
        ret = list()
        for item in self.targetAliases:
            if item['type'] == typeName:
                ret.append(item['value'].lower())
        return ret

    # Get all domains associated with the target
    def getNames(self):
        e = self._getEquivalents("INTERNET_NAME")
        if self.targetType == "INTERNET_NAME" and self.targetValue.lower() not in e:
            e.append(self.targetValue.lower())
        return e

    # Get all IP Subnets or IP Addresses associated with the target
    def getAddresses(self):
        e = self._getEquivalents("IP_ADDRESS")
        if self.targetType == "IP_ADDRESS":
            e.append(self.targetValue)
        return e

    # Check whether the supplied value is "tightly" related
    # to the original target.
    # Tightly in this case means:
    #   1. If the value is an IP:
    #       1.1 is it in the list of aliases or the target itself?
    #       1.2 is it on the target's subnet?
    #   2. If the value is a name (subdomain, domain, hostname):
    #       2.1 is it in the list of aliases or the target itself?
    #       2.2 is it a parent of the aliases of the target (domain/subdomain)
    #       2.3 is it a child of the aliases of the target (hostname)
    # Arguments:
    # * value can be an Internet Name (hostname, subnet, domain)
    # or an IP address.
    # * includeParents = True means you consider a value that is
    # a parent domain of the target to still be a tight relation.
    # * includeChildren = False means you don't consider a value
    # that is a child of the target to be a tight relation.
    def matches(self, value, includeParents=False, includeChildren=True):
        value = value.lower()

        if value is None or value == "":
            return False

        # We can't really say anything about names or phone numbers, so everything matches
        if self.targetType == "HUMAN_NAME" or self.targetType == "PHONE_NUMBER":
            return True

        if netaddr.valid_ipv4(value):
            # 1.1
            if value in self.getAddresses():
                return True
            # 1.2
            if self.targetType == "NETBLOCK_OWNER":
                if netaddr.IPAddress(value) in netaddr.IPNetwork(self.targetValue):
                    return True
            if self.targetType == "IP_ADDRESS":
                if netaddr.IPAddress(value) in \
                        netaddr.IPNetwork(netaddr.IPAddress(self.targetValue)):
                    return True
        else:
            for name in self.getNames():
                # 2.1
                if value == name:
                    return True
                # 2.2            
                if includeParents and name.endswith("." + value):
                    return True
                # 2.3
                if includeChildren and value.endswith("." + name):
                    return True

        return None


# Class for SpiderFoot Events
class SpiderFootEvent(object):
    generated = None
    eventType = None
    confidence = None
    visibility = None
    risk = None
    module = None
    data = None
    sourceEvent = None
    sourceEventHash = None
    moduleDataSource = None
    __id = None

    def __init__(self, eventType, data, module, sourceEvent,
                 confidence=100, visibility=100, risk=0):
        self.eventType = eventType
        self.generated = time.time()
        self.confidence = confidence
        self.visibility = visibility
        self.risk = risk
        self.module = module
        self.sourceEvent = sourceEvent

        if type(data) in [ list, dict ]:
            print("FATAL: Only string events are accepted, not lists or dicts.")
            print("FATAL: Offending module: " + module)
            print("FATAL: Offending type: " + eventType)
            sys.exit(-1)

        if type(data) != unicode and data != None:
            self.data = unicode(data, 'utf-8', errors='replace')
        else:
            self.data = data

        # "ROOT" is a special "hash" reserved for elements with no
        # actual parent (e.g. the first page spidered.)
        if eventType == "ROOT":
            self.sourceEventHash = "ROOT"
            return

        self.sourceEventHash = sourceEvent.getHash()
        self.__id = self.eventType + str(self.generated) + self.module + \
                    str(random.randint(0, 99999999))

    def asDict(self):
        return {
            'generated': int(self.generated),
            'type': self.eventType,
            'data': self.data,
            'module': self.module,
            'source': self.sourceEvent.data
        }

    # Unique hash of this event
    def getHash(self):
        if self.eventType == "ROOT":
            return "ROOT"
        digestStr = self.__id.encode('raw_unicode_escape')
        return hashlib.sha256(digestStr).hexdigest()

    # Update variables as new information becomes available
    def setConfidence(self, confidence):
        self.confidence = confidence

    def setVisibility(self, visibility):
        self.visibility = visibility

    def setRisk(self, risk):
        self.risk = risk

    def setSourceEventHash(self, srcHash):
        self.sourceEventHash = srcHash


# Override the default redirectors to re-use cookies
class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers):
        if "Set-Cookie" in headers:
            req.add_header('cookie', headers['Set-Cookie'])
        result = urllib2.HTTPRedirectHandler.http_error_301(
            self, req, fp, code, msg, headers)
        return result

    def http_error_302(self, req, fp, code, msg, headers):
        if "Set-Cookie" in headers:
            req.add_header('cookie', headers['Set-Cookie'])
        result = urllib2.HTTPRedirectHandler.http_error_302(
            self, req, fp, code, msg, headers)
        return result


"""
Public Suffix List module for Python.
See LICENSE.tp for applicable license.
"""


class PublicSuffixList(object):
    def __init__(self, input_data):
        """Reads and parses public suffix list.

        input_file is a file object or another iterable that returns
        lines of a public suffix list file. If input_file is None, an
        UTF-8 encoded file named "publicsuffix.txt" in the same
        directory as this Python module is used.

        The file format is described at http://publicsuffix.org/list/
        """

        #if input_file is None:
        #input_path = os.path.join(os.path.dirname(__file__), 'publicsuffix.txt')
        #input_file = codecs.open(input_path, "r", "utf8")

        root = self._build_structure(input_data)
        self.root = self._simplify(root)

    def _find_node(self, parent, parts):
        if not parts:
            return parent

        if len(parent) == 1:
            parent.append({})

        assert len(parent) == 2
        negate, children = parent

        child = parts.pop()

        child_node = children.get(child, None)

        if not child_node:
            children[child] = child_node = [0]

        return self._find_node(child_node, parts)

    def _add_rule(self, root, rule):
        if rule.startswith('!'):
            negate = 1
            rule = rule[1:]
        else:
            negate = 0

        parts = rule.split('.')
        self._find_node(root, parts)[0] = negate

    def _simplify(self, node):
        if len(node) == 1:
            return node[0]

        return (node[0], dict((k, self._simplify(v)) for (k, v) in node[1].items()))

    def _build_structure(self, fp):
        root = [0]

        for line in fp:
            line = line.strip()
            if line.startswith('//') or not line:
                continue

            self._add_rule(root, line.split()[0].lstrip('.'))

        return root

    def _lookup_node(self, matches, depth, parent, parts):
        if parent in (0, 1):
            negate = parent
            children = None
        else:
            negate, children = parent

        matches[-depth] = negate

        if depth < len(parts) and children:
            for name in ('*', parts[-depth]):
                child = children.get(name, None)
                if child is not None:
                    self._lookup_node(matches, depth + 1, child, parts)

    def get_public_suffix(self, domain):
        """get_public_suffix("www.example.com") -> "example.com"

        Calling this function with a DNS name will return the
        public suffix for that name.

        Note that for internationalized domains the list at
        http://publicsuffix.org uses decoded names, so it is
        up to the caller to decode any Punycode-encoded names.
        """

        parts = domain.lower().lstrip('.').split('.')
        hits = [None] * len(parts)

        self._lookup_node(hits, 1, self.root, parts)

        for i, what in enumerate(hits):
            if what is not None and what == 0:
                return '.'.join(parts[i:])


# Class for tracking the status of all running scans. Thread safe.
class SpiderFootScanStatus:
    statusTable = dict()
    lock = threading.Lock()

    def setStatus(self, scanId, status):
        with self.lock:
            self.statusTable[scanId] = status

    def getStatus(self, scanId):
        with self.lock:
            if scanId in self.statusTable:
                return self.statusTable[scanId]
            return None

    def getStatusAll(self):
        with self.lock:
            return self.statusTable

# Global variable accessed by various places to get the status of
# running scans.
globalScanStatus = SpiderFootScanStatus()

