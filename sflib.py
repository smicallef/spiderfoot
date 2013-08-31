#-------------------------------------------------------------------------------
# Name:         sflib
# Purpose:      Common functions used by SpiderFoot modules.
#               Also defines the SpiderFootPlugin abstract class for modules.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     26/03/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import inspect
import hashlib
import re
import os
import random
import sys
import time
import urllib2

class SpiderFoot:
    dbh = None
    scanGUID = None

    # 'options' is a dictionary of options which changes the behaviour
    # of how certain things are done in this module
    # 'handle' will be supplied if the module is being used within the
    # SpiderFoot GUI, in which case all feedback should be fed back
    def __init__(self, options, handle=None):
        self.handle = handle
        self.opts = options

        # For the useragent option, if the user has supplied a path,
        # open the file and load into options['__useragent_list']
        if "_useragent" in options.keys():
            if options["_useragent"].startswith("@"):
                fname = options["_useragent"].split('@')[1]
                try:
                    f = open(fname, "r")
                    options['__useragent_list'] = f.readlines()
                except BaseException as b:
                    self.error("Unable to open User Agent file, " + fname + ".")
                    options["__useragent_list"] = [ "Unknown" ]

    #
    # Debug, error message and logging functions
    #

    # Called usually some time after instantiation
    # to set up a database handle and scan GUID, used
    # for logging events to the database about a scan.
    def setDbh(self, handle):
        self.dbh = handle

    def setScanId(self, id):
        self.scanGUID = id

    def _dblog(self, level, message, component=None):
        return self.dbh.scanLogEvent(self.scanGUID, level, message, component)

    def error(self, error, exception=True):
        if self.dbh == None:
            print '[Error] ' + error
        else:
            self._dblog("ERROR", error)
        if exception:
            raise BaseException("Internal Error Encountered: " + error)

    def fatal(self, error):
        if self.dbh == None:
            print '[Fatal] ' + error
        else:
            self._dblog("FATAL", error)
        raise BaseException("Fatal Error Encountered: " + error)
        exit(-1)

    def status(self, message):
        if self.dbh == None:
            print "[Status] " + message
        else:
            self._dblog("STATUS", message)

    def info(self, message):
        frm = inspect.stack()[1]
        mod = inspect.getmodule(frm[0])

        if mod == None:
            modName = "Unknown"
        else:
            modName = mod.__name__

        if self.dbh == None:
            print '[' + modName + '] ' + message
        else:
            self._dblog("INFO", message, modName)
        return

    def debug(self, message):
        if self.opts['_debug'] == False:
            return
        frm = inspect.stack()[1]
        mod = inspect.getmodule(frm[0])

        if mod == None:
            modName = "Unknown"
        else:
            modName = mod.__name__

        if self.dbh == None:
            print '[' + modName + '] ' + message
        else:
            self._dblog("DEBUG", message, modName)
        return

    def myPath(self):
        """ This will get us the program's directory,
        even if we are frozen using py2exe"""

        # Determine whether we've been compiled by py2exe
        if hasattr(sys, "frozen"):
            return os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding( )))

        return os.path.dirname(unicode(__file__, sys.getfilesystemencoding( )))


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

        if not opts.has_key('__modules__'):
            return storeopts

        for mod in opts['__modules__']:
            for opt in opts['__modules__'][mod]['opts']:
                if opt.startswith('_') and filterSystem:
                    continue

                if type(opts['__modules__'][mod]['opts'][opt]) is int or type(opts['__modules__'][mod]['opts'][opt]) is str:
                    storeopts[mod + ":" + opt] = opts['__modules__'][mod]['opts'][opt]

                if type(opts['__modules__'][mod]['opts'][opt]) is bool:
                    if opts['__modules__'][mod]['opts'][opt]:
                        storeopts[mod + ":" + opt] = 1
                    else:
                        storeopts[mod + ":" + opt] = 0
                if type(opts['__modules__'][mod]['opts'][opt]) is list:
                    storeopts[mod + ":" + opt] = ','.join(str(x) for x in opts['__modules__'][mod]['opts'][opt])

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
            if opts.has_key(opt):
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

        if not referencePoint.has_key('__modules__'):
            return returnOpts

        # Module options
        # A lot of mess to handle typing..
        for modName in referencePoint['__modules__']:
            for opt in referencePoint['__modules__'][modName]['opts']:
                if opt.startswith('_') and filterSystem:
                    continue
                if opts.has_key(modName + ":" + opt):
                    if type(referencePoint['__modules__'][modName]['opts'][opt]) is bool:
                        if opts[modName + ":" + opt] == "1":
                            returnOpts['__modules__'][modName]['opts'][opt] = True
                        else:
                            returnOpts['__modules__'][modName]['opts'][opt] = False

                    if type(referencePoint['__modules__'][modName]['opts'][opt]) is str:
                        returnOpts['__modules__'][modName]['opts'][opt] = str(opts[modName + ":" + opt])

                    if type(referencePoint['__modules__'][modName]['opts'][opt]) is int:
                        returnOpts['__modules__'][modName]['opts'][opt] = int(opts[modName + ":" + opt])

                    if type(referencePoint['__modules__'][modName]['opts'][opt]) is list:
                        if type(referencePoint['__modules__'][modName]['opts'][opt][0]) is int:
                            returnOpts['__modules__'][modName]['opts'][opt] = list()
                            for x in str(opts[modName + ":" + opt]).split(","):
                                returnOpts['__modules__'][modName]['opts'][opt].append(int(x))
                        else:
                            returnOpts['__modules__'][modName]['opts'][opt] = str(opts[modName + ":" + opt]).split(",")
        return returnOpts

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

        self.debug('xfrmed rel to abs path: ' + url + ' to ' + '/'.join(finalBits))
        return '/'.join(finalBits)

    # Extract the top level directory from a URL
    def urlBaseDir(self, url):

        bits = url.split('/')

        # For cases like 'www.somesite.com'
        if len(bits) == 0:
            self.debug('base dir of ' + url + ' not identified, using URL as base.')
            return url + '/'

        # For cases like 'http://www.blah.com'
        if '://' in url and url.count('/') < 3:
            self.debug('base dir of ' + url + ' is: ' + url + '/')
            return url + '/'

        base = '/'.join(bits[:-1])
        self.debug('base dir of ' + url + ' is: ' + base + '/')
        return base + '/'

    # Extract the scheme and domain from a URL
    # Does not return the trailing slash! So you can do .endswith()
    # checks.
    def urlBaseUrl(self, url):
        if '://' in url:
            bits = re.match('(\w+://.[^/:]*)[:/].*', url)
        else:
            bits = re.match('(.[^/:]*)[:/]', url)

        if bits == None:
            return url.lower()

        self.debug('base url of ' + url + ' is: ' + bits.group(1))
        return bits.group(1).lower()

    # Extract the FQDN from a URL
    def urlFQDN(self, url):
        baseurl = self.urlBaseUrl(url)
        # http://abc.com will split to ['http:', '', 'abc.com']
        return baseurl.split('/')[2].lower()

    # Extract the keyword (the domain without the TLD or any subdomains)
    # from a domain. Crude for now.. just gets the first word.
    def domainKeyword(self, domain):
        return domain.split('.', 2)[0].lower()

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
    def parseLinks(self, url, data, domain):
        returnLinks = dict()

        if data == None or len(data) == 0:
            self.debug('parseLinks() called with no data to parse')
            return None

        # Find actual links
        try:
            regRel = re.compile('(href|src|action|url)[:=][ \'\"]*(.[^\'\"<> ]*)',
                re.IGNORECASE)
            urlsRel = regRel.findall(data)
        except Exception as e:
            self.error("Error applying regex to: " + data)
            return None

        # Find potential links that aren't links (text possibly in comments, etc.)
        try:
            # Because we're working with a big blob of text now, don't worry
            # about clobbering proper links by url decoding them.
            data = urllib2.unquote(data)
            regRel = re.compile('(.)([a-zA-Z0-9\-\.]+\.'+domain+')', 
                re.IGNORECASE)
            urlsRel = urlsRel + regRel.findall(data)
        except Exception as e:
            self.error("Error applying regex2 to: " + data)

        # Loop through all the URLs/links found by the regex
        for linkTuple in urlsRel:
            # Remember the regex will return two vars (two groups captured)
            meta = linkTuple[0]
            link = linkTuple[1]
            absLink = None

            # Don't include stuff likely part of some dynamically built incomplete
            # URL found in Javascript code (character is part of some logic)
            if link[len(link)-1] == '.' or link[0] == '+' or 'javascript:' in link.lower() or '();' in link:
                self.debug('unlikely link: ' + link)
                continue

            # Filter in-page links
            if re.match('.*#.[^/]+', link):
                self.debug('in-page link: ' + link)
                continue

            # Ignore mail links
            if 'mailto:' in link.lower():
                self.debug("Ignoring mail link: " + link)
                continue

            # URL decode links
            if '%2f' in link.lower():
                link = urllib2.unquote(link)

            # Capture the absolute link:
            # If the link contains ://, it is already an absolute link
            if '://' in link:
                absLink = link

            # If the link starts with a /, the absolute link is off the base URL
            if link.startswith('/'):
                absLink = self.urlBaseUrl(url) + link

            # Maybe the domain was just mentioned and not a link, so we make it one
            if absLink == None and domain.lower() in link.lower():
                absLink = 'http://' + link

            # Otherwise, it's a flat link within the current directory
            if absLink == None:
                absLink = self.urlBaseDir(url) + link

            # Translate any relative pathing (../)
            absLink = self.urlRelativeToAbsolute(absLink)
            returnLinks[absLink] = {'source': url, 'original': link}

        return returnLinks

    # Fetch a URL, return the response object
    def fetchUrl(self, url, fatal=False, cookies=None):
        result = {
            'code': None,
            'status': None,
            'content': None,
            'headers': None,
            'realurl': None
        }

        if url == None:
            self.error('Blank URL supplied to be fetched')
            return result

        try:
            header = dict()
            if self.opts.has_key('_useragent') and not self.opts['_useragent'].startswith('@'):
                header['User-Agent'] = self.opts['_useragent']
            if self.opts.has_key('__useragent_list'):
                header['User-Agent'] = random.choice(self.opts['__useragent_list'])

            if not self.opts.has_key('_fetchtimeout'):
                self.opts['_fetchtimeout'] = 30
            req = urllib2.Request(url, None, header)
            if cookies != None:
                req.add_header('cookie', cookies)
                self.info("Fetching (incl. cookies): " + url)
            else:
                self.info("Fetching: " + url)

            opener = urllib2.build_opener(SmartRedirectHandler())
            fullPage = opener.open(req, timeout=self.opts['_fetchtimeout'])

            # Prepare result to return
            result['content'] = unicode(fullPage.read(), 'utf-8', errors='replace')
            result['headers'] = fullPage.info()
            #print "FOR: " + url
            #print "HEADERS: " + str(result['headers'])
            result['realurl'] = fullPage.geturl()
            result['code'] = fullPage.getcode()
            result['status'] = 'OK'
        except urllib2.HTTPError as h:
            self.info("HTTP code " + str(h.code) + " encountered for " + url)
            # Capture the HTTP error code
            result['code'] = h.code
            result['headers'] = h.info()
            if fatal:
                self.fatal('URL could not be fetched (' + h.code + ')')
        except urllib2.URLError as e:
            self.info("Error fetching " + url + "(" + str(e) + ")")
            result['status'] = str(e)
            if fatal:
                self.fatal('URL could not be fetched (' + str(e) + ')')
        except Exception as x:
            self.info("Unexpected exception occurred fetching: " + url + "(" + str(x) + ")")
            result['content'] = None
            result['status'] = str(x)
            if fatal:
                self.fatal('URL could not be fetched (' + str(x) + ')')

        return result

#
# SpiderFoot plug-in module base class
#
class SpiderFootPlugin(object):
    # Will be set to True by the controller if the user aborts scanning
    _stopScanning = False
    # Modules that will be notified when this module produces events
    _listenerModules = list()
    # Current event being processed
    _currentEvent = None
    # Name of this module, set at startup time
    __name__ = "module_name_not_set!"

    # Not really needed in most cases.
    def __init__(self):
        pass

    # Used to clear any listener relationships, etc. This is needed because
    # Python seems to cache local variables even between threads.
    def clearListeners(self):
        self._listenerModules = list()
        self._stopScanning = False

    # Will always be overriden by the implementer.
    def setup(self, sf, url, userOpts=dict()):
        pass

    # Listener modules which will get notified once we have data for them to
    # work with.
    def registerListener(self, listener):
        self._listenerModules.append(listener)

    # Call the handleEvent() method of every other plug-in listening for
    # events from this plug-in. Remember that those plug-ins will be called
    # within the same execution context of this thread, not on their own.
    def notifyListeners(self, sfEvent):
        eventName = sfEvent.eventType
        eventData = sfEvent.data

        # Check if we've been asked to stop in the meantime, so that
        # notifications stop triggering module activity.
        if self.checkForStop():
            return None

        if eventData == None or (type(eventData) is unicode and len(eventData) == 0):
            #print "No data to send for " + eventName + " to " + listener.__module__
            return None

        for listener in self._listenerModules:
            #print listener.__module__ + ": " + listener.watchedEvents().__str__()
            if eventName not in listener.watchedEvents() and '*' not in listener.watchedEvents():
                #print listener.__module__ + " not listening for " + eventName
                continue
            #print "Notifying " + eventName + " to " + listener.__module__
            listener._currentEvent = sfEvent
            listener.handleEvent(sfEvent)

    # Called to stop scanning
    def stopScanning(self):
        self._stopScanning = True

    # For modules to use to check for when they should give back control
    def checkForStop(self):
        return self._stopScanning

    # Return a list of the default configuration options for the module.
    def defaultOpts(self):
        return self.opts

    # What events is this module interested in for input. The format is a list
    # of event types that are applied to event types that this module wants to
    # be notified of, or * if it wants everything.
    # Will usually be overriden by the implementer, unless it is interested
    # in all events (default behavior).
    def watchedEvents(self):
        return [ '*' ]

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
    
    def __init__(self, eventType, data, module, sourceEvent=None,
        confidence=100, visibility=100, risk=0):
        self.eventType = eventType
        self.generated = time.time()
        self.confidence = confidence
        self.visibility = visibility
        self.risk = risk
        self.module = module
        self.data = data
        self.sourceEvent = sourceEvent

        # "ROOT" is a special "hash" reserved for elements with no
        # actual parent (e.g. the first page spidered.)
        if sourceEvent != None:
            self.sourceEventHash = sourceEvent.getHash()
        else:
            self.sourceEventHash = "ROOT"

    # Unique hash of this event
    def getHash(self):
        if self.eventType == "INITIAL_TARGET":
            return "ROOT"

        # Handle lists and dicts
        if type(self.data) not in [str, unicode]:
            idString = unicode(self.eventType + str(self.data) + str(self.generated) + self.module, 'utf-8', errors='replace')
        else:
            idString = self.eventType + self.data + str(self.generated) + self.module

        digestStr = idString.encode('raw_unicode_escape')
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
        if headers.has_key("Set-Cookie"):
            req.add_header('cookie', headers['Set-Cookie'])
        result = urllib2.HTTPRedirectHandler.http_error_301(
            self, req, fp, code, msg, headers)
        return result

    def http_error_302(self, req, fp, code, msg, headers):
        if headers.has_key("Set-Cookie"):
            req.add_header('cookie', headers['Set-Cookie'])
        result = urllib2.HTTPRedirectHandler.http_error_302(
            self, req, fp, code, msg, headers)
        return result

