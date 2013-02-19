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
import random
import re
import sys
import time
import urllib2

class SpiderFoot:
    # 'options' is a dictionary of options which changes the behaviour
    # of how certain things are done in this module
    #   - debug: enable debugging
    #   - debugfilter: filter debug messages for a string
    # 'handle' will be supplied if the module is being used within the
    # SpiderFoot GUI, in which case all feedback should be fed back
    def __init__(self, options, handle=None):
        self.handle = handle
        self.opts = options

    #
    # Debug, error message and logging functions
    #

    def error(self, error):
        if self.handle == None:
            print '[Error] ' + error
            raise BaseException(error)
        else:
            #self.handle.error(error)
            print 'should not be here'
        return

    def fatal(self, error):
        if self.handle == None:
            print '[Fatal] ' + error
            raise BaseException("Fatal Error Encountered: " + error)
            exit(-1)
        else:
            #self.handle.error(error)
            print 'should not be here'
        return

    def status(self, message):
        print "STATUS: " + message

    def debug(self, message):
        if self.opts['_debug'] == False:
            return

        if self.handle == None:
                frm = inspect.stack()[1]
                mod = inspect.getmodule(frm[0])

                msg = '[d:' + mod.__name__ + '] ' + message
                if self.opts['__debugfilter'] != None and self.opts['__debugfilter'] not in msg:
                    return

                print msg
        else:
            #self.handle.debug(message)
            print 'should not be here'
        return

    #
    # Configuration process
    #

    # Convert a Python dictionary to something storable
    # in the database.
    def configSerialize(self, opts, filterSystem=True):
        storeopts = dict()

        for opt in opts.keys():
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
    def urlBaseUrl(self, url):

        if '://' in url:
            bits = re.match('(\w+://.[^/]*)/.*', url)
        else:
            bits = re.match('(.[^/]*)/', url)

        if bits == None:
            return url

        self.debug('base url of ' + url + ' is: ' + bits.group(1))
        return bits.group(1)

    # Get the base domain from a URL
    def urlBaseDom(self, url):
        url = self.urlBaseUrl(url)
        basedomainBits = url.rsplit('.', 2)
        try:
            return basedomainBits[-2] + '.' + basedomainBits[-1]
        except IndexError:
            # Some error parsing the domain out of the URL
            return None

    # Extract the keyword (the domain without the TLD or any subdomains)
    # from a URL
    def urlKeyword(self, url):
        base = self.urlBaseUrl(url)
        domain = self.urlBaseDom(base)
        return domain.split('.', 2)[0]

    #
    # General helper functions to automate many common tasks between modules
    #

    # Parse the contents of robots.txt, returns a list of patterns
    # which should not be followed
    def parseRobotsTxt(self, robotsTxtData):
        returnArr = list()

        # We don't check the User-Agent rule yet.. probably should at some stage

        for line in robotsTxtData.splitlines():
            if line.startswith('Disallow:'):
                m = re.match('Disallow:\s*(.[^ #]*)', line)
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
    def parseLinks(self, url, data):
        returnLinks = dict()

        if data == None or len(data) == 0:
            self.debug('parseLinks() called with no data to parse')
            return None

        try:
            regRel = re.compile('(href|src|action|url)[:=][ \'\"]*(.[^\'\"<> ]*)',
             re.IGNORECASE)
            urlsRel = regRel.findall(data)
        except Exception as e:
            self.error("Error applying regex to " + data + ", continuing anyway.")
            return None

        # Loop through all the URLs/links found by the regex
        for linkTuple in urlsRel:
            # Remember the regex will return two vars (two groups captured)
            meta = linkTuple[0]
            link = linkTuple[1]

            # Don't include stuff likely part of some dynamically built incomplete
            # URL found in Javascript code (character is part of some logic)
            if link[len(link)-1] == '.' or link[0] == '+':
                self.debug('unlikely link: ' + link)
                continue

            # Filter in-page links
            if re.match('.*#.[^/]+', link):
                self.debug('in-page link: ' + link)
                continue

            # Ignore mail links
            if 'mailto:' in link:
                self.debug("Ignoring mail link: " + link)
                continue

            # Capture the absolute link:
            # If the link contains ://, it is already an absolute link
            if '://' in link:
                absLink = link

            # If the link starts with a /, the absolute link is off the base URL
            if link.startswith('/'):
                absLink = self.urlBaseUrl(url) + link

            # Otherwise, it's a flat link within the current directory
            if '://' not in link and not link.startswith('/'):
                absLink = self.urlBaseDir(url) + link

            # Translate any relative pathing (../)
            absLink = self.urlRelativeToAbsolute(absLink)
            returnLinks[absLink] = {'source': url, 'original': link}

        return returnLinks

    # Scrape Google for content, starting at startUrl and iterating through
    # results based on options supplied. Will return a dictionary of all pages
    # fetched and their contents {page => content}.
    # Options accepted:
    # limit: number of search result pages before returning, default is 10
    # nopause: don't randomly pause between fetches
    def googleIterate(self, searchString, opts=dict()):
        limit = 10
        fetches = 0
        returnResults = dict()

        if opts.has_key('limit'):
            limit = opts['limit']

        # We attempt to make the URL look as authentically human as possible
        seedUrl = "http://www.google.com/search?q={0}".format(searchString) + \
            "&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:en-US:official&client=firefox-a"
        firstPage = self.fetchUrl(seedUrl)
        if firstPage['code'] == "403":
            self.error("Google doesn't like us right now..")
            return None

        if firstPage['content'] == None:
            self.error("Failed to fetch content from Google.")
            return None

        returnResults[seedUrl] = firstPage['content']

        matches = re.findall("(\/search\S+start=\d+.[^\'\"]*sa=N)", firstPage['content'])
        while matches > 0 and fetches < limit:
            nextUrl = None
            fetches += 1
            for match in matches:
                # Google moves in increments of 10
                if "start=" + str(fetches*10) in match:
                    nextUrl = match.replace("&amp;", "&")

            if nextUrl == None:
                self.debug("Nothing left to scan for in Google results.")
                return returnResults
            self.debug("Next Google URL: " + nextUrl)

            # Wait for a random number of seconds between fetches
            if not opts.has_key('nopause'):
                pauseSecs = random.randint(4, 15)
                self.debug("Pausing for " + str(pauseSecs))
                time.sleep(pauseSecs)

            nextPage = self.fetchUrl('http://www.google.com' + nextUrl)
            if firstPage['code'] == 403:
                self.error("Google doesn't like us any more..")
                return returnResults

            if nextPage['content'] == None:
                self.error("Failed to fetch subsequent content from Google.")
                return returnResults

            returnResults[nextUrl] = nextPage['content']
            matches = re.findall("(\/search\S+start=\d+.[^\'\"]*)", nextPage['content'])

        return returnResults

    # Fetch a URL, return the response object
    def fetchUrl(self, url, fatal=False):
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
            if self.opts.has_key('_useragent'):
                header['User-Agent'] = self.opts['_useragent']
            # Let modules override
            if self.opts.has_key('useragent'):
                header['User-Agent'] = self.opts['useragent']

            if not self.opts.has_key('_fetchtimeout'):
                self.opts['_fetchtimeout'] = 30
            req = urllib2.Request(url, None, header)
            self.debug("Fetching " + url)
            fullPage = urllib2.urlopen(req, None, self.opts['_fetchtimeout'])

            # Prepare result to return
            result['content'] = fullPage.read()
            result['headers'] = fullPage.info()
            result['realurl'] = fullPage.geturl()
            result['status'] = 'OK'
        except urllib2.HTTPError as h:
            self.debug("HTTP code " + str(h.code) + " encountered for " + url)
            # Capture the HTTP error code
            result['code'] = h.code
            if fatal:
                self.fatal('URL could not be fetched (' + h.code + ')')
        except urllib2.URLError as e:
            self.debug("Error fetching " + url + "(" + str(e) + ")")
            result['status'] = str(e)
            if fatal:
                self.fatal('URL could not be fetched (' + str(e) + ')')
        except Exception as x:
            self.debug("Unexpected exception occurred fetching: " + url + "(" + str(x) + ")")
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

    # Not really needed in most cases.
    def __init__(self):
        pass

    # Used to clear any listener relationships, etc. This is needed because
    # Python seems to cache local variables even between threads.
    def clearListeners(self):
        self._listenerModules = list()
        self._stopScanning = False

    # Will always be overriden by the implementer.
    def setup(self, url, userOpts=dict()):
        pass

    # Listener modules which will get notified once we have data for them to
    # work with.
    def registerListener(self, listener):
        self._listenerModules.append(listener)

    # Call the handleEvent() method of every other plug-in listening for
    # events from this plug-in. Remember that those plug-ins will be called
    # within the same execution context of this thread, not on their own.
    def notifyListeners(self, eventName, eventSource, eventData):
        # Check if we've been asked to stop in the meantime, so that
        # notifications stop triggering module activity.
        if self.checkForStop():
            return None

        if self.opts.has_key('blocknotif') and self.opts['__blocknotif']:
            #print "Notifications blocked for " + eventName + " to " + listener.__module__
            return None

        if eventData == None or len(eventData) == 0:
            #print "No data to send for " + eventName + " to " + listener.__module__
            return None

        for listener in self._listenerModules:
            #print listener.__module__ + ": " + listener.watchedEvents().__str__()
            if eventName not in listener.watchedEvents() and '*' not in listener.watchedEvents():
                #print listener.__module__ + " not listening for " + eventName
                continue
            #print "Notifying " + eventName + " to " + listener.__module__
            listener.handleEvent(self.__module__, eventName, eventSource, eventData)

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
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
        return None

    # Kick off the work (for some modules nothing will happen here, but instead
    # the work will start from the handleEvent() method.
    # Will usually be overriden by the implementer.
    def start(self):
        return None
