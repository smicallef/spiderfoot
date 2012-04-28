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

import sys
import re
import urllib2
import inspect

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

        # initialize database handler for storing results
        return

    def error(self, error):
        if self.handle == None:
            print '[Error] ' + error
        else:
            #self.handle.error(error)
            print 'should not be here'
        return

    def fatal(self, error):
        if self.handle == None:
            print '[Fatal] ' + error
            exit(-1)
        else:
            #self.handle.error(error)
            print 'should not be here'
        return

    def debug(self, message):
        if self.opts['_debug'] == False:
            return

        if self.handle == None:
                frm = inspect.stack()[1]
                mod = inspect.getmodule(frm[0])

                msg = '[d:' + mod.__name__ + '] ' + message
                if self.opts['_debugfilter'] != None and self.opts['_debugfilter'] not in msg:
                    return

                print msg
        else:
            #self.handle.debug(message)
            print 'should not be here'
        return

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
            bits = re.match('(.*://.[^/]*)/.*', url)
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
        return basedomainBits[-2] + '.' + basedomainBits[-1]

    # Extract the keyword (the domain without the TLD or any subdomains)
    # from a URL
    def urlKeyword(self, url):
        base = self.urlBaseUrl(url)
        domain = self.urlBaseDom(base)
        return domain.split('.', 2)[0]

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
            self.debug("Error fetching " + url)
            result['status'] = str(e)
            if fatal:
                self.fatal('URL could not be fetched (' + str(e) + ')')
        except Exception as x:
            self.error("Unexpected exception occurred: " + str(x))
            result['status'] = str(x)
            if fatal:
                self.fatal('URL could not be fetched (' + str(x) + ')')

        return result

class SpiderFootPlugin(object):
    # Modules that will be notified when this module produces events
    _listenerModules = list()

    # Will always be overriden by the implementer.
    def __init__(self, url, userOpts=dict()):
        pass

    # Listener modules which will get notified once we have data for them to
    # work with.
    def registerListener(self, listener):
        self._listenerModules.append(listener)

    # Call the handleEvent() method of every other plug-in listening for
    # events from this plug-in. Remember that those plug-ins will be called
    # within the same execution context of this thread, not on their own.
    def notifyListeners(self, eventName, eventSource, eventData):
        if self.opts.has_key('blocknotif') and self.opts['_blocknotif']:
            return None

        if eventData == None or len(eventData) == 0:
            return None

        for listener in self._listenerModules:
            if eventName not in listener.watchedEvents() and '*' not in listener.watchedEvents():
                continue
            #print "Notifying " + eventName + " to " + listener.__module__
            listener.handleEvent(self.__module__, eventName, eventSource, eventData)

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
