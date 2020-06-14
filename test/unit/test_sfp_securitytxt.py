import unittest
import collections
from modules.sfp_securitytxt import sfp_securitytxt
from sflib import SpiderFootEvent, SpiderFootTarget

class SpiderFootStub:
    def __init__(self):
        self.logMessages = collections.defaultdict(list)
        self.fetchedUrls = []
        self.fetchUrlResponses = {}

    def debug(self, message):
        self.logMessages['debug'].append(message)
        print(f'[DEBUG] {message}')

    def error(self, message, exception):
        self.logMessages['error'].append(message)
        print(f'[ERROR] {message} {exception}')

    def fetchUrl(self, url):
        self.fetchedUrls.append(url)
        response = self.fetchUrlResponses.get(url, {'code': '404'})
        if isinstance(response, Exception):
            raise response
        if not isinstance(response, dict):
            response = {'code': '200', 'content': response}
        return response

class SpiderFootDatabaseStub:
    def __init__(self):
        # (name, seed_target, created, started, ended, status)
        self.scanInstanceGetResult = None

    def scanInstanceGet(self, _):
        return self.scanInstanceGetResult

class EventListenerStub:
    def __init__(self, debug=True):
        self.debugEnabled = debug
        self.events = []
        self._priority = 0

    @staticmethod
    def watchedEvents():
        return ['*']

    def handleEvent(self, event):
        if self.debugEnabled:
            print(f'[EVENT] {event.eventType} {event.data}')
        self.events.append(event)

class TestSecurityTxtModule(unittest.TestCase):
    def setUpModule(self, moduleType, targetType, targetValue, userOpts=None):
        moduleType = sfp_securitytxt
        self.foo = 100
        self.spiderfoot = SpiderFootStub()
        self.eventListener = EventListenerStub()
        db = SpiderFootDatabaseStub()
        module = moduleType()
        module.setTarget(SpiderFootTarget(targetValue, targetType))
        module._listenerModules.append(self.eventListener)
        db.scanInstanceGetResult = ('TEST', 0, None, None, None, 'TEST')
        module.setDbh(db)
        module.setup(self.spiderfoot, userOpts)
        return module

    def test_metadata(self):
        module = sfp_securitytxt()

        self.assertEqual(
            module.watchedEvents(),
            ['INTERNET_NAME', 'DOMAINNAME'])

        self.assertEqual(
            module.producedEvents(),
            ['PGP_KEY', 'EMAILADDR', 'LINKED_URL_INTERNAL', 'LINKED_URL_EXTERNAL'])

    def test_user_opts(self):
        targetType = 'INTERNET_NAME'
        targetValue = 'google.com'
        userOpts = {
            'test': 'test_value'
        }
        module = self.setUpModule(sfp_securitytxt, targetType, targetValue, userOpts)
        self.assertEqual(module.opts['test'], userOpts['test'])

    def test_repeated_event(self):
        targetType = 'INTERNET_NAME'
        targetValue = 'google.com'
        module = self.setUpModule(sfp_securitytxt, targetType, targetValue)
        rootEvent = SpiderFootEvent('ROOT', targetValue, '', None)
        incomingEvent = SpiderFootEvent('INTERNET_NAME', 'google.com', 'Spiderfoot UI', rootEvent)

        module.handleEvent(incomingEvent)
        module.handleEvent(incomingEvent)

        self.assertTrue(any('already mapped' in m for m in self.spiderfoot.logMessages['debug']))

    SECURITYTXT_CONTENT = '''
Contact: https://g.co/vulnz
Contact: mailto:security@google.com
Encryption: https://services.google.com/corporate/publickey.txt
Acknowledgements: https://bughunter.withgoogle.com/
Policy: https://g.co/vrp
Hiring: https://g.co/SecurityPrivacyEngJobs
# Flag: BountyCon{075e1e5eef2bc8d49bfe4a27cd17f0bf4b2b85cf}                
'''
    PGP_KEY_CONTENT = '''
    pub   rsa4096 2015-10-17 [C] [expires: 2021-10-11]
          E3317DB04D3958FD5F662C37B8E4105CC9DEDC77
    uid           Google Security Team <security@google.com>
    sig        B8E4105CC9DEDC77 2018-10-12   [selfsig]
    sig        C789A16F6F4D6519 2015-10-17   [User ID not found]
    sig        B8E4105CC9DEDC77 2015-10-17   [selfsig]
    sub   rsa4096 2018-10-12 [E] [expires: 2021-10-11]
    sig        B8E4105CC9DEDC77 2018-10-12   [keybind]
    sub   rsa4096 2018-10-12 [S] [expires: 2021-10-11]
    sig        B8E4105CC9DEDC77 2018-10-12   [keybind]
    sub   nistp521 2018-10-12 [S] [expires: 2021-10-11]
    sig        B8E4105CC9DEDC77 2018-10-12   [keybind]
    sub   nistp521 2018-10-12 [E] [expires: 2021-10-11]
    sig        B8E4105CC9DEDC77 2018-10-12   [keybind]
    sub   cv25519 2018-10-12 [E] [expires: 2021-10-11]
    sig        B8E4105CC9DEDC77 2018-10-12   [keybind]
    sub   nistp384 2015-10-17 [S] [expires: 2018-10-16]
    sig        B8E4105CC9DEDC77 2015-10-17   [keybind]
    sub   rsa4096 2015-10-17 [S] [expires: 2018-10-16]
    sig        B8E4105CC9DEDC77 2015-10-17  
    '''

    def test_complete_file(self):
        targetType = 'INTERNET_NAME'
        targetValue = 'google.com'
        module = self.setUpModule(sfp_securitytxt, targetType, targetValue)
        self.spiderfoot.fetchUrlResponses = {
            'https://google.com/.well-known/security.txt': self.SECURITYTXT_CONTENT,
            'https://services.google.com/corporate/publickey.txt': self.PGP_KEY_CONTENT
        }

        rootEvent = SpiderFootEvent('ROOT', targetValue, '', None)
        incomingEvent = SpiderFootEvent('INTERNET_NAME', 'google.com', 'Spiderfoot UI', rootEvent)

        module.handleEvent(incomingEvent)

        self.assertEqual(len(self.eventListener.events), 4, 'wrong number of responses')
        self.assertEqual(self.spiderfoot.fetchedUrls[0], 'https://google.com/.well-known/security.txt')

        self.assertEqual(self.eventListener.events[0].eventType, 'LINKED_URL_EXTERNAL')
        self.assertEqual(self.eventListener.events[0].data, 'https://g.co/vulnz')
        self.assertEqual(self.eventListener.events[0].module, 'sfp_securitytxt')
        self.assertEqual(self.eventListener.events[0].sourceEvent, incomingEvent)

        self.assertEqual(self.eventListener.events[1].eventType, 'EMAILADDR')
        self.assertEqual(self.eventListener.events[1].data, 'security@google.com')
        self.assertEqual(self.eventListener.events[1].module, 'sfp_securitytxt')
        self.assertEqual(self.eventListener.events[1].sourceEvent, incomingEvent)

        self.assertEqual(self.eventListener.events[2].eventType, 'LINKED_URL_INTERNAL')
        self.assertEqual(self.eventListener.events[2].data, 'https://services.google.com/corporate/publickey.txt')
        self.assertEqual(self.eventListener.events[2].module, 'sfp_securitytxt')
        self.assertEqual(self.eventListener.events[2].sourceEvent, incomingEvent)

        self.assertEqual(self.eventListener.events[3].eventType, 'PGP_KEY')
        self.assertEqual(self.eventListener.events[3].data, self.PGP_KEY_CONTENT)
        self.assertEqual(self.eventListener.events[3].module, 'sfp_securitytxt')
        self.assertEqual(self.eventListener.events[3].sourceEvent, incomingEvent)
        self.assertEqual(self.spiderfoot.fetchedUrls[1], 'https://services.google.com/corporate/publickey.txt')

    def test_scheme_iteration(self):
        targetType = 'INTERNET_NAME'
        targetValue = 'google.com'
        module = self.setUpModule(sfp_securitytxt, targetType, targetValue)
        # No https response
        self.spiderfoot.fetchUrlResponses = {
            'http://google.com/.well-known/security.txt': 'Contact: https://g.co/vulnz'
        }

        rootEvent = SpiderFootEvent('ROOT', targetValue, '', None)
        incomingEvent = SpiderFootEvent('INTERNET_NAME', 'google.com', 'Spiderfoot UI', rootEvent)

        module.handleEvent(incomingEvent)

        self.assertEqual(len(self.eventListener.events), 1, 'wrong number of responses')
        self.assertEqual(self.spiderfoot.fetchedUrls, [
            'https://google.com/.well-known/security.txt',
            'http://google.com/.well-known/security.txt',
        ])
        self.assertEqual(self.eventListener.events[0].eventType, 'LINKED_URL_EXTERNAL')
        self.assertEqual(self.eventListener.events[0].data, 'https://g.co/vulnz')
        self.assertEqual(self.eventListener.events[0].module, 'sfp_securitytxt')
        self.assertEqual(self.eventListener.events[0].sourceEvent, incomingEvent)

    def test_nonhttp_pgp_key(self):
        targetType = 'INTERNET_NAME'
        targetValue = 'google.com'
        module = self.setUpModule(sfp_securitytxt, targetType, targetValue)
        # No https response
        self.spiderfoot.fetchUrlResponses = {
            'http://google.com/.well-known/security.txt':
                'Contact: https://g.co/vulnz\n'
                'Encryption: dns:5d2d37ab76d47d36._openpgpkey.example.com?type=OPENPGPKEY'
        }

        rootEvent = SpiderFootEvent('ROOT', targetValue, '', None)
        incomingEvent = SpiderFootEvent('INTERNET_NAME', 'google.com', 'Spiderfoot UI', rootEvent)

        module.handleEvent(incomingEvent)

        self.assertEqual(len(self.eventListener.events), 2, 'wrong number of responses')

        event = self.eventListener.events[1]

        self.assertEqual(event.eventType, 'PGP_KEY')
        self.assertEqual(event.data, 'dns:5d2d37ab76d47d36._openpgpkey.example.com?type=OPENPGPKEY')
        self.assertEqual(event.module, 'sfp_securitytxt')
        self.assertEqual(event.sourceEvent, incomingEvent)

    def test_fetch_exception(self):
        with self.assertRaises(BaseException) as context:
            targetType = 'INTERNET_NAME'
            targetValue = 'google.com'
            module = self.setUpModule(sfp_securitytxt, targetType, targetValue)
            self.spiderfoot.fetchUrlResponses = {
                'https://google.com/.well-known/security.txt': Exception('TEST'),
            }
            rootEvent = SpiderFootEvent('ROOT', targetValue, '', None)
            incomingEvent = SpiderFootEvent('INTERNET_NAME', 'google.com', 'Spiderfoot UI', rootEvent)
            module.handleEvent(incomingEvent)

        self.assertEqual(context.exception.args, ('TEST',))
        self.assertTrue(any('Failed to process' in m for m in self.spiderfoot.logMessages['error']))
