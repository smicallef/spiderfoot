# test_sfp_dnsdumpster.py
import unittest

from modules.sfp_dnsdumpster import sfp_dnsdumpster
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


class TestModulednsdumpster(unittest.TestCase):
    """
    Test modules.sfp_dnsdumpster
    """

    default_options = {
        '_debug': False,  # Debug
        '__logging': True,  # Logging in general
        '__outputfilter': None,  # Event types to filter from modules' output
        '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',  # User-Agent to use for HTTP requests
        '_dnsserver': '',  # Override the default resolver
        '_fetchtimeout': 5,  # number of seconds before giving up on a fetch
        '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
        '_internettlds_cache': 72,
        '_genericusers': "abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,ispsupport,list-request,list,maildaemon,marketing,noc,no-reply,noreply,null,peering,peering-notify,peering-request,phish,phishing,postmaster,privacy,registrar,registry,root,routing-registry,rr,sales,security,spam,support,sysadmin,tech,undisclosed-recipients,unsubscribe,usenet,uucp,webmaster,www",
        '__version__': '3.3',
        '__database': 'spiderfoot.test.db',  # note: test database file
        '__modules__': None,  # List of modules. Will be set after start-up.
        '_socks1type': '',
        '_socks2addr': '',
        '_socks3port': '',
        '_socks4user': '',
        '_socks5pwd': '',
        '_torctlport': 9051,
        '__logstdout': False
    }

    def test_opts(self):
        module = sfp_dnsdumpster()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        """
        Test setup(self, sfc, userOpts=dict())
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsdumpster()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_dnsdumpster()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_dnsdumpster()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent(self):
        """
        Test handleEvent(self, event)
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsdumpster()
        module.setup(sf, dict())

        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)
