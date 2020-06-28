# test_spiderfootscanner.py
from sfscan import SpiderFootScanner
import unittest
import uuid

class TestSpiderFootScanner(unittest.TestCase):
    """
    Test SpiderFootScanStatus
    """
    default_options = {
      '_debug': False,
      '__logging': True,
      '__outputfilter': None,
      '__blocknotif': False,
      '_fatalerrors': False,
      '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
      '_dnsserver': '',
      '_fetchtimeout': 5,
      '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
      '_internettlds_cache': 72,
      '_genericusers': "abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,ispsupport,list-request,list,maildaemon,marketing,noc,no-reply,noreply,null,peering,peering-notify,peering-request,phish,phishing,postmaster,privacy,registrar,registry,root,routing-registry,rr,sales,security,spam,support,sysadmin,tech,undisclosed-recipients,unsubscribe,usenet,uucp,webmaster,www",
      '__version__': '3.0',
      '__database': 'spiderfoot.test.db',  # note: test database file
      '__webaddr': '127.0.0.1',
      '__webport': 5001,
      '__docroot': '',
      '__modules__': None,
      '_socks1type': '',
      '_socks2addr': '',
      '_socks3port': '',
      '_socks4user': '',
      '_socks5pwd': '',
      '_socks6dns': True,
      '_torctlport': 9051,
      '__logstdout': False
    }

    def test_init(self):
        """
        Test __init__(self, scanName, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        sfscan = SpiderFootScanner("", scan_id, "", "IP_ADDRESS", list(), opts, start=False)
        self.assertIsInstance(sfscan, SpiderFootScanner)

    def test_init_invalid_scan_name_should_raise(self):
        """
        Test __init__(self, scanName, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = str(uuid.uuid4())
        with self.assertRaises(TypeError) as cm:
            sfscan = SpiderFootScanner(None, scan_id, "", "IP_ADDRESS", list(), self.default_options, start=False)

    def test_init_invalid_scan_id_should_raise(self):
        """
        Test __init__(self, scanName, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = None
        with self.assertRaises(TypeError) as cm:
            sfscan = SpiderFootScanner(None, scan_id, "", "IP_ADDRESS", list(), self.default_options, start=False)

    def test_init_invalid_scan_target_should_raise(self):
        """
        Test __init__(self, scanName, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = str(uuid.uuid4())
        with self.assertRaises(TypeError) as cm:
            sfscan = SpiderFootScanner("", scan_id, None, "IP_ADDRESS", list(), self.default_options, start=False)

    def test_init_invalid_scan_target_type_should_raise(self):
        """
        Test __init__(self, scanName, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        with self.assertRaises(TypeError) as cm:
            sfscan = SpiderFootScanner("", scan_id, "", None, list(), self.default_options, start=False)

    def test_init_invalid_module_list_should_raise(self):
        """
        Test __init__(self, scanName, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        with self.assertRaises(TypeError) as cm:
            sfscan = SpiderFootScanner("", scan_id, "", "IP_ADDRESS", None, self.default_options, start=False)

    def test_init_invalid_options_should_raise(self):
        """
        Test __init__(self, scanName, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        with self.assertRaises(TypeError) as cm:
            sfscan = SpiderFootScanner("", scan_id, "", "IP_ADDRESS", list(), None, start=False)

        scan_id = str(uuid.uuid4())
        with self.assertRaises(ValueError) as cm:
            sfscan = SpiderFootScanner("", scan_id, "", "IP_ADDRESS", list(), dict(), start=False)

    def test_set_status_invalid_status_should_raise(self):
        """
        Test def setStatus(self, status, started=None, ended=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        sfscan = SpiderFootScanner("", scan_id, "", "IP_ADDRESS", list(), opts, start=False)
        self.assertIsInstance(sfscan, SpiderFootScanner)

        with self.assertRaises(ValueError) as cm:
            sfscan.setStatus("invalid status", None, None)

    def test_get_id_should_return_a_scan_id(self):
        """
        Test def getId(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        sfscan = SpiderFootScanner("", scan_id, "", "IP_ADDRESS", list(), opts, start=False)
        self.assertIsInstance(sfscan, SpiderFootScanner)

        get_id = sfscan.getId()
        self.assertIsInstance(get_id, str)
        self.assertEqual(scan_id, get_id)

    @unittest.skip("todo")
    def test_start_scan_should_start_a_scan(self):
        """
        Test def startScan(self)
        """
        self.assertEqual('TBD', 'TBD')

if __name__ == '__main__':
    unittest.main()

