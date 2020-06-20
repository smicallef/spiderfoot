# test_spiderfootscanner.py
from sfscan import SpiderFootScanner
import unittest

class TestSpiderFootScanStatus(unittest.TestCase):
    """
    Test SpiderFootScanStatus
    """

    def test_init_no_options_should_raise(self):
        """
        Test __init__(self, scanName, scanTarget, targetType, scanId, moduleList, globalOpts, moduleOpts)
        """
        with self.assertRaises(TypeError) as cm:
            sfscan = SpiderFootScanner(None, None, None, None, None, None, None)
  
    @unittest.skip("todo")
    def test_init(self):
        """
        Test __init__(self, scanName, scanTarget, targetType, scanId, moduleList, globalOpts, moduleOpts)
        """
        #sfscan = SpiderFootScanner("", "", "", "", list(), dict(), dict())
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_set_status_should_return_none(self):
        """
        Test def setStatus(self, status, started=None, ended=None)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_run_should_return_none(self):
        """
        Test def run(self)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_get_id_should_return_none(self):
        """
        Test def getId(self)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_start_scan_should_return_none(self):
        """
        Test def startScan(self)
        """
        self.assertEqual('TBD', 'TBD')

if __name__ == '__main__':
    unittest.main()

