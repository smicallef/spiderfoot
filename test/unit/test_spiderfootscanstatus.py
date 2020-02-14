# test_spiderfootscanstatus.py
from sflib import SpiderFootScanStatus
import unittest


class TestSpiderFootScanStatus(unittest.TestCase):
    """
    Test SpiderFootScanStatus
    """

    def test_set_status_should_return_none(self):
        """
        Test setStatus(self, scanId, status)
        """
        globalScanStatus = SpiderFootScanStatus()

        scan_id = "example scan id"
        status = "example status"

        scan_status = globalScanStatus.setStatus(scan_id, status)
        self.assertEqual(None, scan_status)

    def test_get_status_should_return_a_string(self):
        """
        Test getStatus(self, scanId)
        """
        globalScanStatus = SpiderFootScanStatus()

        scan_id = "example scan id"
        status = "example status"
        globalScanStatus.setStatus(scan_id, status)

        scan_status = globalScanStatus.getStatus(scan_id)
        self.assertEqual(status, scan_status)

    def test_get_status_all_should_return_a_dict(self):
        """
        Test getStatusAll(self)
        """
        globalScanStatus = SpiderFootScanStatus()

        scan_status = globalScanStatus.getStatusAll()
        self.assertEqual(dict, type(scan_status))


if __name__ == "__main__":
    unittest.main()
