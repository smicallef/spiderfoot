# test_spiderfoot.py
import pytest
import unittest

from spiderfoot import SpiderFootHelpers


@pytest.mark.usefixtures
class TestSpiderFootHelpers(unittest.TestCase):
    """
    Test SpiderFootHelpers
    """

    def test_target_type(self):
        """
        Test targetType(target)
        """
        target_type = SpiderFootHelpers.targetTypeFromString("0.0.0.0")
        self.assertEqual('IP_ADDRESS', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("noreply@spiderfoot.net")
        self.assertEqual('EMAILADDR', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("0.0.0.0/0")
        self.assertEqual('NETBLOCK_OWNER', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("+1234567890")
        self.assertEqual('PHONE_NUMBER', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString('"Human Name"')
        self.assertEqual('HUMAN_NAME', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString('"abc123"')
        self.assertEqual('USERNAME', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("1234567890")
        self.assertEqual('BGP_AS_OWNER', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("::1")
        self.assertEqual('IPV6_ADDRESS', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("spiderfoot.net")
        self.assertEqual('INTERNET_NAME', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("1HesYJSP1QqcyPEjnQ9vzBL1wujruNGe7R")
        self.assertEqual('BITCOIN_ADDRESS', target_type)

    def test_target_type_invalid_seed_should_return_none(self):
        """
        Test targetType(target)
        """
        target_type = SpiderFootHelpers.targetTypeFromString(None)
        self.assertEqual(None, target_type)

        target_type = SpiderFootHelpers.targetTypeFromString("")
        self.assertEqual(None, target_type)

        target_type = SpiderFootHelpers.targetTypeFromString('""')
        self.assertEqual(None, target_type)

    def test_buildGraphData_should_return_a_set(self):
        """
        Test buildGraphData(data, flt=list())
        """
        graph_data = SpiderFootHelpers.buildGraphData('', '')
        self.assertIsInstance(graph_data, set)

        graph_data = SpiderFootHelpers.buildGraphData(None, None)
        self.assertIsInstance(graph_data, set)

        graph_data = SpiderFootHelpers.buildGraphData(list(), list())
        self.assertIsInstance(graph_data, set)

        graph_data = SpiderFootHelpers.buildGraphData([])
        self.assertIsInstance(graph_data, set)

        graph_data = SpiderFootHelpers.buildGraphData(["test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test"])
        self.assertIsInstance(graph_data, set)

        self.assertEqual('TBD', 'TBD')

    def test_buildGraphGexf_should_return_bytes(self):
        """
        Test buildGraphGexf(root, title, data, flt=[])
        """
        gexf = SpiderFootHelpers.buildGraphGexf(None, None, None)
        self.assertIsInstance(gexf, bytes)

        gexf = SpiderFootHelpers.buildGraphGexf('', '', '')
        self.assertIsInstance(gexf, bytes)

        gexf = SpiderFootHelpers.buildGraphGexf('test root', 'test title', [])
        self.assertIsInstance(gexf, bytes)

        gexf = SpiderFootHelpers.buildGraphGexf('test root', 'test title', [["test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "ENTITY", "test", "test", "test"]])
        self.assertIsInstance(gexf, bytes)

        self.assertEqual('TBD', 'TBD')

    def test_buildGraphJson_should_return_a_string(self):
        """
        Test buildGraphJson(root, data, flt=list())
        """
        json = SpiderFootHelpers.buildGraphJson(None, None)
        self.assertIsInstance(json, str)

        json = SpiderFootHelpers.buildGraphJson('', '')
        self.assertIsInstance(json, str)

        json = SpiderFootHelpers.buildGraphJson('test root', [])
        self.assertIsInstance(json, str)

        json = SpiderFootHelpers.buildGraphJson('test root', [["test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "ENTITY", "test", "test", "test"]])
        self.assertIsInstance(json, str)

        self.assertEqual('TBD', 'TBD')

    def test_dataParentChildToTree_should_return_dict(self):
        """
        Test dataParentChildToTree(data)
        """
        invalid_types = [None, "", list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                tree = SpiderFootHelpers.dataParentChildToTree(invalid_type)
                self.assertIsInstance(tree, dict)

        tree = SpiderFootHelpers.dataParentChildToTree(dict())
        self.assertIsInstance(tree, dict)

        tree = SpiderFootHelpers.dataParentChildToTree({"test": {"123": "456"}})
        self.assertIsInstance(tree, dict)

    def test_genScanInstanceId_should_return_a_string(self):
        """
        Test genScanInstanceId()
        """
        scan_instance_id = SpiderFootHelpers.genScanInstanceId()
        self.assertIsInstance(scan_instance_id, str)

    def test_validLEI_should_return_a_boolean(self):
        """
        Test validLEI(lei)
        """
        invalid_types = [None, "", list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                valid_phone = SpiderFootHelpers.validLEI(invalid_type)
                self.assertIsInstance(valid_phone, bool)
                self.assertFalse(valid_phone)

        valid_lei = SpiderFootHelpers.validLEI('7ZW8QJWVPR4P1J1KQYZZ')
        self.assertIsInstance(valid_lei, bool)
        self.assertFalse(valid_lei)

        valid_lei = SpiderFootHelpers.validLEI('7ZW8QJWVPR4P1J1KQY45')
        self.assertIsInstance(valid_lei, bool)
        self.assertTrue(valid_lei)

    def test_parse_robots_txt_should_return_list(self):
        """
        Test parseRobotsTxt(robotsTxtData)
        """
        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                robots_txt = SpiderFootHelpers.parseRobotsTxt(invalid_type)
                self.assertIsInstance(robots_txt, list)

        robots_txt = SpiderFootHelpers.parseRobotsTxt("disallow:")
        self.assertIsInstance(robots_txt, list)
        self.assertFalse(robots_txt)

        robots_txt = SpiderFootHelpers.parseRobotsTxt("disallow: /disallowed/path\n")
        self.assertIsInstance(robots_txt, list)
        self.assertIn("/disallowed/path", robots_txt)
