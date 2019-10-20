# test_spiderfoottarget.py
from sflib import SpiderFootTarget
import unittest
 
class TestSpiderFootTarget(unittest.TestCase):
    """
    Test SpiderFootTarget
    """
 
    def test_init(self):
        """
        Test __init__
        """

        #target = SpiderFootTarget('junk', 'junk')
        #self.assertEqual(target, None)

        target_value = '127.0.0.1'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)
        self.assertEqual(target.getType(), target_type)
        self.assertEqual(target.getValue(), target_value)

        target_value = '::1'
        target_type = 'IPV6_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)
        self.assertEqual(target.getType(), target_type)
        self.assertEqual(target.getValue(), target_value)

        target_value = '0.0.0.0/0'
        target_type = 'NETBLOCK_OWNER'
        target = SpiderFootTarget(target_value, target_type)
        self.assertEqual(target.getType(), target_type)
        self.assertEqual(target.getValue(), target_value)

        target_value = 'localhost.local'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        self.assertEqual(target.getType(), target_type)
        self.assertEqual(target.getValue(), target_value)

        target_value = 'root@localhost.local'
        target_type = 'EMAILADDR'
        target = SpiderFootTarget(target_value, target_type)
        self.assertEqual(target.getType(), target_type)
        self.assertEqual(target.getValue(), target_value)

        target_value = 'hello'
        target_type = 'HUMAN_NAME'
        target = SpiderFootTarget(target_value, target_type)
        self.assertEqual(target.getType(), target_type)
        self.assertEqual(target.getValue(), target_value)

        target_value = '1234'
        target_type = 'BGP_AS_OWNER'
        target = SpiderFootTarget(target_value, target_type)
        self.assertEqual(target.getType(), target_type)
        self.assertEqual(target.getValue(), target_value)

        target_value = '+12345678901'
        target_type = 'PHONE_NUMBER'
        target = SpiderFootTarget(target_value, target_type)
        self.assertEqual(target.getType(), target_type)
        self.assertEqual(target.getValue(), target_value)

    def test_set_alias(self):
        """
	Test setAlias(self, value, typeName)
        """
        self.assertEqual('TBD', 'TBD')

    def test_get_aliases(self):
        """
	Test getAliases(self)
        """
        self.assertEqual('TBD', 'TBD')
 
    def test_get_equivalents(self):
        """
        Test _getEquivalents(self, typeName)
        """
        self.assertEqual('TBD', 'TBD')

    def test_get_names(self):
        """
	Test getNames(self)
        """
        self.assertEqual('TBD', 'TBD')

    def test_get_addresses(self):
        """
        Test getAddresses(self)
        """
        self.assertEqual('TBD', 'TBD')

    def test_matches(self):
        """
	Test matches(self, value, includeParents=False, includeChildren=True)
        """
        self.assertEqual('TBD', 'TBD')

if __name__ == '__main__':
    unittest.main()

