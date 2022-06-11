# test_spiderfoottarget.py
import unittest

from spiderfoot import SpiderFootTarget


class TestSpiderFootTarget(unittest.TestCase):

    valid_target_types = [
        'IP_ADDRESS', 'IPV6_ADDRESS', 'NETBLOCK_OWNER', 'INTERNET_NAME',
        'EMAILADDR', 'HUMAN_NAME', 'BGP_AS_OWNER', 'PHONE_NUMBER', "USERNAME",
        'BITCOIN_ADDRESS'
    ]

    def test_init_argument_targetValue_invalid_type_should_raise_TypeError(self):
        target_type = 'IP_ADDRESS'

        invalid_types = [None, list(), bytes(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootTarget(invalid_type, target_type)

    def test_init_argument_targetType_invalid_type_should_raise_TypeError(self):
        target_value = 'example target value'

        invalid_types = [None, list(), bytes(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootTarget(target_value, invalid_type)

    def test_init_argument_targetType_invalid_should_raise_ValueError(self):
        target_value = 'example target value'
        with self.assertRaises(ValueError):
            SpiderFootTarget(target_value, 'invalid target type')

    def test_init_supported_target_types(self):
        target_value = 'example target value'

        for target_type in self.valid_target_types:
            with self.subTest(target_type=target_type):
                target = SpiderFootTarget(target_value, target_type)
                self.assertIsInstance(target, SpiderFootTarget)
                self.assertEqual(target.targetType, target_type)
                self.assertEqual(target.targetValue, target_value)

    def test_setAlias_invalid_alias_should_not_set_alias(self):
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        target.setAlias(None, None)
        target.setAlias("", None)
        target.setAlias(None, "")
        target.setAlias("", "")
        target.setAlias("example value", None)
        target.setAlias(None, "example type")

        target_aliases = target.targetAliases
        self.assertIsInstance(target_aliases, list)
        self.assertEqual([], target_aliases)

    def test_setAlias_should_set_alias(self):
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        target.setAlias("example value", "example type")

        expected_aliases = [{'type': 'example type', 'value': 'example value'}]

        target_aliases = target.targetAliases
        self.assertEqual(expected_aliases, target_aliases)

        # check duplicated aliases aren't created
        target.setAlias("example value", "example type")

        target_aliases = target.targetAliases
        self.assertEqual(expected_aliases, target_aliases)

    def test_targetType_attribute_should_return_a_string(self):
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        self.assertIsInstance(target.targetType, str)
        self.assertEqual(target_type, target.targetType)

    def test_targetType_attribute_setter_invalid_type_should_raise_TypeError(self):
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'

        invalid_types = [None, list(), bytes(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    target = SpiderFootTarget(target_value, target_type)
                    target.targetType = invalid_type

    def test_targetValue_attribute_should_return_a_string(self):
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        self.assertIsInstance(target.targetValue, str)
        self.assertEqual(target_value, target.targetValue)

    def test_targetValue_attribute_setter_invalid_type_should_raise_TypeError(self):
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'

        invalid_types = [None, list(), bytes(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    target = SpiderFootTarget(target_value, target_type)
                    target.targetValue = invalid_type

    def test_targetValue_attribute_setter_empty_value_should_raise_ValueError(self):
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'

        with self.assertRaises(ValueError):
            target = SpiderFootTarget(target_value, target_type)
            target.targetValue = ""

    def test_targetAliases_attribute_should_return_a_list(self):
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        self.assertIsInstance(target.targetAliases, list)

    def test_getEquivalents_should_return_a_list(self):
        """
        Test _getEquivalents(self, typeName)
        """
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        equivalents = target._getEquivalents(target_type)
        self.assertEqual(list, type(equivalents))

    def test_getEquivalents_should_return_alias_values(self):
        """
        Test _getEquivalents(self, typeName)
        """
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        alias_type = "example type"
        alias_value = "example value"
        target.setAlias(alias_value, alias_type)

        equivalents = target._getEquivalents(alias_type)
        self.assertIsInstance(equivalents, list)
        self.assertEqual(equivalents[0], alias_value)

    def test_getNames_should_return_a_list(self):
        """
        Test getNames(self)
        """
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        names = target.getNames()
        self.assertEqual(list, type(names))

    def test_getAddresses_should_return_a_list(self):
        """
        Test getAddresses(self)
        """
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        addresses = target.getAddresses()
        self.assertEqual(list, type(addresses))

        target_value = 'example target value'
        target_type = 'IPV6_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        addresses = target.getAddresses()
        self.assertEqual(list, type(addresses))

    def test_matches_argument_value_invalid_type_should_return_False(self):
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        invalid_types = [None, list(), bytes(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                matches = target.matches(invalid_type)
                self.assertFalse(matches)

    def test_matches_argument_value_matching_ipv4_address_should_return_True(self):
        target_value = '1.1.1.1'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches(target_value)
        self.assertTrue(matches)

    def test_matches_argument_value_unmatching_ipv4_address_should_return_False(self):
        target_value = '1.1.1.1'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches('1.1.1.2')
        self.assertFalse(matches)

    def test_matches_argument_value_unmatching_ipv4_address_in_same_subnet_when_targetType_is_netblock_should_return_True(self):
        target_value = '127.0.0.0/24'
        target_type = 'NETBLOCK_OWNER'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches('127.0.0.2')
        self.assertTrue(matches)

    def test_matches_argument_value_matching_ipv6_address_should_return_True(self):
        target_value = '::1'
        target_type = 'IPV6_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches(target_value)
        self.assertTrue(matches)

    def test_matches_argument_value_unmatching_ipv6_address_should_return_False(self):
        target_value = '::1'
        target_type = 'IPV6_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches('::2')
        self.assertFalse(matches)

    def test_matches_argument_value_matching_internet_name_should_return_True(self):
        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches(target_value)
        self.assertTrue(matches)

    def test_matches_argument_value_unmatching_internet_name_should_return_False(self):
        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches(f"{target_value}.test")
        self.assertFalse(matches)

    def test_matches_argument_includeChildren_true_with_matching_target_subdomain_should_return_True(self):
        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches(f"test.{target_value}", includeChildren=True)
        self.assertTrue(matches)

    def test_matches_argument_includeParents_true_with_matching_target_parent_domain_should_return_True(self):
        parent_domain = 'spiderfoot.net'
        target_value = f"test.{parent_domain}"
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches(parent_domain, includeParents=True)
        self.assertTrue(matches)

    def test_matches_argument_value_any_human_name_should_return_True(self):
        target_value = 'SpiderFoot'
        target_type = 'HUMAN_NAME'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches('something else entirely')
        self.assertTrue(matches)

    def test_matches_argument_value_any_phone_number_should_return_True(self):
        target_value = 'SpiderFoot'
        target_type = 'PHONE_NUMBER'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches('something else entirely')
        self.assertTrue(matches)

    def test_matches_argument_value_any_bitcoin_address_should_return_True(self):
        target_value = 'SpiderFoot'
        target_type = 'BITCOIN_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches('something else entirely')
        self.assertTrue(matches)

    def test_matches_argument_value_any_username_should_return_True(self):
        target_value = 'SpiderFoot'
        target_type = 'USERNAME'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches('something else entirely')
        self.assertTrue(matches)

    def test_matches_argument_value_with_empty_value_should_return_False(self):
        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        matches = target.matches("")
        self.assertFalse(matches)
