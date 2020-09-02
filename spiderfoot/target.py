import netaddr


class SpiderFootTarget():
    """SpiderFoot target.

    Attributes:
        validTypes (list): valid event types accepted as a target
        targetType (str): target type
        targetValue (str): target value
        targetAliases (list): target aliases
    """

    _validTypes = ["IP_ADDRESS", 'IPV6_ADDRESS', "NETBLOCK_OWNER", "INTERNET_NAME",
                   "EMAILADDR", "HUMAN_NAME", "BGP_AS_OWNER", 'PHONE_NUMBER', "USERNAME"]
    _targetType = None
    _targetValue = None
    _targetAliases = list()

    def __init__(self, targetValue, typeName):
        """Initialize SpiderFoot target.

        Args:
            targetValue (str): target value
            typeName (str): target type

        Raises:
            TypeError: targetValue type was invalid
            ValueError: targetValue value was empty
            ValueError: typeName value was an invalid target type
        """

        self.targetType = typeName
        self.targetValue = targetValue
        self.targetAliases = list()

    @property
    def targetType(self):
        return self._targetType

    @targetType.setter
    def targetType(self, targetType):
        if not isinstance(targetType, str):
            raise TypeError(f"targetType is {type(targetType)}; expected str()")

        if targetType not in self._validTypes:
            raise ValueError(f"targetType value is {targetType}; expected {self._validTypes}")

        self._targetType = targetType

    @property
    def targetValue(self):
        return self._targetValue

    @targetValue.setter
    def targetValue(self, targetValue):
        if not isinstance(targetValue, str):
            raise TypeError(f"targetValue is {type(targetValue)}; expected str()")
        if not targetValue:
            raise ValueError("targetValue value is blank")

        self._targetValue = targetValue

    @property
    def targetAliases(self):
        return self._targetAliases

    @targetAliases.setter
    def targetAliases(self, value):
        self._targetAliases = value

    def setAlias(self, value, typeName):
        """Specify other hostnames, IPs, etc. that are aliases for this target.

        For instance, if the user searched for an ASN, a module
        might supply all the nested subnets as aliases.
        Or, if a user searched for an IP address, a module
        might supply the hostname as an alias.

        Args:
            value (str): TBD
            typeName (str): TBD

        Returns:
            None
        """
        if not isinstance(value, (str, bytes)):
            return None

        if not value:
            return None

        if not isinstance(typeName, (str, bytes)):
            return None

        if {'type': typeName, 'value': value} in self.targetAliases:
            return None

        self.targetAliases.append(
            {'type': typeName, 'value': value.lower()}
        )

        return None

    def _getEquivalents(self, typeName):
        """TBD

        Returns:
            list: target aliases
        """

        ret = list()
        for item in self.targetAliases:
            if item['type'] == typeName:
                ret.append(item['value'].lower())
        return ret

    def getNames(self):
        """Get all domains associated with the target.

        Returns:
            list: domains associated with the target
        """

        e = self._getEquivalents("INTERNET_NAME")
        if self.targetType in ["INTERNET_NAME", "EMAILADDR"] and self.targetValue.lower() not in e:
            e.append(self.targetValue.lower())

        names = list()
        for name in e:
            if isinstance(name, bytes):
                names.append(name.decode("utf-8"))
            else:
                names.append(name)

        return names

    def getAddresses(self):
        """Get all IP Subnets or IP Addresses associated with the target.

        Returns:
            list: TBD
        """

        e = self._getEquivalents("IP_ADDRESS")
        if self.targetType == "IP_ADDRESS":
            e.append(self.targetValue)

        e = self._getEquivalents("IPV6_ADDRESS")
        if self.targetType == "IPV6_ADDRESS":
            e.append(self.targetValue)

        return e

    def matches(self, value, includeParents=False, includeChildren=True):
        """Check whether the supplied value is "tightly" related
        to the original target.

        Tightly in this case means:
          1. If the value is an IP:
              1.1 is it in the list of aliases or the target itself?
              1.2 is it on the target's subnet?
          2. If the value is a name (subdomain, domain, hostname):
              2.1 is it in the list of aliases or the target itself?
              2.2 is it a parent of the aliases of the target (domain/subdomain)
              2.3 is it a child of the aliases of the target (hostname)

        Args:
            value (str): can be an Internet Name (hostname, subnet, domain) or an IP address.
            includeParents (bool):  True means you consider a value that is
                a parent domain of the target to still be a tight relation.
            includeChildren (bool): False means you don't consider a value
                that is a child of the target to be a tight relation.

        Returns:
            bool: whether the value matches the target
        """
        if not isinstance(value, str) and not isinstance(value, bytes):
            return False

        value = value.lower()

        if isinstance(value, bytes):
            value = value.decode("utf-8")

        if not value:
            return False

        # We can't really say anything about names, username or phone numbers,
        # so everything matches
        if self.targetType in ["HUMAN_NAME", "PHONE_NUMBER", "USERNAME"]:
            return True

        if netaddr.valid_ipv4(value):
            # 1.1
            if value in self.getAddresses():
                return True
            # 1.2
            if self.targetType == "NETBLOCK_OWNER":
                if netaddr.IPAddress(value) in netaddr.IPNetwork(self.targetValue):
                    return True
            if self.targetType in ["IP_ADDRESS", "IPV6_ADDRESS"]:
                if netaddr.IPAddress(value) in netaddr.IPNetwork(netaddr.IPAddress(self.targetValue)):
                    return True
        else:
            for name in self.getNames():
                # 2.1
                if value == name:
                    return True
                # 2.2
                if includeParents and name.endswith("." + value):
                    return True
                # 2.3
                if includeChildren and value.endswith("." + name):
                    return True

        return None

# end of SpiderFootTarget class
