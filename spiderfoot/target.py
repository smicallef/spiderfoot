import netaddr


class SpiderFootTarget():
    """SpiderFoot target.

    Attributes:
        validTypes (list): valid event types accepted as a target
        targetType (str): target type
        targetValue (str): target value
        targetAliases (list): target aliases
    """

    _validTypes = ["IP_ADDRESS", 'IPV6_ADDRESS', "NETBLOCK_OWNER", "NETBLOCKV6_OWNER", "INTERNET_NAME",
                   "EMAILADDR", "HUMAN_NAME", "BGP_AS_OWNER", 'PHONE_NUMBER', "USERNAME",
                   "BITCOIN_ADDRESS"]
    _targetType = None
    _targetValue = None
    _targetAliases = list()

    def __init__(self, targetValue: str, typeName: str) -> None:
        """Initialize SpiderFoot target.

        Args:
            targetValue (str): target value
            typeName (str): target type
        """
        self.targetType = typeName
        self.targetValue = targetValue
        self.targetAliases = list()

    @property
    def targetType(self) -> str:
        return self._targetType

    @targetType.setter
    def targetType(self, targetType: str) -> None:
        if not isinstance(targetType, str):
            raise TypeError(f"targetType is {type(targetType)}; expected str()")

        if targetType not in self._validTypes:
            raise ValueError(f"targetType value is {targetType}; expected {self._validTypes}")

        self._targetType = targetType

    @property
    def targetValue(self) -> str:
        return self._targetValue

    @targetValue.setter
    def targetValue(self, targetValue: str) -> None:
        if not isinstance(targetValue, str):
            raise TypeError(f"targetValue is {type(targetValue)}; expected str()")
        if not targetValue:
            raise ValueError("targetValue value is blank")

        self._targetValue = targetValue

    @property
    def targetAliases(self) -> list:
        return self._targetAliases

    @targetAliases.setter
    def targetAliases(self, value: list) -> None:
        self._targetAliases = value

    def setAlias(self, value: str, typeName: str) -> None:
        """Specify other hostnames, IPs, etc. that are aliases for this target.

        For instance, if the user searched for an ASN, a module
        might supply all the nested subnets as aliases.
        Or, if a user searched for an IP address, a module
        might supply the hostname as an alias.

        Args:
            value (str): Target alias value
            typeName (str): Target alias data type
        """
        if not isinstance(value, (str, bytes)):
            return

        if not value:
            return

        if not isinstance(typeName, (str, bytes)):
            return

        if not typeName:
            return

        alias = {'type': typeName, 'value': value.lower()}

        if alias in self.targetAliases:
            return

        self.targetAliases.append(alias)

    def _getEquivalents(self, typeName: str) -> list:
        """Get all aliases of the specfied target data type.

        Args:
            typeName (str): Target data type

        Returns:
            list: target aliases
        """
        ret = list()
        for item in self.targetAliases:
            if item['type'] == typeName:
                ret.append(item['value'].lower())
        return ret

    def getNames(self) -> list:
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

    def getAddresses(self) -> list:
        """Get all IP subnet or IP address aliases associated with the target.

        Returns:
            list: List of IP subnets and addresses
        """
        e = self._getEquivalents("IP_ADDRESS")
        if self.targetType == "IP_ADDRESS":
            e.append(self.targetValue)

        e = self._getEquivalents("IPV6_ADDRESS")
        if self.targetType == "IPV6_ADDRESS":
            e.append(self.targetValue)

        return e

    def matches(self, value: str, includeParents: bool = False, includeChildren: bool = True) -> bool:
        """Check whether the supplied value is "tightly" related to the original target.

        Tightly in this case means:

        If the value is an IP:
            * is it in the list of aliases or the target itself?
            * is it on the target's subnet?

        If the value is an internet name (subdomain, domain, hostname):
            * is it in the list of aliases or the target itself?
            * is it a parent of the aliases of the target (domain/subdomain)
            * is it a child of the aliases of the target (hostname)

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

        if isinstance(value, bytes):
            value = value.decode("utf-8")

        if not value:
            return False

        # We can't really say anything about names, username, bitcoin addresses
        # or phone numbers, so everything matches
        if self.targetType in ["HUMAN_NAME", "PHONE_NUMBER", "USERNAME", "BITCOIN_ADDRESS"]:
            return True

        # TODO: review handling of other potential self.targetType target types:
        # "INTERNET_NAME", "EMAILADDR", "BGP_AS_OWNER"

        # For IP addreses, check if it is an alias of the target or within the target's subnet.
        if netaddr.valid_ipv4(value) or netaddr.valid_ipv6(value):
            if value in self.getAddresses():
                return True

            if self.targetType in ["IP_ADDRESS", "IPV6_ADDRESS", "NETBLOCK_OWNER", "NETBLOCKV6_OWNER"]:
                try:
                    if netaddr.IPAddress(value) in netaddr.IPNetwork(self.targetValue):
                        return True
                except netaddr.AddrFormatError:
                    return False

            return False

        # For everything else, check if the value is within or equal to target names
        for name in self.getNames():
            if value == name:
                return True
            if includeParents and name.endswith("." + value):
                return True
            if includeChildren and value.endswith("." + name):
                return True

        return False

# end of SpiderFootTarget class
