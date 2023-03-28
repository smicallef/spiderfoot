import netaddr

class SpiderFootTarget:
    _valid_types = ["IP_ADDRESS", 'IPV6_ADDRESS', "NETBLOCK_OWNER", "NETBLOCKV6_OWNER", "INTERNET_NAME",
                   "EMAILADDR", "HUMAN_NAME", "BGP_AS_OWNER", 'PHONE_NUMBER', "USERNAME",
                   "BITCOIN_ADDRESS"]

    def __init__(self, target_value: str, type_name: str) -> None:
        self.target_type = type_name
        self.target_value = target_value
        self.aliases = []

    @property
    def target_type(self) -> str:
        return self._target_type

    @target_type.setter
    def target_type(self, target_type: str) -> None:
        if target_type not in self._valid_types:
            raise ValueError(f"Invalid target type: {target_type}. Expected {self._valid_types}")
        self._target_type = target_type

    @property
    def target_value(self) -> str:
        return self._target_value

    @target_value.setter
    def target_value(self, target_value: str) -> None:
        if not target_value:
            raise ValueError("Target value cannot be empty")
        self._target_value = target_value

    def set_alias(self, value: str, type_name: str) -> None:
        if not value or not type_name:
            return
        alias = {'type': type_name, 'value': value.lower()}
        if alias in self.aliases:
            return
        self.aliases.append(alias)

    def _get_equivalents(self, type_name: str) -> list:
        return [item['value'].lower() for item in self.aliases if item['type'] == type_name]

    def get_names(self) -> list:
        names = self._get_equivalents("INTERNET_NAME")
        if self.target_type in ["INTERNET_NAME", "EMAILADDR"] and self.target_value.lower() not in names:
            names.append(self.target_value.lower())
        return names

    def get_addresses(self) -> list:
        addresses = self._get_equivalents("IP_ADDRESS")
        if self.target_type == "IP_ADDRESS":
            addresses.append(self.target_value)
        addresses.extend(self._get_equivalents("IPV6_ADDRESS"))
        if self.target_type == "IPV6_ADDRESS":
            addresses.append(self.target_value)
        return addresses
