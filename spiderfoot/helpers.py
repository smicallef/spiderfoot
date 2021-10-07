import json
import os
import os.path
import random
import re
import uuid

import networkx as nx
from networkx.readwrite.gexf import GEXFWriter
from pathlib import Path


class SpiderFootHelpers():
    """SpiderFoot helper functions."""

    @staticmethod
    def dataPath() -> str:
        """Returns the file system location of SpiderFoot data and configuration files.

        Returns:
            str: SpiderFoot data file system path
        """
        path = os.environ.get('SPIDERFOOT_DATA')
        if not path:
            path = f"{Path.home()}/.spiderfoot/"
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def cachePath() -> str:
        """Returns the file system location of the cacha data files.

        Returns:
            str: SpiderFoot cache file system path
        """
        path = os.environ.get('SPIDERFOOT_CACHE')
        if not path:
            path = f"{Path.home()}/.spiderfoot/cache"
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def logPath() -> str:
        """Returns the file system location of SpiderFoot log files.

        Returns:
            str: SpiderFoot data file system path
        """
        path = os.environ.get('SPIDERFOOT_LOGS')
        if not path:
            path = f"{Path.home()}/.spiderfoot/logs"
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def targetTypeFromString(target: str) -> None:
        """Return the scan target seed data type for the specified scan target input.

        Args:
            target (str): scan target seed input

        Returns:
            str: scan target seed data type
        """
        if not target:
            return None

        # NOTE: the regex order is important
        regexToType = [
            {r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$": "IP_ADDRESS"},
            {r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/\d+$": "NETBLOCK_OWNER"},
            {r"^.*@.*$": "EMAILADDR"},
            {r"^\+[0-9]+$": "PHONE_NUMBER"},
            {r"^\".+\s+.+\"$": "HUMAN_NAME"},
            {r"^\".+\"$": "USERNAME"},
            {r"^[0-9]+$": "BGP_AS_OWNER"},
            {r"^[0-9a-f:]+$": "IPV6_ADDRESS"},
            {r"^[0-9a-f:]+::/[0-9]+$": "NETBLOCKV6_OWNER"},
            {r"^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)+([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$": "INTERNET_NAME"},
            {r"^(bc(0([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1[ac-hj-np-z02-9]{8,87})|[13][a-km-zA-HJ-NP-Z1-9]{25,35})$": "BITCOIN_ADDRESS"},
        ]

        # Parse the target and set the target type
        for rxpair in regexToType:
            rx = list(rxpair.keys())[0]
            if re.match(rx, target, re.IGNORECASE | re.UNICODE):
                return list(rxpair.values())[0]

        return None

    @staticmethod
    def buildGraphGexf(root: str, title: str, data: list, flt: list = []) -> str:
        """Convert supplied raw data into GEXF (Graph Exchange XML Format) format (e.g. for Gephi).

        Args:
            root (str): TBD
            title (str): unused
            data (list): Scan result as list
            flt (list): List of event types to include. If not set everything is included.

        Returns:
            str: GEXF formatted XML
        """
        mapping = SpiderFootHelpers.buildGraphData(data, flt)
        graph = nx.Graph()

        nodelist = dict()
        ncounter = 0
        for pair in mapping:
            (dst, src) = pair

            # Leave out this special case
            if dst == "ROOT" or src == "ROOT":
                continue

            color = {
                'r': 0,
                'g': 0,
                'b': 0
            }

            if dst not in nodelist:
                ncounter = ncounter + 1
                if dst in root:
                    color['r'] = 255
                graph.add_node(dst)
                graph.nodes[dst]['viz'] = {'color': color}
                nodelist[dst] = ncounter

            if src not in nodelist:
                ncounter = ncounter + 1
                if src in root:
                    color['r'] = 255
                graph.add_node(src)
                graph.nodes[src]['viz'] = {'color': color}
                nodelist[src] = ncounter

            graph.add_edge(src, dst)

        gexf = GEXFWriter(graph=graph)
        return str(gexf).encode('utf-8')

    @staticmethod
    def buildGraphJson(root: str, data: list, flt: list = []) -> str:
        """Convert supplied raw data into JSON format for SigmaJS.

        Args:
            root (str): TBD
            data (list): Scan result as list
            flt (list): List of event types to include. If not set everything is included.

        Returns:
            str: TBD
        """
        mapping = SpiderFootHelpers.buildGraphData(data, flt)
        ret = dict()
        ret['nodes'] = list()
        ret['edges'] = list()

        nodelist = dict()
        ecounter = 0
        ncounter = 0
        for pair in mapping:
            (dst, src) = pair
            col = "#000"

            # Leave out this special case
            if dst == "ROOT" or src == "ROOT":
                continue

            if dst not in nodelist:
                ncounter = ncounter + 1

                if dst in root:
                    col = "#f00"

                ret['nodes'].append({
                    'id': str(ncounter),
                    'label': str(dst),
                    'x': random.SystemRandom().randint(1, 1000),
                    'y': random.SystemRandom().randint(1, 1000),
                    'size': "1",
                    'color': col
                })

                nodelist[dst] = ncounter

            if src not in nodelist:
                ncounter = ncounter + 1

                if src in root:
                    col = "#f00"

                ret['nodes'].append({
                    'id': str(ncounter),
                    'label': str(src),
                    'x': random.SystemRandom().randint(1, 1000),
                    'y': random.SystemRandom().randint(1, 1000),
                    'size': "1",
                    'color': col
                })

                nodelist[src] = ncounter

            ecounter = ecounter + 1

            ret['edges'].append({
                'id': str(ecounter),
                'source': str(nodelist[src]),
                'target': str(nodelist[dst])
            })

        return json.dumps(ret)

    @staticmethod
    def buildGraphData(data: list, flt: list = []) -> set:
        """Return a format-agnostic collection of tuples to use as the
        basis for building graphs in various formats.

        Args:
            data (list): Scan result as list
            flt (list): List of event types to include. If not set everything is included.

        Returns:
            set: TBD

        Raises:
            ValueError: data value was invalid
            TypeError: data type was invalid
        """
        if not isinstance(data, list):
            raise TypeError(f"data is {type(data)}; expected list()")

        if not data:
            raise ValueError("data is empty")

        def get_next_parent_entities(item: str, pids: list) -> list:
            ret = list()

            for [parent, entity_id] in parents[item]:
                if entity_id in pids:
                    continue
                if parent in entities:
                    ret.append(parent)
                else:
                    pids.append(entity_id)
                    for p in get_next_parent_entities(parent, pids):
                        ret.append(p)
            return ret

        mapping = set()
        entities = dict()
        parents = dict()

        for row in data:
            if len(row) != 15:
                raise ValueError(f"data row length is {len(row)}; expected 15")

            if row[11] == "ENTITY" or row[11] == "INTERNAL":
                # List of all valid entity values
                if len(flt) > 0:
                    if row[4] in flt or row[11] == "INTERNAL":
                        entities[row[1]] = True
                else:
                    entities[row[1]] = True

            if row[1] not in parents:
                parents[row[1]] = list()
            parents[row[1]].append([row[2], row[8]])

        for entity in entities:
            for [parent, _id] in parents[entity]:
                if parent in entities:
                    if entity != parent:
                        # Add entity parent
                        mapping.add((entity, parent))
                else:
                    ppids = list()
                    # Check parent for entityship.
                    next_parents = get_next_parent_entities(parent, ppids)
                    for next_parent in next_parents:
                        if entity != next_parent:
                            # Add next entity parent
                            mapping.add((entity, next_parent))
        return mapping

    @staticmethod
    def dataParentChildToTree(data: dict) -> dict:
        """Converts a dictionary of k -> array to a nested
        tree that can be digested by d3 for visualizations.

        Args:
            data (dict): dictionary of k -> array

        Returns:
            dict: nested tree

        Raises:
            ValueError: data value was invalid
            TypeError: data type was invalid
        """
        if not isinstance(data, dict):
            raise TypeError(f"data is {type(data)}; expected dict()")

        if not data:
            raise ValueError("data is empty")

        def get_children(needle: str, haystack: dict) -> list:
            ret = list()

            if needle not in list(haystack.keys()):
                return None

            if haystack[needle] is None:
                return None

            for c in haystack[needle]:
                ret.append({"name": c, "children": get_children(c, haystack)})
            return ret

        # Find the element with no parents, that's our root.
        root = None
        for k in list(data.keys()):
            if data[k] is None:
                continue

            contender = True
            for ck in list(data.keys()):
                if data[ck] is None:
                    continue

                if k in data[ck]:
                    contender = False

            if contender:
                root = k
                break

        if root is None:
            return {}

        return {"name": root, "children": get_children(root, data)}

    @staticmethod
    def validLEI(lei: str) -> bool:
        """Check if the provided string is a valid Legal Entity Identifier (LEI).

        Args:
            lei (str): The LEI number to check.

        Returns:
            bool: string is a valid LEI

        Note:
            ISO 17442 has been withdrawn and is not accurate
            https://www.gleif.org/en/about-lei/iso-17442-the-lei-code-structure
        """
        if not isinstance(lei, str):
            return False

        if not re.match(r'^[A-Z0-9]{18}[0-9]{2}$', lei, re.IGNORECASE):
            return False

        return True

    @staticmethod
    def genScanInstanceId() -> str:
        """Generate an globally unique ID for this scan.

        Returns:
            str: scan instance unique ID
        """
        return str(uuid.uuid4()).split("-")[0].upper()

    @staticmethod
    def parseRobotsTxt(robotsTxtData: str) -> list:
        """Parse the contents of robots.txt.

        Args:
            robotsTxtData (str): robots.txt file contents

        Returns:
            list: list of patterns which should not be followed

        Todo:
            Check and parse User-Agent.

            Fix whitespace parsing; ie, " " is not a valid disallowed path
        """
        returnArr = list()

        if not isinstance(robotsTxtData, str):
            return returnArr

        for line in robotsTxtData.splitlines():
            if line.lower().startswith('disallow:'):
                m = re.match(r'disallow:\s*(.[^ #]*)', line, re.IGNORECASE)
                if m:
                    returnArr.append(m.group(1))

        return returnArr

    @staticmethod
    def sanitiseInput(cmd: str) -> bool:
        """Verify input command is safe to execute

        Args:
            cmd (str): The command to check

        Returns:
            bool: command is "safe"
        """
        chars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                 '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '.']
        for c in cmd:
            if c.lower() not in chars:
                return False

        if '..' in cmd:
            return False

        if cmd.startswith("-"):
            return False

        if len(cmd) < 3:
            return False

        return True
