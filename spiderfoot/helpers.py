import json
import random
import re
import uuid
from networkx import nx
from networkx.readwrite.gexf import GEXFWriter


class SpiderFootHelpers():
    """SpiderFoot helper functions."""

    @staticmethod
    def targetTypeFromString(target):
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
            {r"^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)+([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$": "INTERNET_NAME"},
            {r"^([13][a-km-zA-HJ-NP-Z1-9]{25,34})$": "BITCOIN_ADDRESS"}
        ]

        # Parse the target and set the target type
        for rxpair in regexToType:
            rx = list(rxpair.keys())[0]
            if re.match(rx, target, re.IGNORECASE | re.UNICODE):
                return list(rxpair.values())[0]

        return None

    @staticmethod
    def buildGraphGexf(root, title, data, flt=[]):
        """Convert supplied raw data into GEXF format (e.g. for Gephi)

        GEXF produced by PyGEXF doesn't work with SigmaJS because
        SJS needs coordinates for each node.
        flt is a list of event types to include, if not set everything is
        included.

        Args:
            root (str): TBD
            title (str): unused
            data (list): scan result as list
            flt (list): TBD

        Returns:
            str: TBD
        """

        mapping = SpiderFootHelpers.buildGraphData(data, flt)
        graph = nx.Graph()

        nodelist = dict()
        ncounter = 0
        for pair in mapping:
            (dst, src) = pair
            col = ["0", "0", "0"]

            # Leave out this special case
            if dst == "ROOT" or src == "ROOT":
                continue

            if dst not in nodelist:
                ncounter = ncounter + 1
                if dst in root:
                    col = ["255", "0", "0"]
                graph.node[dst]['viz'] = {'color': {'r': col[0], 'g': col[1], 'b': col[2]}}
                nodelist[dst] = ncounter

            if src not in nodelist:
                ncounter = ncounter + 1
                if src in root:
                    col = ["255", "0", "0"]
                graph.add_node(src)
                graph.node[src]['viz'] = {'color': {'r': col[0], 'g': col[1], 'b': col[2]}}
                nodelist[src] = ncounter

            graph.add_edge(src, dst)

        gexf = GEXFWriter(graph=graph)
        return str(gexf).encode('utf-8')

    @staticmethod
    def buildGraphJson(root, data, flt=[]):
        """Convert supplied raw data into JSON format for SigmaJS.

        Args:
            root (str): TBD
            data (list): scan result as list
            flt (list): TBD

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
    def buildGraphData(data, flt=list()):
        """Return a format-agnostic collection of tuples to use as the
        basis for building graphs in various formats.

        Args:
            data (list): Scan result as list
            flt (list): TBD

        Returns:
            set: TBD
        """
        if not data:
            return set()

        mapping = set()
        entities = dict()
        parents = dict()

        def get_next_parent_entities(item, pids):
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

        for row in data:
            if len(row) != 15:
                # TODO: print error
                continue

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
    def dataParentChildToTree(data):
        """Converts a dictionary of k -> array to a nested
        tree that can be digested by d3 for visualizations.

        Args:
            data (dict): dictionary of k -> array

        Returns:
            dict: nested tree
        """

        if not isinstance(data, dict):
            # TODO: print error
            return {}

        def get_children(needle, haystack):
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
    def validLEI(lei):
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
    def genScanInstanceId():
        """Generate an globally unique ID for this scan.

        Returns:
            str: scan instance unique ID
        """

        return str(uuid.uuid4()).split("-")[0].upper()

    @staticmethod
    def parseRobotsTxt(robotsTxtData):
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
