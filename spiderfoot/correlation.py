import logging
from copy import deepcopy
import re
import netaddr
import yaml
from spiderfoot import SpiderFootDb


class SpiderFootCorrelator:
    """SpiderFoot correlation capabilities.

    Todo:
        Make the rule checking per analysis method
    """

    log = logging.getLogger("spiderfoot.correlator")
    dbh = None
    scanId = None
    types = None
    rules = list()
    type_entity_map = dict()

    # For syntax checking
    mandatory_components = ["meta", "collections", "headline"]
    components = {
        # collect a set of data elements based on various conditions
        "meta": {
            "strict": ["name", "description", "risk"],
            "optional": ["author", "url"]
        },
        "collections": {
            "strict": ["collect"]
        },
        "aggregation": {
            "strict": ["field"]
        },
        # TODO: Make the rule checking per analysis method
        "analysis": {
            "strict": ["method"],
            "optional": ["field", "maximum_percent", "noisy_percent", "minimum", "maximum", "must_be_unique", "match_method"]
        },
        "headline": {},
        "id": {},
        "version": {},
        "enabled": {},
        "rawYaml": {}
    }

    def __init__(self, dbh: SpiderFootDb, ruleset: dict, scanId: str = None) -> None:
        """Initialize SpiderFoot correlator engine with scan ID and ruleset.

        Args:
            dbh (SpiderFootDb): database handle
            ruleset (dict): correlation rule set
            scanId (str): scan instance ID

        Raises:
            TypeError: argument type was invalid
            SyntaxError: correlation ruleset contains malformed or invalid rule
        """
        if not isinstance(ruleset, dict):
            raise TypeError(f"ruleset is {type(ruleset)}; expected dict()")

        if not isinstance(dbh, SpiderFootDb):
            raise TypeError(f"dbh is {type(dbh)}; expected SpiderFootDb()")

        self.dbh = dbh

        if scanId and not isinstance(scanId, str):
            raise TypeError(f"scanId is {type(scanId)}; expected str()")

        self.scanId = scanId

        self.types = self.dbh.eventTypes()
        for t in self.types:
            self.type_entity_map[t[1]] = t[3]

        self.rules = list()

        # Sanity-check the rules
        for rule_id in ruleset.keys():
            self.log.debug(f"Parsing rule {rule_id}...")
            try:
                self.rules.append(yaml.safe_load(ruleset[rule_id]))
                self.rules[len(self.rules) - 1]['rawYaml'] = ruleset[rule_id]
            except Exception as e:
                raise SyntaxError(f"Unable to process a YAML correlation rule [{rule_id}]") from e

        # Strip any trailing newlines that may have creeped into meta name/description
        for rule in self.rules:
            for k in rule['meta'].keys():
                if isinstance(rule['meta'][k], str):
                    rule['meta'][k] = rule['meta'][k].strip()
                else:
                    rule['meta'][k] = rule[k]

        if not self.check_ruleset_validity(self.rules):
            raise SyntaxError("Sanity check of correlation rules failed.")

    def get_ruleset(self) -> list:
        """Correlation rule set.

        Returns:
            list: correlation rules
        """
        return self.rules

    def run_correlations(self) -> None:
        """Run all correlation rules.

        Raises:
            ValueError: correlation rules cannot be run on specified scanId
        """
        scan_instance = self.dbh.scanInstanceGet(self.scanId)
        if not scan_instance:
            raise ValueError(f"Invalid scan ID. Scan {self.scanId} does not exist.")

        if scan_instance[5] in ["RUNNING", "STARTING", "STARTED"]:
            raise ValueError(f"Scan {self.scanId} is {scan_instance[5]}. You cannot run correlations on running scans.")

        for rule in self.rules:
            self.log.debug(f"Processing rule: {rule['id']}")
            results = self.process_rule(rule)
            if not results:
                self.log.debug(f"No results for rule {rule['id']}.")
                continue

            self.log.info(f"Rule {rule['id']} returned {len(results.keys())} results.")

            for result in results:
                self.create_correlation(rule, results[result])

    def build_db_criteria(self, matchrule: dict) -> dict:
        """Build up the criteria to be used to query the database.

        Args:
            matchrule (dict): dict representing a match rule

        Returns:
            dict: criteria to be used with SpiderFootDb.scanResultEvent()

        Raises:
            TypeError: argument type was invalid
        """
        if not isinstance(matchrule, dict):
            raise TypeError(f"matchrule is {type(matchrule)}; expected dict()")

        criterias = dict()

        if "." in matchrule['field']:
            self.log.error("The first collection must either be data, type or module.")
            return None

        if matchrule['field'] == "data" and matchrule['type'] == "regex":
            self.log.error("The first collection cannot use regex on data.")
            return None

        if matchrule['field'] == "module" and matchrule['method'] != 'exact':
            self.log.error("Collection based on module names doesn't support regex.")
            return None

        # Build up the event type part of the query
        if matchrule['field'] == "type":
            if 'eventType' not in criterias:
                criterias['eventType'] = list()

            if matchrule['method'] == 'regex':
                if type(matchrule['value']) != list:
                    regexps = [matchrule['value']]
                else:
                    regexps = matchrule['value']

                for r in regexps:
                    for t in self.types:
                        if re.search(r, t[1]):
                            criterias['eventType'].append(t[1])

            if matchrule['method'] == 'exact':
                if type(matchrule['value']) != list:
                    matches = [matchrule['value']]
                else:
                    matches = matchrule['value']

                for m in matches:
                    matched = False
                    for t in self.types:
                        if t[1] == m:
                            matched = True
                            criterias['eventType'].append(t[1])
                    if not matched:
                        self.log.error(f"Invalid type specified: {m}")
                        return None

        # Match by module(s)
        if matchrule['field'] == "module":
            if 'srcModule' not in criterias:
                criterias['srcModule'] = list()

            if matchrule['method'] == 'exact':
                if isinstance(matchrule['value'], list):
                    criterias['srcModule'].extend(matchrule['value'])
                else:
                    criterias['srcModule'].append(matchrule['value'])

        # Match by data
        if matchrule['field'] == "data":
            if 'data' not in criterias:
                criterias['data'] = list()

            if isinstance(matchrule['value'], list):
                for v in matchrule['value']:
                    criterias['data'].append(v.encode('raw_unicode_escape'))
            else:
                criterias['data'].append(matchrule['value'].encode('raw_unicode_escape'))

        return criterias

    def enrich_event_sources(self, events: dict) -> None:
        """Enrich event sources.

        Args:
            events (dict): events

        Raises:
            TypeError: argument type was invalid
        """
        if not isinstance(events, dict):
            raise TypeError(f"events is {type(events)}; expected dict()")

        event_chunks = [list(events.keys())[x:(x + 5000)] for x in range(0, len(list(events.keys())), 5000)]

        for chunk in event_chunks:
            # Get sources
            self.log.debug(f"Getting sources for {len(chunk)} events")
            source_data = self.dbh.scanElementSourcesDirect(self.scanId, chunk)
            for row in source_data:
                events[row[8]]['source'].append({
                    'type': row[15],
                    'data': row[2],
                    'module': row[16],
                    'id': row[9],
                    'entity_type': self.type_entity_map[row[15]]
                })

    def enrich_event_children(self, events: dict) -> None:
        """Enrich event children.

        Args:
            events (dict): events

        Raises:
            TypeError: argument type was invalid
        """
        if not isinstance(events, dict):
            raise TypeError(f"events is {type(events)}; expected dict()")

        event_chunks = [list(events.keys())[x:x + 5000] for x in range(0, len(list(events.keys())), 5000)]

        for chunk in event_chunks:
            # Get children
            self.log.debug(f"Getting children for {len(chunk)} events")
            child_data = self.dbh.scanResultEvent(self.scanId, sourceId=chunk)
            for row in child_data:
                events[row[9]]['child'].append({
                    'type': row[4],
                    'data': row[1],
                    'module': row[3],
                    'id': row[8]
                })

    def enrich_event_entities(self, events: dict) -> None:
        """Given our starting set of ids, loop through the source
        of each until you have a match according to the criteria
        provided.

        Args:
            events (dict): events

        Raises:
            TypeError: argument type was invalid
        """
        if not isinstance(events, dict):
            raise TypeError(f"events is {type(events)}; expected dict()")

        entity_missing = dict()
        for event_id in events:
            if 'source' not in events[event_id]:
                continue

            row = events[event_id]
            # Go through each source if it's not an ENTITY, capture its ID
            # so we can capture its source, otherwise copy the source as
            # an entity record, since it's of a valid type to be considered one.
            for source in row['source']:
                if source['entity_type'] in ['ENTITY', 'INTERNAL']:
                    events[row['id']]['entity'].append(source)
                else:
                    # key is the element ID that we need to find an entity for
                    # by checking its source, and the value is the original ID
                    # for which we are seeking an entity. As we traverse up the
                    # discovery path the key will change but the value must always
                    # point back to the same ID.
                    entity_missing[source['id']] = row['id']

        while len(entity_missing) > 0:
            self.log.debug(f"{len(entity_missing.keys())} entities are missing, going deeper...")
            new_missing = dict()
            self.log.debug(f"Getting sources for {len(entity_missing.keys())} items")
            if len(entity_missing.keys()) > 5000:
                chunks = [list(entity_missing.keys())[x:x + 5000] for x in range(0, len(list(entity_missing.keys())), 5000)]
                entity_data = list()
                self.log.debug("Fetching data in chunks")
                for chunk in chunks:
                    self.log.debug(f"chunk size: {len(chunk)}")
                    entity_data.extend(self.dbh.scanElementSourcesDirect(self.scanId, chunk))
            else:
                self.log.debug(f"fetching sources for {len(entity_missing)} items")
                entity_data = self.dbh.scanElementSourcesDirect(self.scanId, list(entity_missing.keys()))

            for entity_candidate in entity_data:
                event_id = entity_missing[entity_candidate[8]]
                if self.type_entity_map[entity_candidate[15]] not in ['ENTITY', 'INTERNAL']:
                    # key of this dictionary is the id we need to now get a source for,
                    # and the value is the original ID of the item missing an entity
                    new_missing[entity_candidate[9]] = event_id
                else:
                    events[event_id]['entity'].append({
                        'type': entity_candidate[15],
                        'data': entity_candidate[2],
                        'module': entity_candidate[16],
                        'id': entity_candidate[9],
                        'entity_type': self.type_entity_map[entity_candidate[15]]
                    })

            if len(new_missing) == 0:
                break

            entity_missing = deepcopy(new_missing)

    def collect_from_db(self, matchrule: dict, fetchChildren: bool, fetchSources: bool, fetchEntities: bool) -> list:
        """Collect event values from database.

        Args:
            matchrule (dict): correlation rule
            fetchChildren (bool): TBD
            fetchSources (bool): TBD
            fetchEntities (bool): TBD

        Returns:
            list: event values
        """

        events = dict()

        self.log.debug(f"match rule: {matchrule}")
        # Parse the criteria from the match rule
        query_args = self.build_db_criteria(matchrule)
        if not query_args:
            self.log.error(f"Error encountered parsing match rule: {matchrule}.")
            return None

        query_args['instanceId'] = self.scanId
        self.log.debug(f"db query: {query_args}")
        for row in self.dbh.scanResultEvent(**query_args):
            events[row[8]] = {
                'type': row[4],
                'data': row[1],
                'module': row[3],
                'id': row[8],
                'entity_type': self.type_entity_map[row[4]],
                'source': [],
                'child': [],
                'entity': []
            }

        # You need to fetch sources if you need entities, since
        # the source will often be the entity.
        if fetchSources or fetchEntities:
            self.enrich_event_sources(events)

        if fetchChildren:
            self.enrich_event_children(events)

        if fetchEntities:
            self.enrich_event_entities(events)

        self.log.debug(f"returning {len(events.values())} events from match_rule {matchrule}")
        return list(events.values())

    def event_extract(self, event: dict, field: str) -> list:
        """Event event field.

        Args:
            event (dict): event
            field (str): TBD

        Returns:
            list: event data
        """

        if "." in field:
            ret = list()
            key, field = field.split(".")
            for subevent in event[key]:
                ret.extend(self.event_extract(subevent, field))
            return ret

        return [event[field]]

    def event_keep(self, event: dict, field: str, patterns: str, patterntype: str) -> bool:
        """Keep event field.

        Args:
            event (dict): event
            field (str): TBD
            patterns (str): TBD
            patterntype (str): TBD

        Returns:
            bool: TBD
        """

        if "." in field:
            key, field = field.split(".")
            for subevent in event[key]:
                if self.event_keep(subevent, field, patterns, patterntype):
                    return True
            return False

        value = event[field]

        if patterntype == "exact":
            ret = False
            for pattern in patterns:
                if pattern.startswith("not "):
                    ret = True
                    pattern = re.sub(r"^not\s+", "", pattern)
                    if value == pattern:
                        return False
                else:
                    ret = False
                    if value == pattern:
                        return True
            if ret:
                return True
            return False

        if patterntype == "regex":
            ret = False
            for pattern in patterns:
                if pattern.startswith("not "):
                    ret = True
                    pattern = re.sub(r"^not\s+", "", pattern)
                    if re.search(pattern, value, re.IGNORECASE):
                        return False
                else:
                    ret = False
                    if re.search(pattern, value, re.IGNORECASE):
                        return True
            if ret:
                return True
            return False

        return False

    def refine_collection(self, matchrule: dict, events: list) -> None:
        """Cull events from the events list if they don't meet the match criteria.

        Args:
            matchrule (dict): TBD
            events (list): TBD
        """
        patterns = list()

        if isinstance(matchrule['value'], list):
            for r in matchrule['value']:
                patterns.append(str(r))
        else:
            patterns = [str(matchrule['value'])]

        field = matchrule['field']
        self.log.debug(f"attempting to match {patterns} against the {field} field in {len(events)} events")

        # Go through each event, remove it if we shouldn't keep it
        # according to the match rule patterns.
        for event in events[:]:
            if not self.event_keep(event, field, patterns, matchrule['method']):
                self.log.debug(f"removing {event} because of {field}")
                events.remove(event)

    def collect_events(self, collection: dict, fetchChildren: bool, fetchSources: bool, fetchEntities: bool, collectIndex: int) -> list:
        """Collect data for aggregation and analysis.

        Args:
            collection (dict): TBD
            fetchChildren (bool): TBD
            fetchSources (bool): TBD
            fetchEntities (bool): TBD
            collectIndex (int): TBD

        Returns:
            list: TBD
        """
        step = 0

        for matchrule in collection:
            # First match rule means we fetch from the database, every
            # other step happens locally to avoid burdening the db.
            if step == 0:
                events = self.collect_from_db(matchrule,
                                              fetchEntities=fetchEntities,
                                              fetchChildren=fetchChildren,
                                              fetchSources=fetchSources)
                step += 1
                continue

            # Remove events in-place based on subsequent match-rules
            self.refine_collection(matchrule, events)

        # Stamp events with this collection ID for potential
        # use in analysis later.
        for e in events:
            e['_collection'] = collectIndex
            if fetchEntities:
                for ee in e['entity']:
                    ee['_collection'] = collectIndex
            if fetchChildren:
                for ce in e['child']:
                    ce['_collection'] = collectIndex
            if fetchSources:
                for se in e['source']:
                    se['_collection'] = collectIndex

        self.log.debug(f"returning collection ({len(events)})...")
        return events

    def aggregate_events(self, rule: dict, events: list) -> dict:
        """Aggregate events according to the rule.

        Args:
            rule (dict): correlation rule
            events (list): TBD

        Returns:
            dict: TBD
        """
        if 'field' not in rule:
            self.log.error(f"Unable to find field definition for aggregation in {rule['id']}")
            return False

        def event_strip(event: dict, field: str, value: str) -> None:
            """Strip sub fields that don't match value.

            Args:
                event (dict): event
                field (str): TBD
                value (str): TBD
            """
            topfield, subfield = field.split(".")
            if field.startswith(topfield + "."):
                for s in event[topfield]:
                    if s[subfield] != value:
                        event[topfield].remove(s)

        ret = dict()
        for e in events:
            buckets = self.event_extract(e, rule['field'])
            for b in buckets:
                e_copy = deepcopy(e)
                # if the bucket is of a child, source or entity,
                # remove the children, sources or entities that
                # aren't matching this bucket
                if "." in rule['field']:
                    event_strip(e_copy, rule['field'], b)
                if b in ret:
                    ret[b].append(e_copy)
                    continue
                ret[b] = [e_copy]

        return ret

    def analyze_events(self, rule: dict, buckets: dict) -> None:
        """Analyze events according to the rule. Modifies buckets in place.

        Args:
            rule (dict): correlation rule
            buckets (dict): TBD

        Todo:
            Implement support for 'both_collections'

        Returns:
            None
        """
        self.log.debug(f"applying {rule}")

        if rule['method'] == "threshold":
            return self.analysis_threshold(rule, buckets)
        if rule['method'] == "outlier":
            return self.analysis_outlier(rule, buckets)
        if rule['method'] == "first_collection_only":
            return self.analysis_first_collection_only(rule, buckets)
        if rule['method'] == "match_all_to_first_collection":
            return self.analysis_match_all_to_first_collection(rule, buckets)
        if rule['method'] == "both_collections":
            # TODO: Implement when genuine case appears
            pass

        return None

    def analysis_match_all_to_first_collection(self, rule: dict, buckets: dict) -> None:
        """Find buckets that are in the first collection.

        Args:
            rule (dict): correlation rule
            buckets (dict): TBD
        """
        self.log.debug(f"called with buckets {buckets}")

        def check_event(events: list, reference: list) -> bool:
            """Check event.

            Args:
                events (list): TBD
                reference (list): TBD

            Returns:
                bool: TBD
            """
            for event_data in events:
                if rule['match_method'] == 'subnet':
                    for r in reference:
                        try:
                            self.log.debug(f"checking if {event_data} is in {r}")
                            if netaddr.IPAddress(event_data) in netaddr.IPNetwork(r):
                                self.log.debug(f"found subnet match: {event_data} in {r}")
                                return True
                        except Exception:
                            pass

                if rule['match_method'] == 'exact':
                    if event_data in reference:
                        self.log.debug(f"found exact match: {event_data} in {reference}")
                        return True

                if rule['match_method'] == 'contains':
                    for r in reference:
                        if event_data in r:
                            self.log.debug(f"found pattern match: {event_data} in {r}")
                            return True

            return False

        # 1. Build up the list of values from collection 0
        # 2. Go through each event in each collection > 0 and drop any events that aren't
        #    in collection 0.
        # 3. For each bucket, if there are no events from collection > 0, drop them.

        reference = set()
        for bucket in buckets:
            for event in buckets[bucket]:
                if event['_collection'] == 0:
                    reference.update(self.event_extract(event, rule['field']))

        for bucket in list(buckets.keys()):
            pluszerocount = 0
            for event in buckets[bucket][:]:
                if event['_collection'] == 0:
                    continue
                pluszerocount += 1

                if not check_event(self.event_extract(event, rule['field']), reference):
                    buckets[bucket].remove(event)
                    pluszerocount -= 1

            # delete the bucket if there are no events > collection 0
            if pluszerocount == 0:
                del(buckets[bucket])

    def analysis_first_collection_only(self, rule: dict, buckets: dict) -> None:
        """analysis_first_collection_only TBD

        Args:
            rule (dict): TBD
            buckets (dict): TBD
        """

        colzero = set()

        for bucket in buckets:
            for e in buckets[bucket]:
                if e['_collection'] == 0:
                    colzero.add(e[rule['field']])

        for bucket in list(buckets.keys()):
            delete = False
            for e in buckets[bucket]:
                if e['_collection'] > 0 and e[rule['field']] in colzero:
                    delete = True
                    break
            if delete:
                del(buckets[bucket])

        # Remove buckets with collection > 0 values
        for bucket in list(buckets.keys()):
            for e in buckets[bucket]:
                if e['_collection'] > 0:
                    del(buckets[bucket])
                    break

    def analysis_outlier(self, rule: dict, buckets: dict) -> None:
        """analysis_outlier TBD

        Args:
            rule (dict): TBD
            buckets (dict): TBD
        """

        countmap = dict()
        for bucket in list(buckets.keys()):
            countmap[bucket] = len(buckets[bucket])

        if len(list(countmap.keys())) == 0:
            for bucket in list(buckets.keys()):
                del(buckets[bucket])
            return

        total = float(sum(countmap.values()))
        avg = total / float(len(list(countmap.keys())))
        avgpct = (avg / total) * 100.0

        self.log.debug(f"average percent is {avgpct} based on {avg} / {total} * 100.0")
        if avgpct < rule.get('noisy_percent', 10):
            self.log.debug(f"Not correlating because the average percent is {avgpct} (too anomalous)")
            for bucket in list(buckets.keys()):
                del(buckets[bucket])
            return

        # Figure out which buckets don't contain outliers and delete them
        delbuckets = list()
        for bucket in buckets:
            if (countmap[bucket] / total) * 100.0 > rule['maximum_percent']:
                delbuckets.append(bucket)

        for bucket in set(delbuckets):
            del(buckets[bucket])

    def analysis_threshold(self, rule: dict, buckets: dict) -> None:
        """analysis_treshold TBD

        Args:
            rule (dict): TBD
            buckets (dict): TBD
        """

        for bucket in list(buckets.keys()):
            countmap = dict()
            for event in buckets[bucket]:
                e = self.event_extract(event, rule['field'])
                for ef in e:
                    if ef not in countmap:
                        countmap[ef] = 0
                    countmap[ef] += 1

            if not rule.get('count_unique_only'):
                for v in countmap:
                    if countmap[v] >= rule.get('minimum', 0) and countmap[v] <= rule.get('maximum', 999999999):
                        continue
                    # Delete the bucket of events if it didn't meet the
                    # analysis criteria.
                    if bucket in buckets:
                        del(buckets[bucket])
                continue

            # If we're only looking at the number of times the requested
            # field appears in the bucket...
            uniques = len(list(countmap.keys()))
            if uniques < rule.get('minimum', 0) or uniques > rule.get('maximum', 999999999):
                del(buckets[bucket])

    def analyze_field_scope(self, field: str) -> list:
        """Analysis field scope.

        Args:
            field (str): TBD

        Returns:
            list: TBD
        """

        return [
            field.startswith('child.'),
            field.startswith('source.'),
            field.startswith('entity.')
        ]

    def analyze_rule_scope(self, rule: dict) -> list:
        """Analyze the rule for use of children, sources or entities
        so that they can be fetched during collection.

        Args:
            rule (dict): TBD

        Returns:
            list: TBD
        """

        children = False
        source = False
        entity = False

        if rule.get('collections'):
            for collection in rule['collections']:
                for method in collection['collect']:
                    c, s, e = self.analyze_field_scope(method['field'])
                    if c:
                        children = True
                    if s:
                        source = True
                    if e:
                        entity = True

        if rule.get('aggregation'):
            c, s, e = self.analyze_field_scope(rule['aggregation']['field'])
            if c:
                children = True
            if s:
                source = True
            if e:
                entity = True

        if rule.get('analysis'):
            for analysis in rule['analysis']:
                if 'field' not in analysis:
                    continue
                c, s, e = self.analyze_field_scope(analysis['field'])
                if c:
                    children = True
                if s:
                    source = True
                if e:
                    entity = True

        return children, source, entity

    def process_rule(self, rule: dict) -> list:
        """Work through all the components of the rule to produce a final
        set of data elements for building into correlations.

        Args:
            rule (dict): correlation rule

        Returns:
            list: TBD

        Raises:
            TypeError: argument type was invalid
        """
        if not isinstance(rule, dict):
            raise TypeError(f"rule is {type(rule)}; expected dict()")

        events = list()
        buckets = dict()

        fetchChildren, fetchSources, fetchEntities = self.analyze_rule_scope(rule)

        # Go through collections and collect the data from the DB
        for collectIndex, c in enumerate(rule.get('collections')):
            events.extend(self.collect_events(c['collect'],
                          fetchChildren,
                          fetchSources,
                          fetchEntities,
                          collectIndex))

        if not events:
            self.log.debug("No events found after going through collections.")
            return None

        self.log.debug(f"{len(events)} proceeding to next stage: aggregation.")
        self.log.debug(f"{events} ready to be processed.")

        # Perform aggregations. Aggregating breaks up the events
        # into buckets with the key being the field to aggregate by.
        if 'aggregation' in rule:
            buckets = self.aggregate_events(rule['aggregation'], events)
            if not buckets:
                self.log.debug("no buckets found after aggregation")
                return None
        else:
            buckets = {'default': events}

        # Perform analysis across the buckets
        if 'analysis' in rule:
            for method in rule['analysis']:
                # analyze() will operate on the bucket, make changes
                # and empty it if the analysis doesn't yield results.
                self.analyze_events(method, buckets)

        return buckets

    def build_correlation_title(self, rule: dict, data: list) -> str:
        """Build the correlation title with field substitution.

        Args:
            rule (dict): correlation rule
            data (list): TBD

        Returns:
            str: correlation rule title

        Raises:
            TypeError: argument type was invalid
        """
        if not isinstance(rule, dict):
            raise TypeError(f"rule is {type(rule)}; expected dict()")

        if not isinstance(data, list):
            raise TypeError(f"data is {type(data)}; expected list()")

        title = rule['headline']
        if isinstance(title, dict):
            title = title['text']

        fields = re.findall(r"{([a-z\.]+)}", title)
        for m in fields:
            try:
                v = self.event_extract(data[0], m)[0]
            except Exception:
                self.log.error(f"Field requested was not available: {m}")
            title = title.replace("{" + m + "}", v.replace("\r", "").split("\n")[0])
        return title

    def create_correlation(self, rule: dict, data: list, readonly: bool = False) -> bool:
        """Store the correlation result in the backend database.

        Args:
            rule (dict): correlation rule
            data (list): TBD
            readonly (bool): Dry run. Do not store the correlation result in the database.

        Returns:
            bool: Correlation rule result was stored successfully.
        """
        title = self.build_correlation_title(rule, data)
        self.log.info(f"New correlation [{rule['id']}]: {title}")

        if readonly:
            return True

        eventIds = list()
        for e in data:
            eventIds.append(e['id'])

        corrId = self.dbh.correlationResultCreate(self.scanId,
                                                  rule['id'],
                                                  rule['meta']['name'],
                                                  rule['meta']['description'],
                                                  rule['meta']['risk'],
                                                  rule['rawYaml'],
                                                  title,
                                                  eventIds)
        if not corrId:
            self.log.error(f"Unable to create correlation in DB for {rule['id']}")
            return False

        return True

    def check_ruleset_validity(self, rules: list) -> bool:
        """Syntax-check all rules.

        Args:
            rules (list): correlation rules

        Returns:
            bool: correlation rule set is valid
        """
        if not isinstance(rules, list):
            return False

        ok = True
        for rule in rules:
            if not self.check_rule_validity(rule):
                ok = False

        if ok:
            return True
        return False

    def check_rule_validity(self, rule: dict) -> bool:
        """Check a correlation rule for syntax errors.

        Args:
            rule (dict): correlation rule

        Returns:
            bool: correlation rule is valid
        """
        if not isinstance(rule, dict):
            return False

        fields = set(rule.keys())

        if not fields:
            self.log.error("Rule is empty.")
            return False

        if not rule.get('id'):
            self.log.error("Rule has no ID.")
            return False

        ok = True

        for f in self.mandatory_components:
            if f not in fields:
                self.log.error(f"Mandatory rule component, {f}, not found in {rule['id']}.")
                ok = False

        validfields = set(self.components.keys())
        if len(fields.union(validfields)) > len(validfields):
            self.log.error(f"Unexpected field(s) in correlation rule {rule['id']}: {[f for f in fields if f not in validfields]}")
            ok = False

        for collection in rule.get('collections', list()):
            # Match by data element type(s) or type regexps
            for matchrule in collection['collect']:
                if matchrule['method'] not in ["exact", "regex"]:
                    self.log.error(f"Invalid collection method: {matchrule['method']}")
                    ok = False

                if matchrule['field'] not in ["type", "module", "data",
                                              "child.type", "child.module", "child.data",
                                              "source.type", "source.module", "source.data",
                                              "entity.type", "entity.module", "entity.data"]:
                    self.log.error(f"Invalid collection field: {matchrule['field']}")
                    ok = False

                if 'value' not in matchrule:
                    self.log.error(f"Value missing for collection rule in {rule['id']}")
                    ok = False

            if 'analysis' in rule:
                valid_methods = ["threshold", "outlier", "first_collection_only",
                                 "both_collections", "match_all_to_first_collection"]
                for method in rule['analysis']:
                    if method['method'] not in valid_methods:
                        self.log.error(f"Unknown analysis method '{method['method']}' defined for {rule['id']}.")
                        ok = False

        for field in fields:
            # Check strict options are defined
            strictoptions = self.components[field].get('strict', list())
            otheroptions = self.components[field].get('optional', list())
            alloptions = set(strictoptions).union(otheroptions)

            for opt in strictoptions:
                if isinstance(rule[field], list):
                    for item, optelement in enumerate(rule[field]):
                        if not optelement.get(opt):
                            self.log.error(f"Required field for {field} missing in {rule['id']}, item {item}: {opt}")
                            ok = False
                    continue

                if isinstance(rule[field], dict):
                    if not rule[field].get(opt):
                        self.log.error(f"Required field for {field} missing in {rule['id']}: {opt}")
                        ok = False

                else:
                    self.log.error(f"Rule field '{field}' is not a list() or dict()")
                    ok = False

                # Check if any of the options aren't valid
                if opt not in alloptions:
                    self.log.error(f"Unexpected option, {opt}, found in {field} for {rule['id']}. Must be one of {alloptions}.")
                    ok = False

        if ok:
            return True
        return False
