# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for Tor extra-info descriptors. These are published by relays whenever
their server descriptor is published and have a similar format. However, unlike
server descriptors these don't contain information that Tor clients require to
function and as such aren't fetched by default.

Defined in section 2.2 of the `dir-spec
<https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_,
extra-info descriptors contain interesting but non-vital information such as
usage statistics. Tor clients cannot request these documents for bridges.

Extra-info descriptors are available from a few sources...

* If you have 'DownloadExtraInfo 1' in your torrc...

 * control port via 'GETINFO extra-info/digest/\*' queries
 * the 'cached-extrainfo' file in tor's data directory

* Archived descriptors provided by CollecTor
  (https://collector.torproject.org/).

* Directory authorities and mirrors via their DirPort.

**Module Overview:**

::

  ExtraInfoDescriptor - Tor extra-info descriptor.
    |- RelayExtraInfoDescriptor - Extra-info descriptor for a relay.
    |- BridgeExtraInfoDescriptor - Extra-info descriptor for a bridge.
    |
    +- digest - calculates the upper-case hex digest value for our content

.. data:: DirResponse (enum)

  Enumeration for known statuses for ExtraInfoDescriptor's dir_*_responses.

  =================== ===========
  DirResponse         Description
  =================== ===========
  **OK**              network status requests that were answered
  **NOT_ENOUGH_SIGS** network status wasn't signed by enough authorities
  **UNAVAILABLE**     requested network status was unavailable
  **NOT_FOUND**       requested network status was not found
  **NOT_MODIFIED**    network status unmodified since If-Modified-Since time
  **BUSY**            directory was busy
  =================== ===========

.. data:: DirStat (enum)

  Enumeration for known stats for ExtraInfoDescriptor's dir_*_direct_dl and
  dir_*_tunneled_dl.

  ===================== ===========
  DirStat               Description
  ===================== ===========
  **COMPLETE**          requests that completed successfully
  **TIMEOUT**           requests that didn't complete within a ten minute timeout
  **RUNNING**           requests still in process when measurement's taken
  **MIN**               smallest rate at which a descriptor was downloaded in B/s
  **MAX**               largest rate at which a descriptor was downloaded in B/s
  **D1-4** and **D6-9** rate of the slowest x/10 download rates in B/s
  **Q1** and **Q3**     rate of the slowest and fastest quarter download rates in B/s
  **MD**                median download rate in B/s
  ===================== ===========
"""

import functools
import hashlib
import re

import stem.util.connection
import stem.util.enum
import stem.util.str_tools

from stem.descriptor import (
  PGP_BLOCK_END,
  Descriptor,
  _read_until_keywords,
  _get_descriptor_components,
  _value,
  _values,
  _parse_timestamp_line,
  _parse_forty_character_hex,
  _parse_key_block,
)

try:
  # added in python 3.2
  from functools import lru_cache
except ImportError:
  from stem.util.lru_cache import lru_cache

# known statuses for dirreq-v2-resp and dirreq-v3-resp...
DirResponse = stem.util.enum.Enum(
  ('OK', 'ok'),
  ('NOT_ENOUGH_SIGS', 'not-enough-sigs'),
  ('UNAVAILABLE', 'unavailable'),
  ('NOT_FOUND', 'not-found'),
  ('NOT_MODIFIED', 'not-modified'),
  ('BUSY', 'busy'),
)

# known stats for dirreq-v2/3-direct-dl and dirreq-v2/3-tunneled-dl...
dir_stats = ['complete', 'timeout', 'running', 'min', 'max', 'q1', 'q3', 'md']
dir_stats += ['d%i' % i for i in range(1, 5)]
dir_stats += ['d%i' % i for i in range(6, 10)]
DirStat = stem.util.enum.Enum(*[(stat.upper(), stat) for stat in dir_stats])

# relay descriptors must have exactly one of the following
REQUIRED_FIELDS = (
  'extra-info',
  'published',
  'router-signature',
)

# optional entries that can appear at most once
SINGLE_FIELDS = (
  'read-history',
  'write-history',
  'geoip-db-digest',
  'geoip6-db-digest',
  'bridge-stats-end',
  'bridge-ips',
  'dirreq-stats-end',
  'dirreq-v2-ips',
  'dirreq-v3-ips',
  'dirreq-v2-reqs',
  'dirreq-v3-reqs',
  'dirreq-v2-share',
  'dirreq-v3-share',
  'dirreq-v2-resp',
  'dirreq-v3-resp',
  'dirreq-v2-direct-dl',
  'dirreq-v3-direct-dl',
  'dirreq-v2-tunneled-dl',
  'dirreq-v3-tunneled-dl',
  'dirreq-read-history',
  'dirreq-write-history',
  'entry-stats-end',
  'entry-ips',
  'cell-stats-end',
  'cell-processed-cells',
  'cell-queued-cells',
  'cell-time-in-queue',
  'cell-circuits-per-decile',
  'conn-bi-direct',
  'exit-stats-end',
  'exit-kibibytes-written',
  'exit-kibibytes-read',
  'exit-streams-opened',
)


_timestamp_re = re.compile('^(.*) \(([0-9]+) s\)( .*)?$')
_locale_re = re.compile('^[a-zA-Z0-9\?]{2}$')


def _parse_file(descriptor_file, is_bridge = False, validate = False, **kwargs):
  """
  Iterates over the extra-info descriptors in a file.

  :param file descriptor_file: file with descriptor content
  :param bool is_bridge: parses the file as being a bridge descriptor
  :param bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :param dict kwargs: additional arguments for the descriptor constructor

  :returns: iterator for :class:`~stem.descriptor.extrainfo_descriptor.ExtraInfoDescriptor`
    instances in the file

  :raises:
    * **ValueError** if the contents is malformed and validate is **True**
    * **IOError** if the file can't be read
  """

  while True:
    if not is_bridge:
      extrainfo_content = _read_until_keywords('router-signature', descriptor_file)

      # we've reached the 'router-signature', now include the pgp style block

      block_end_prefix = PGP_BLOCK_END.split(' ', 1)[0]
      extrainfo_content += _read_until_keywords(block_end_prefix, descriptor_file, True)
    else:
      extrainfo_content = _read_until_keywords('router-digest', descriptor_file, True)

    if extrainfo_content:
      if extrainfo_content[0].startswith(b'@type'):
        extrainfo_content = extrainfo_content[1:]

      if is_bridge:
        yield BridgeExtraInfoDescriptor(bytes.join(b'', extrainfo_content), validate, **kwargs)
      else:
        yield RelayExtraInfoDescriptor(bytes.join(b'', extrainfo_content), validate, **kwargs)
    else:
      break  # done parsing file


def _parse_timestamp_and_interval(keyword, content):
  """
  Parses a 'YYYY-MM-DD HH:MM:SS (NSEC s) *' entry.

  :param str keyword: line's keyword
  :param str content: line content to be parsed

  :returns: **tuple** of the form (timestamp (**datetime**), interval
    (**int**), remaining content (**str**))

  :raises: **ValueError** if the content is malformed
  """

  line = '%s %s' % (keyword, content)
  content_match = _timestamp_re.match(content)

  if not content_match:
    raise ValueError('Malformed %s line: %s' % (keyword, line))

  timestamp_str, interval, remainder = content_match.groups()

  if remainder:
    remainder = remainder[1:]  # remove leading space

  if not interval.isdigit():
    raise ValueError("%s line's interval wasn't a number: %s" % (keyword, line))

  try:
    timestamp = stem.util.str_tools._parse_timestamp(timestamp_str)
    return timestamp, int(interval), remainder
  except ValueError:
    raise ValueError("%s line's timestamp wasn't parsable: %s" % (keyword, line))


def _parse_extra_info_line(descriptor, entries):
  # "extra-info" Nickname Fingerprint

  value = _value('extra-info', entries)
  extra_info_comp = value.split()

  if len(extra_info_comp) < 2:
    raise ValueError('Extra-info line must have two values: extra-info %s' % value)
  elif not stem.util.tor_tools.is_valid_nickname(extra_info_comp[0]):
    raise ValueError("Extra-info line entry isn't a valid nickname: %s" % extra_info_comp[0])
  elif not stem.util.tor_tools.is_valid_fingerprint(extra_info_comp[1]):
    raise ValueError('Tor relay fingerprints consist of forty hex digits: %s' % extra_info_comp[1])

  descriptor.nickname = extra_info_comp[0]
  descriptor.fingerprint = extra_info_comp[1]


def _parse_transport_line(descriptor, entries):
  # "transport" transportname address:port [arglist]
  # Everything after the transportname is scrubbed in published bridge
  # descriptors, so we'll never see it in practice.
  #
  # These entries really only make sense for bridges, but have been seen
  # on non-bridges in the wild when the relay operator configured it this
  # way.

  transports = {}

  for value in _values('transport', entries):
    name, address, port, args = None, None, None, None

    if ' ' not in value:
      # scrubbed
      name = value
    else:
      # not scrubbed
      value_comp = value.split()

      if len(value_comp) < 1:
        raise ValueError('Transport line is missing its transport name: transport %s' % value)
      elif len(value_comp) < 2:
        raise ValueError('Transport line is missing its address:port value: transport %s' % value)
      elif ':' not in value_comp[1]:
        raise ValueError("Transport line's address:port entry is missing a colon: transport %s" % value)

      name = value_comp[0]
      address, port_str = value_comp[1].split(':', 1)

      if not stem.util.connection.is_valid_ipv4_address(address) or \
             stem.util.connection.is_valid_ipv6_address(address):
        raise ValueError('Transport line has a malformed address: transport %s' % value)
      elif not stem.util.connection.is_valid_port(port_str):
        raise ValueError('Transport line has a malformed port: transport %s' % value)

      port = int(port_str)
      args = value_comp[2:] if len(value_comp) >= 3 else []

    transports[name] = (address, port, args)

  descriptor.transport = transports


def _parse_cell_circuits_per_decline_line(descriptor, entries):
  # "cell-circuits-per-decile" num

  value = _value('cell-circuits-per-decile', entries)

  if not value.isdigit():
    raise ValueError('Non-numeric cell-circuits-per-decile value: %s' % value)
  elif int(value) < 0:
    raise ValueError('Negative cell-circuits-per-decile value: %s' % value)

  descriptor.cell_circuits_per_decile = int(value)


def _parse_dirreq_line(keyword, recognized_counts_attr, unrecognized_counts_attr, descriptor, entries):
  value = _value(keyword, entries)

  recognized_counts = {}
  unrecognized_counts = {}

  is_response_stats = keyword in ('dirreq-v2-resp', 'dirreq-v3-resp')
  key_set = DirResponse if is_response_stats else DirStat

  key_type = 'STATUS' if is_response_stats else 'STAT'
  error_msg = '%s lines should contain %s=COUNT mappings: %s %s' % (keyword, key_type, keyword, value)

  if value:
    for entry in value.split(','):
      if '=' not in entry:
        raise ValueError(error_msg)

      status, count = entry.split('=', 1)

      if count.isdigit():
        if status in key_set:
          recognized_counts[status] = int(count)
        else:
          unrecognized_counts[status] = int(count)
      else:
        raise ValueError(error_msg)

  setattr(descriptor, recognized_counts_attr, recognized_counts)
  setattr(descriptor, unrecognized_counts_attr, unrecognized_counts)


def _parse_dirreq_share_line(keyword, attribute, descriptor, entries):
  value = _value(keyword, entries)

  if not value.endswith('%'):
    raise ValueError('%s lines should be a percentage: %s %s' % (keyword, keyword, value))
  elif float(value[:-1]) < 0:
    raise ValueError('Negative percentage value: %s %s' % (keyword, value))

  # bug means it might be above 100%: https://lists.torproject.org/pipermail/tor-dev/2012-June/003679.html

  setattr(descriptor, attribute, float(value[:-1]) / 100)


def _parse_cell_line(keyword, attribute, descriptor, entries):
  # "<keyword>" num,...,num

  value = _value(keyword, entries)
  entries, exc = [], None

  if value:
    for entry in value.split(','):
      try:
        # Values should be positive but as discussed in ticket #5849
        # there was a bug around this. It was fixed in tor 0.2.2.1.

        entries.append(float(entry))
      except ValueError:
        exc = ValueError('Non-numeric entry in %s listing: %s %s' % (keyword, keyword, value))

  setattr(descriptor, attribute, entries)

  if exc:
    raise exc


def _parse_timestamp_and_interval_line(keyword, end_attribute, interval_attribute, descriptor, entries):
  # "<keyword>" YYYY-MM-DD HH:MM:SS (NSEC s)

  timestamp, interval, _ = _parse_timestamp_and_interval(keyword, _value(keyword, entries))
  setattr(descriptor, end_attribute, timestamp)
  setattr(descriptor, interval_attribute, interval)


def _parse_conn_bi_direct_line(descriptor, entries):
  # "conn-bi-direct" YYYY-MM-DD HH:MM:SS (NSEC s) BELOW,READ,WRITE,BOTH

  value = _value('conn-bi-direct', entries)
  timestamp, interval, remainder = _parse_timestamp_and_interval('conn-bi-direct', value)
  stats = remainder.split(',')

  if len(stats) != 4 or not (stats[0].isdigit() and stats[1].isdigit() and stats[2].isdigit() and stats[3].isdigit()):
    raise ValueError('conn-bi-direct line should end with four numeric values: conn-bi-direct %s' % value)

  descriptor.conn_bi_direct_end = timestamp
  descriptor.conn_bi_direct_interval = interval
  descriptor.conn_bi_direct_below = int(stats[0])
  descriptor.conn_bi_direct_read = int(stats[1])
  descriptor.conn_bi_direct_write = int(stats[2])
  descriptor.conn_bi_direct_both = int(stats[3])


def _parse_history_line(keyword, end_attribute, interval_attribute, values_attribute, descriptor, entries):
  # "<keyword>" YYYY-MM-DD HH:MM:SS (NSEC s) NUM,NUM,NUM,NUM,NUM...

  value = _value(keyword, entries)
  timestamp, interval, remainder = _parse_timestamp_and_interval(keyword, value)
  history_values = []

  if remainder:
    try:
      history_values = [int(entry) for entry in remainder.split(',')]
    except ValueError:
      raise ValueError('%s line has non-numeric values: %s %s' % (keyword, keyword, value))

  setattr(descriptor, end_attribute, timestamp)
  setattr(descriptor, interval_attribute, interval)
  setattr(descriptor, values_attribute, history_values)


def _parse_port_count_line(keyword, attribute, descriptor, entries):
  # "<keyword>" port=N,port=N,...

  value, port_mappings = _value(keyword, entries), {}
  error_msg = 'Entries in %s line should only be PORT=N entries: %s %s' % (keyword, keyword, value)

  if value:
    for entry in value.split(','):
      if '=' not in entry:
        raise ValueError(error_msg)

      port, stat = entry.split('=', 1)

      if (port == 'other' or stem.util.connection.is_valid_port(port)) and stat.isdigit():
        if port != 'other':
          port = int(port)

        port_mappings[port] = int(stat)
      else:
        raise ValueError(error_msg)

  setattr(descriptor, attribute, port_mappings)


def _parse_geoip_to_count_line(keyword, attribute, descriptor, entries):
  # "<keyword>" CC=N,CC=N,...
  #
  # The maxmind geoip (https://www.maxmind.com/app/iso3166) has numeric
  # locale codes for some special values, for instance...
  #   A1,"Anonymous Proxy"
  #   A2,"Satellite Provider"
  #   ??,"Unknown"

  value, locale_usage = _value(keyword, entries), {}
  error_msg = 'Entries in %s line should only be CC=N entries: %s %s' % (keyword, keyword, value)

  if value:
    for entry in value.split(','):
      if '=' not in entry:
        raise ValueError(error_msg)

      locale, count = entry.split('=', 1)

      if _locale_re.match(locale) and count.isdigit():
        locale_usage[locale] = int(count)
      else:
        raise ValueError(error_msg)

  setattr(descriptor, attribute, locale_usage)


def _parse_bridge_ip_versions_line(descriptor, entries):
  value, ip_versions = _value('bridge-ip-versions', entries), {}

  if value:
    for entry in value.split(','):
      if '=' not in entry:
        raise stem.ProtocolError("The bridge-ip-versions should be a comma separated listing of '<protocol>=<count>' mappings: bridge-ip-versions %s" % value)

      protocol, count = entry.split('=', 1)

      if not count.isdigit():
        raise stem.ProtocolError('IP protocol count was non-numeric (%s): bridge-ip-versions %s' % (count, value))

      ip_versions[protocol] = int(count)

  descriptor.ip_versions = ip_versions


def _parse_bridge_ip_transports_line(descriptor, entries):
  value, ip_transports = _value('bridge-ip-transports', entries), {}

  if value:
    for entry in value.split(','):
      if '=' not in entry:
        raise stem.ProtocolError("The bridge-ip-transports should be a comma separated listing of '<protocol>=<count>' mappings: bridge-ip-transports %s" % value)

      protocol, count = entry.split('=', 1)

      if not count.isdigit():
        raise stem.ProtocolError('Transport count was non-numeric (%s): bridge-ip-transports %s' % (count, value))

      ip_transports[protocol] = int(count)

  descriptor.ip_transports = ip_transports


def _parse_hs_stats(keyword, stat_attribute, extra_attribute, descriptor, entries):
  # "<keyword>" num key=val key=val...

  value, stat, extra = _value(keyword, entries), None, {}

  if value is not None:
    value_comp = value.split()

    if not value_comp:
      raise ValueError("'%s' line was blank" % keyword)

    try:
      stat = int(value_comp[0])
    except ValueError:
      raise ValueError("'%s' stat was non-numeric (%s): %s %s" % (keyword, value_comp[0], keyword, value))

    for entry in value_comp[1:]:
      if '=' not in entry:
        raise ValueError('Entries after the stat in %s lines should only be key=val entries: %s %s' % (keyword, keyword, value))

      key, val = entry.split('=', 1)
      extra[key] = val

  setattr(descriptor, stat_attribute, stat)
  setattr(descriptor, extra_attribute, extra)


_parse_geoip_db_digest_line = _parse_forty_character_hex('geoip-db-digest', 'geoip_db_digest')
_parse_geoip6_db_digest_line = _parse_forty_character_hex('geoip6-db-digest', 'geoip6_db_digest')
_parse_dirreq_v2_resp_line = functools.partial(_parse_dirreq_line, 'dirreq-v2-resp', 'dir_v2_responses', 'dir_v2_responses_unknown')
_parse_dirreq_v3_resp_line = functools.partial(_parse_dirreq_line, 'dirreq-v3-resp', 'dir_v3_responses', 'dir_v3_responses_unknown')
_parse_dirreq_v2_direct_dl_line = functools.partial(_parse_dirreq_line, 'dirreq-v2-direct-dl', 'dir_v2_direct_dl', 'dir_v2_direct_dl_unknown')
_parse_dirreq_v3_direct_dl_line = functools.partial(_parse_dirreq_line, 'dirreq-v3-direct-dl', 'dir_v3_direct_dl', 'dir_v3_direct_dl_unknown')
_parse_dirreq_v2_tunneled_dl_line = functools.partial(_parse_dirreq_line, 'dirreq-v2-tunneled-dl', 'dir_v2_tunneled_dl', 'dir_v2_tunneled_dl_unknown')
_parse_dirreq_v3_tunneled_dl_line = functools.partial(_parse_dirreq_line, 'dirreq-v3-tunneled-dl', 'dir_v3_tunneled_dl', 'dir_v3_tunneled_dl_unknown')
_parse_dirreq_v2_share_line = functools.partial(_parse_dirreq_share_line, 'dirreq-v2-share', 'dir_v2_share')
_parse_dirreq_v3_share_line = functools.partial(_parse_dirreq_share_line, 'dirreq-v3-share', 'dir_v3_share')
_parse_cell_processed_cells_line = functools.partial(_parse_cell_line, 'cell-processed-cells', 'cell_processed_cells')
_parse_cell_queued_cells_line = functools.partial(_parse_cell_line, 'cell-queued-cells', 'cell_queued_cells')
_parse_cell_time_in_queue_line = functools.partial(_parse_cell_line, 'cell-time-in-queue', 'cell_time_in_queue')
_parse_published_line = _parse_timestamp_line('published', 'published')
_parse_geoip_start_time_line = _parse_timestamp_line('geoip-start-time', 'geoip_start_time')
_parse_cell_stats_end_line = functools.partial(_parse_timestamp_and_interval_line, 'cell-stats-end', 'cell_stats_end', 'cell_stats_interval')
_parse_entry_stats_end_line = functools.partial(_parse_timestamp_and_interval_line, 'entry-stats-end', 'entry_stats_end', 'entry_stats_interval')
_parse_exit_stats_end_line = functools.partial(_parse_timestamp_and_interval_line, 'exit-stats-end', 'exit_stats_end', 'exit_stats_interval')
_parse_bridge_stats_end_line = functools.partial(_parse_timestamp_and_interval_line, 'bridge-stats-end', 'bridge_stats_end', 'bridge_stats_interval')
_parse_dirreq_stats_end_line = functools.partial(_parse_timestamp_and_interval_line, 'dirreq-stats-end', 'dir_stats_end', 'dir_stats_interval')
_parse_read_history_line = functools.partial(_parse_history_line, 'read-history', 'read_history_end', 'read_history_interval', 'read_history_values')
_parse_write_history_line = functools.partial(_parse_history_line, 'write-history', 'write_history_end', 'write_history_interval', 'write_history_values')
_parse_dirreq_read_history_line = functools.partial(_parse_history_line, 'dirreq-read-history', 'dir_read_history_end', 'dir_read_history_interval', 'dir_read_history_values')
_parse_dirreq_write_history_line = functools.partial(_parse_history_line, 'dirreq-write-history', 'dir_write_history_end', 'dir_write_history_interval', 'dir_write_history_values')
_parse_exit_kibibytes_written_line = functools.partial(_parse_port_count_line, 'exit-kibibytes-written', 'exit_kibibytes_written')
_parse_exit_kibibytes_read_line = functools.partial(_parse_port_count_line, 'exit-kibibytes-read', 'exit_kibibytes_read')
_parse_exit_streams_opened_line = functools.partial(_parse_port_count_line, 'exit-streams-opened', 'exit_streams_opened')
_parse_hidden_service_stats_end_line = _parse_timestamp_line('hidserv-stats-end', 'hs_stats_end')
_parse_hidden_service_rend_relayed_cells_line = functools.partial(_parse_hs_stats, 'hidserv-rend-relayed-cells', 'hs_rend_cells', 'hs_rend_cells_attr')
_parse_hidden_service_dir_onions_seen_line = functools.partial(_parse_hs_stats, 'hidserv-dir-onions-seen', 'hs_dir_onions_seen', 'hs_dir_onions_seen_attr')
_parse_dirreq_v2_ips_line = functools.partial(_parse_geoip_to_count_line, 'dirreq-v2-ips', 'dir_v2_ips')
_parse_dirreq_v3_ips_line = functools.partial(_parse_geoip_to_count_line, 'dirreq-v3-ips', 'dir_v3_ips')
_parse_dirreq_v2_reqs_line = functools.partial(_parse_geoip_to_count_line, 'dirreq-v2-reqs', 'dir_v2_requests')
_parse_dirreq_v3_reqs_line = functools.partial(_parse_geoip_to_count_line, 'dirreq-v3-reqs', 'dir_v3_requests')
_parse_geoip_client_origins_line = functools.partial(_parse_geoip_to_count_line, 'geoip-client-origins', 'geoip_client_origins')
_parse_entry_ips_line = functools.partial(_parse_geoip_to_count_line, 'entry-ips', 'entry_ips')
_parse_bridge_ips_line = functools.partial(_parse_geoip_to_count_line, 'bridge-ips', 'bridge_ips')
_parse_router_digest_line = _parse_forty_character_hex('router-digest', '_digest')
_parse_router_signature_line = _parse_key_block('router-signature', 'signature', 'SIGNATURE')


class ExtraInfoDescriptor(Descriptor):
  """
  Extra-info descriptor document.

  :var str nickname: **\*** relay's nickname
  :var str fingerprint: **\*** identity key fingerprint
  :var datetime published: **\*** time in UTC when this descriptor was made
  :var str geoip_db_digest: sha1 of the geoIP database file for IPv4 addresses
  :var str geoip6_db_digest: sha1 of the geoIP database file for IPv6 addresses
  :var dict transport: **\*** mapping of transport methods to their (address,
    port, args) tuple, these usually appear on bridges in which case all of
    those are **None**

  **Bi-directional connection usage:**

  :var datetime conn_bi_direct_end: end of the sampling interval
  :var int conn_bi_direct_interval: seconds per interval
  :var int conn_bi_direct_below: connections that read/wrote less than 20 KiB
  :var int conn_bi_direct_read: connections that read at least 10x more than wrote
  :var int conn_bi_direct_write: connections that wrote at least 10x more than read
  :var int conn_bi_direct_both: remaining connections

  **Bytes read/written for relayed traffic:**

  :var datetime read_history_end: end of the sampling interval
  :var int read_history_interval: seconds per interval
  :var list read_history_values: bytes read during each interval

  :var datetime write_history_end: end of the sampling interval
  :var int write_history_interval: seconds per interval
  :var list write_history_values: bytes written during each interval

  **Cell relaying statistics:**

  :var datetime cell_stats_end: end of the period when stats were gathered
  :var int cell_stats_interval: length in seconds of the interval
  :var list cell_processed_cells: measurement of processed cells per circuit
  :var list cell_queued_cells: measurement of queued cells per circuit
  :var list cell_time_in_queue: mean enqueued time in milliseconds for cells
  :var int cell_circuits_per_decile: mean number of circuits in a decile

  **Directory Mirror Attributes:**

  :var datetime dir_stats_end: end of the period when stats were gathered
  :var int dir_stats_interval: length in seconds of the interval
  :var dict dir_v2_ips: mapping of locales to rounded count of requester ips
  :var dict dir_v3_ips: mapping of locales to rounded count of requester ips
  :var float dir_v2_share: percent of total directory traffic it expects to serve
  :var float dir_v3_share: percent of total directory traffic it expects to serve
  :var dict dir_v2_requests: mapping of locales to rounded count of requests
  :var dict dir_v3_requests: mapping of locales to rounded count of requests

  :var dict dir_v2_responses: mapping of :data:`~stem.descriptor.extrainfo_descriptor.DirResponse` to their rounded count
  :var dict dir_v3_responses: mapping of :data:`~stem.descriptor.extrainfo_descriptor.DirResponse` to their rounded count
  :var dict dir_v2_responses_unknown: mapping of unrecognized statuses to their count
  :var dict dir_v3_responses_unknown: mapping of unrecognized statuses to their count

  :var dict dir_v2_direct_dl: mapping of :data:`~stem.descriptor.extrainfo_descriptor.DirStat` to measurement over DirPort
  :var dict dir_v3_direct_dl: mapping of :data:`~stem.descriptor.extrainfo_descriptor.DirStat` to measurement over DirPort
  :var dict dir_v2_direct_dl_unknown: mapping of unrecognized stats to their measurement
  :var dict dir_v3_direct_dl_unknown: mapping of unrecognized stats to their measurement

  :var dict dir_v2_tunneled_dl: mapping of :data:`~stem.descriptor.extrainfo_descriptor.DirStat` to measurement over ORPort
  :var dict dir_v3_tunneled_dl: mapping of :data:`~stem.descriptor.extrainfo_descriptor.DirStat` to measurement over ORPort
  :var dict dir_v2_tunneled_dl_unknown: mapping of unrecognized stats to their measurement
  :var dict dir_v3_tunneled_dl_unknown: mapping of unrecognized stats to their measurement

  **Bytes read/written for directory mirroring:**

  :var datetime dir_read_history_end: end of the sampling interval
  :var int dir_read_history_interval: seconds per interval
  :var list dir_read_history_values: bytes read during each interval

  :var datetime dir_write_history_end: end of the sampling interval
  :var int dir_write_history_interval: seconds per interval
  :var list dir_write_history_values: bytes read during each interval

  **Guard Attributes:**

  :var datetime entry_stats_end: end of the period when stats were gathered
  :var int entry_stats_interval: length in seconds of the interval
  :var dict entry_ips: mapping of locales to rounded count of unique user ips

  **Exit Attributes:**

  :var datetime exit_stats_end: end of the period when stats were gathered
  :var int exit_stats_interval: length in seconds of the interval
  :var dict exit_kibibytes_written: traffic per port (keys are ints or 'other')
  :var dict exit_kibibytes_read: traffic per port (keys are ints or 'other')
  :var dict exit_streams_opened: streams per port (keys are ints or 'other')

  **Hidden Service Attributes:**

  :var datetime hs_stats_end: end of the sampling interval
  :var int hs_rend_cells: rounded count of the RENDEZVOUS1 cells seen
  :var int hs_rend_cells_attr: **\*** attributes provided for the hs_rend_cells
  :var int hs_dir_onions_seen: rounded count of the identities seen
  :var int hs_dir_onions_seen_attr: **\*** attributes provided for the hs_dir_onions_seen

  **Bridge Attributes:**

  :var datetime bridge_stats_end: end of the period when stats were gathered
  :var int bridge_stats_interval: length in seconds of the interval
  :var dict bridge_ips: mapping of locales to rounded count of unique user ips
  :var datetime geoip_start_time: replaced by bridge_stats_end (deprecated)
  :var dict geoip_client_origins: replaced by bridge_ips (deprecated)
  :var dict ip_versions: mapping of ip protocols to a rounded count for the number of users
  :var dict ip_versions: mapping of ip transports to a count for the number of users

  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined

  .. versionchanged:: 1.4.0
     Added the hs_stats_end, hs_rend_cells, hs_rend_cells_attr,
     hs_dir_onions_seen, and hs_dir_onions_seen_attr attributes.
  """

  ATTRIBUTES = {
    'nickname': (None, _parse_extra_info_line),
    'fingerprint': (None, _parse_extra_info_line),
    'published': (None, _parse_published_line),
    'geoip_db_digest': (None, _parse_geoip_db_digest_line),
    'geoip6_db_digest': (None, _parse_geoip6_db_digest_line),
    'transport': ({}, _parse_transport_line),

    'conn_bi_direct_end': (None, _parse_conn_bi_direct_line),
    'conn_bi_direct_interval': (None, _parse_conn_bi_direct_line),
    'conn_bi_direct_below': (None, _parse_conn_bi_direct_line),
    'conn_bi_direct_read': (None, _parse_conn_bi_direct_line),
    'conn_bi_direct_write': (None, _parse_conn_bi_direct_line),
    'conn_bi_direct_both': (None, _parse_conn_bi_direct_line),

    'read_history_end': (None, _parse_read_history_line),
    'read_history_interval': (None, _parse_read_history_line),
    'read_history_values': (None, _parse_read_history_line),

    'write_history_end': (None, _parse_write_history_line),
    'write_history_interval': (None, _parse_write_history_line),
    'write_history_values': (None, _parse_write_history_line),

    'cell_stats_end': (None, _parse_cell_stats_end_line),
    'cell_stats_interval': (None, _parse_cell_stats_end_line),
    'cell_processed_cells': (None, _parse_cell_processed_cells_line),
    'cell_queued_cells': (None, _parse_cell_queued_cells_line),
    'cell_time_in_queue': (None, _parse_cell_time_in_queue_line),
    'cell_circuits_per_decile': (None, _parse_cell_circuits_per_decline_line),

    'dir_stats_end': (None, _parse_dirreq_stats_end_line),
    'dir_stats_interval': (None, _parse_dirreq_stats_end_line),
    'dir_v2_ips': (None, _parse_dirreq_v2_ips_line),
    'dir_v3_ips': (None, _parse_dirreq_v3_ips_line),
    'dir_v2_share': (None, _parse_dirreq_v2_share_line),
    'dir_v3_share': (None, _parse_dirreq_v3_share_line),
    'dir_v2_requests': (None, _parse_dirreq_v2_reqs_line),
    'dir_v3_requests': (None, _parse_dirreq_v3_reqs_line),
    'dir_v2_responses': (None, _parse_dirreq_v2_resp_line),
    'dir_v3_responses': (None, _parse_dirreq_v3_resp_line),
    'dir_v2_responses_unknown': (None, _parse_dirreq_v2_resp_line),
    'dir_v3_responses_unknown': (None, _parse_dirreq_v3_resp_line),
    'dir_v2_direct_dl': (None, _parse_dirreq_v2_direct_dl_line),
    'dir_v3_direct_dl': (None, _parse_dirreq_v3_direct_dl_line),
    'dir_v2_direct_dl_unknown': (None, _parse_dirreq_v2_direct_dl_line),
    'dir_v3_direct_dl_unknown': (None, _parse_dirreq_v3_direct_dl_line),
    'dir_v2_tunneled_dl': (None, _parse_dirreq_v2_tunneled_dl_line),
    'dir_v3_tunneled_dl': (None, _parse_dirreq_v3_tunneled_dl_line),
    'dir_v2_tunneled_dl_unknown': (None, _parse_dirreq_v2_tunneled_dl_line),
    'dir_v3_tunneled_dl_unknown': (None, _parse_dirreq_v3_tunneled_dl_line),

    'dir_read_history_end': (None, _parse_dirreq_read_history_line),
    'dir_read_history_interval': (None, _parse_dirreq_read_history_line),
    'dir_read_history_values': (None, _parse_dirreq_read_history_line),

    'dir_write_history_end': (None, _parse_dirreq_write_history_line),
    'dir_write_history_interval': (None, _parse_dirreq_write_history_line),
    'dir_write_history_values': (None, _parse_dirreq_write_history_line),

    'entry_stats_end': (None, _parse_entry_stats_end_line),
    'entry_stats_interval': (None, _parse_entry_stats_end_line),
    'entry_ips': (None, _parse_entry_ips_line),

    'exit_stats_end': (None, _parse_exit_stats_end_line),
    'exit_stats_interval': (None, _parse_exit_stats_end_line),
    'exit_kibibytes_written': (None, _parse_exit_kibibytes_written_line),
    'exit_kibibytes_read': (None, _parse_exit_kibibytes_read_line),
    'exit_streams_opened': (None, _parse_exit_streams_opened_line),

    'hs_stats_end': (None, _parse_hidden_service_stats_end_line),
    'hs_rend_cells': (None, _parse_hidden_service_rend_relayed_cells_line),
    'hs_rend_cells_attr': ({}, _parse_hidden_service_rend_relayed_cells_line),
    'hs_dir_onions_seen': (None, _parse_hidden_service_dir_onions_seen_line),
    'hs_dir_onions_seen_attr': ({}, _parse_hidden_service_dir_onions_seen_line),

    'bridge_stats_end': (None, _parse_bridge_stats_end_line),
    'bridge_stats_interval': (None, _parse_bridge_stats_end_line),
    'bridge_ips': (None, _parse_bridge_ips_line),
    'geoip_start_time': (None, _parse_geoip_start_time_line),
    'geoip_client_origins': (None, _parse_geoip_client_origins_line),

    'ip_versions': (None, _parse_bridge_ip_versions_line),
    'ip_transports': (None, _parse_bridge_ip_transports_line),
  }

  PARSER_FOR_LINE = {
    'extra-info': _parse_extra_info_line,
    'geoip-db-digest': _parse_geoip_db_digest_line,
    'geoip6-db-digest': _parse_geoip6_db_digest_line,
    'transport': _parse_transport_line,
    'cell-circuits-per-decile': _parse_cell_circuits_per_decline_line,
    'dirreq-v2-resp': _parse_dirreq_v2_resp_line,
    'dirreq-v3-resp': _parse_dirreq_v3_resp_line,
    'dirreq-v2-direct-dl': _parse_dirreq_v2_direct_dl_line,
    'dirreq-v3-direct-dl': _parse_dirreq_v3_direct_dl_line,
    'dirreq-v2-tunneled-dl': _parse_dirreq_v2_tunneled_dl_line,
    'dirreq-v3-tunneled-dl': _parse_dirreq_v3_tunneled_dl_line,
    'dirreq-v2-share': _parse_dirreq_v2_share_line,
    'dirreq-v3-share': _parse_dirreq_v3_share_line,
    'cell-processed-cells': _parse_cell_processed_cells_line,
    'cell-queued-cells': _parse_cell_queued_cells_line,
    'cell-time-in-queue': _parse_cell_time_in_queue_line,
    'published': _parse_published_line,
    'geoip-start-time': _parse_geoip_start_time_line,
    'cell-stats-end': _parse_cell_stats_end_line,
    'entry-stats-end': _parse_entry_stats_end_line,
    'exit-stats-end': _parse_exit_stats_end_line,
    'bridge-stats-end': _parse_bridge_stats_end_line,
    'dirreq-stats-end': _parse_dirreq_stats_end_line,
    'conn-bi-direct': _parse_conn_bi_direct_line,
    'read-history': _parse_read_history_line,
    'write-history': _parse_write_history_line,
    'dirreq-read-history': _parse_dirreq_read_history_line,
    'dirreq-write-history': _parse_dirreq_write_history_line,
    'exit-kibibytes-written': _parse_exit_kibibytes_written_line,
    'exit-kibibytes-read': _parse_exit_kibibytes_read_line,
    'exit-streams-opened': _parse_exit_streams_opened_line,
    'hidserv-stats-end': _parse_hidden_service_stats_end_line,
    'hidserv-rend-relayed-cells': _parse_hidden_service_rend_relayed_cells_line,
    'hidserv-dir-onions-seen': _parse_hidden_service_dir_onions_seen_line,
    'dirreq-v2-ips': _parse_dirreq_v2_ips_line,
    'dirreq-v3-ips': _parse_dirreq_v3_ips_line,
    'dirreq-v2-reqs': _parse_dirreq_v2_reqs_line,
    'dirreq-v3-reqs': _parse_dirreq_v3_reqs_line,
    'geoip-client-origins': _parse_geoip_client_origins_line,
    'entry-ips': _parse_entry_ips_line,
    'bridge-ips': _parse_bridge_ips_line,
    'bridge-ip-versions': _parse_bridge_ip_versions_line,
    'bridge-ip-transports': _parse_bridge_ip_transports_line,
  }

  def __init__(self, raw_contents, validate = False):
    """
    Extra-info descriptor constructor. By default this validates the
    descriptor's content as it's parsed. This validation can be disabled to
    either improve performance or be accepting of malformed data.

    :param str raw_contents: extra-info content provided by the relay
    :param bool validate: checks the validity of the extra-info descriptor if
      **True**, skips these checks otherwise

    :raises: **ValueError** if the contents is malformed and validate is True
    """

    super(ExtraInfoDescriptor, self).__init__(raw_contents, lazy_load = not validate)
    entries = _get_descriptor_components(raw_contents, validate)

    if validate:
      for keyword in self._required_fields():
        if keyword not in entries:
          raise ValueError("Extra-info descriptor must have a '%s' entry" % keyword)

      for keyword in self._required_fields() + SINGLE_FIELDS:
        if keyword in entries and len(entries[keyword]) > 1:
          raise ValueError("The '%s' entry can only appear once in an extra-info descriptor" % keyword)

      expected_first_keyword = self._first_keyword()
      if expected_first_keyword and expected_first_keyword != list(entries.keys())[0]:
        raise ValueError("Extra-info descriptor must start with a '%s' entry" % expected_first_keyword)

      expected_last_keyword = self._last_keyword()
      if expected_last_keyword and expected_last_keyword != list(entries.keys())[-1]:
        raise ValueError("Descriptor must end with a '%s' entry" % expected_last_keyword)

      self._parse(entries, validate)
    else:
      self._entries = entries

  def digest(self):
    """
    Provides the upper-case hex encoded sha1 of our content. This value is part
    of the server descriptor entry for this relay.

    :returns: **str** with the upper-case hex digest value for this server
      descriptor
    """

    raise NotImplementedError('Unsupported Operation: this should be implemented by the ExtraInfoDescriptor subclass')

  def _required_fields(self):
    return REQUIRED_FIELDS

  def _first_keyword(self):
    return 'extra-info'

  def _last_keyword(self):
    return 'router-signature'


class RelayExtraInfoDescriptor(ExtraInfoDescriptor):
  """
  Relay extra-info descriptor, constructed from data such as that provided by
  'GETINFO extra-info/digest/\*', cached descriptors, and metrics
  (`specification <https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_).

  :var str signature: **\*** signature for this extrainfo descriptor

  **\*** attribute is required when we're parsed with validation
  """

  ATTRIBUTES = dict(ExtraInfoDescriptor.ATTRIBUTES, **{
    'signature': (None, _parse_router_signature_line),
  })

  PARSER_FOR_LINE = dict(ExtraInfoDescriptor.PARSER_FOR_LINE, **{
    'router-signature': _parse_router_signature_line,
  })

  @lru_cache()
  def digest(self):
    # our digest is calculated from everything except our signature
    raw_content, ending = str(self), '\nrouter-signature\n'
    raw_content = raw_content[:raw_content.find(ending) + len(ending)]
    return hashlib.sha1(stem.util.str_tools._to_bytes(raw_content)).hexdigest().upper()


class BridgeExtraInfoDescriptor(ExtraInfoDescriptor):
  """
  Bridge extra-info descriptor (`bridge descriptor specification
  <https://collector.torproject.org/formats.html#bridge-descriptors>`_)
  """

  ATTRIBUTES = dict(ExtraInfoDescriptor.ATTRIBUTES, **{
    '_digest': (None, _parse_router_digest_line),
  })

  PARSER_FOR_LINE = dict(ExtraInfoDescriptor.PARSER_FOR_LINE, **{
    'router-digest': _parse_router_digest_line,
  })

  def digest(self):
    return self._digest

  def _required_fields(self):
    excluded_fields = [
      'router-signature',
    ]

    included_fields = [
      'router-digest',
    ]

    return tuple(included_fields + [f for f in REQUIRED_FIELDS if f not in excluded_fields])

  def _last_keyword(self):
    return None
