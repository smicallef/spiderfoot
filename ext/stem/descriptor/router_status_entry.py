# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for router status entries, the information for individual routers
within a network status document. This information is provided from a few
sources...

* control port via 'GETINFO ns/\*' and 'GETINFO md/\*' queries
* router entries in a network status document, like the cached-consensus

**Module Overview:**

::

  RouterStatusEntry - Common parent for router status entries
    |- RouterStatusEntryV2 - Entry for a network status v2 document
    |- RouterStatusEntryV3 - Entry for a network status v3 document
    +- RouterStatusEntryMicroV3 - Entry for a microdescriptor flavored v3 document
"""

import base64
import binascii

import stem.exit_policy
import stem.prereq
import stem.util.str_tools

from stem.descriptor import (
  KEYWORD_LINE,
  Descriptor,
  _value,
  _values,
  _get_descriptor_components,
  _read_until_keywords,
)


def _parse_file(document_file, validate, entry_class, entry_keyword = 'r', start_position = None, end_position = None, section_end_keywords = (), extra_args = ()):
  """
  Reads a range of the document_file containing some number of entry_class
  instances. We deliminate the entry_class entries by the keyword on their
  first line (entry_keyword). When finished the document is left at the
  end_position.

  Either an end_position or section_end_keywords must be provided.

  :param file document_file: file with network status document content
  :param bool validate: checks the validity of the document's contents if
    **True**, skips these checks otherwise
  :param class entry_class: class to construct instance for
  :param str entry_keyword: first keyword for the entry instances
  :param int start_position: start of the section, default is the current position
  :param int end_position: end of the section
  :param tuple section_end_keywords: keyword(s) that deliminate the end of the
    section if no end_position was provided
  :param tuple extra_args: extra arguments for the entry_class (after the
    content and validate flag)

  :returns: iterator over entry_class instances

  :raises:
    * **ValueError** if the contents is malformed and validate is **True**
    * **IOError** if the file can't be read
  """

  if start_position:
    document_file.seek(start_position)
  else:
    start_position = document_file.tell()

  # check if we're starting at the end of the section (ie, there's no entries to read)
  if section_end_keywords:
    first_keyword = None
    line_match = KEYWORD_LINE.match(stem.util.str_tools._to_unicode(document_file.readline()))

    if line_match:
      first_keyword = line_match.groups()[0]

    document_file.seek(start_position)

    if first_keyword in section_end_keywords:
      return

  while end_position is None or document_file.tell() < end_position:
    desc_lines, ending_keyword = _read_until_keywords(
      (entry_keyword,) + section_end_keywords,
      document_file,
      ignore_first = True,
      end_position = end_position,
      include_ending_keyword = True
    )

    desc_content = bytes.join(b'', desc_lines)

    if desc_content:
      yield entry_class(desc_content, validate, *extra_args)

      # check if we stopped at the end of the section
      if ending_keyword in section_end_keywords:
        break
    else:
      break


def _parse_r_line(descriptor, entries):
  # Parses a RouterStatusEntry's 'r' line. They're very nearly identical for
  # all current entry types (v2, v3, and microdescriptor v3) with one little
  # wrinkle: only the microdescriptor flavor excludes a 'digest' field.
  #
  # For v2 and v3 router status entries:
  #   "r" nickname identity digest publication IP ORPort DirPort
  #   example: r mauer BD7xbfsCFku3+tgybEZsg8Yjhvw itcuKQ6PuPLJ7m/Oi928WjO2j8g 2012-06-22 13:19:32 80.101.105.103 9001 0
  #
  # For v3 microdescriptor router status entries:
  #   "r" nickname identity publication IP ORPort DirPort
  #   example: r Konata ARIJF2zbqirB9IwsW0mQznccWww 2012-09-24 13:40:40 69.64.48.168 9001 9030

  value = _value('r', entries)
  include_digest = not isinstance(descriptor, RouterStatusEntryMicroV3)

  r_comp = value.split(' ')

  # inject a None for the digest to normalize the field positioning
  if not include_digest:
    r_comp.insert(2, None)

  if len(r_comp) < 8:
    expected_field_count = 'eight' if include_digest else 'seven'
    raise ValueError("%s 'r' line must have %s values: r %s" % (descriptor._name(), expected_field_count, value))

  if not stem.util.tor_tools.is_valid_nickname(r_comp[0]):
    raise ValueError("%s nickname isn't valid: %s" % (descriptor._name(), r_comp[0]))
  elif not stem.util.connection.is_valid_ipv4_address(r_comp[5]):
    raise ValueError("%s address isn't a valid IPv4 address: %s" % (descriptor._name(), r_comp[5]))
  elif not stem.util.connection.is_valid_port(r_comp[6]):
    raise ValueError('%s ORPort is invalid: %s' % (descriptor._name(), r_comp[6]))
  elif not stem.util.connection.is_valid_port(r_comp[7], allow_zero = True):
    raise ValueError('%s DirPort is invalid: %s' % (descriptor._name(), r_comp[7]))

  descriptor.nickname = r_comp[0]
  descriptor.fingerprint = _base64_to_hex(r_comp[1])

  if include_digest:
    descriptor.digest = _base64_to_hex(r_comp[2])

  descriptor.address = r_comp[5]
  descriptor.or_port = int(r_comp[6])
  descriptor.dir_port = None if r_comp[7] == '0' else int(r_comp[7])

  try:
    published = '%s %s' % (r_comp[3], r_comp[4])
    descriptor.published = stem.util.str_tools._parse_timestamp(published)
  except ValueError:
    raise ValueError("Publication time time wasn't parsable: r %s" % value)


def _parse_a_line(descriptor, entries):
  # "a" SP address ":" portlist
  # example: a [2001:888:2133:0:82:94:251:204]:9001

  or_addresses = []

  for value in _values('a', entries):
    if ':' not in value:
      raise ValueError("%s 'a' line must be of the form '[address]:[ports]': a %s" % (descriptor._name(), value))

    address, port = value.rsplit(':', 1)
    is_ipv6 = address.startswith('[') and address.endswith(']')

    if is_ipv6:
      address = address[1:-1]  # remove brackets

    if not ((not is_ipv6 and stem.util.connection.is_valid_ipv4_address(address)) or
            (is_ipv6 and stem.util.connection.is_valid_ipv6_address(address))):
      raise ValueError("%s 'a' line must start with an IPv6 address: a %s" % (descriptor._name(), value))

    if stem.util.connection.is_valid_port(port):
      or_addresses.append((address, int(port), is_ipv6))
    else:
      raise ValueError("%s 'a' line had an invalid port (%s): a %s" % (descriptor._name(), port, value))

  descriptor.or_addresses = or_addresses


def _parse_s_line(descriptor, entries):
  # "s" Flags
  # example: s Named Running Stable Valid

  value = _value('s', entries)
  flags = [] if value == '' else value.split(' ')
  descriptor.flags = flags

  for flag in flags:
    if flags.count(flag) > 1:
      raise ValueError('%s had duplicate flags: s %s' % (descriptor._name(), value))
    elif flag == '':
      raise ValueError("%s had extra whitespace on its 's' line: s %s" % (descriptor._name(), value))


def _parse_v_line(descriptor, entries):
  # "v" version
  # example: v Tor 0.2.2.35
  #
  # The spec says that if this starts with "Tor " then what follows is a
  # tor version. If not then it has "upgraded to a more sophisticated
  # protocol versioning system".

  value = _value('v', entries)
  descriptor.version_line = value

  if value.startswith('Tor '):
    try:
      descriptor.version = stem.version._get_version(value[4:])
    except ValueError as exc:
      raise ValueError('%s has a malformed tor version (%s): v %s' % (descriptor._name(), exc, value))


def _parse_w_line(descriptor, entries):
  # "w" "Bandwidth=" INT ["Measured=" INT] ["Unmeasured=1"]
  # example: w Bandwidth=7980

  value = _value('w', entries)
  w_comp = value.split(' ')

  if len(w_comp) < 1:
    raise ValueError("%s 'w' line is blank: w %s" % (descriptor._name(), value))
  elif not w_comp[0].startswith('Bandwidth='):
    raise ValueError("%s 'w' line needs to start with a 'Bandwidth=' entry: w %s" % (descriptor._name(), value))

  bandwidth = None
  measured = None
  is_unmeasured = False
  unrecognized_bandwidth_entries = []

  for w_entry in w_comp:
    if '=' in w_entry:
      w_key, w_value = w_entry.split('=', 1)
    else:
      w_key, w_value = w_entry, None

    if w_key == 'Bandwidth':
      if not (w_value and w_value.isdigit()):
        raise ValueError("%s 'Bandwidth=' entry needs to have a numeric value: w %s" % (descriptor._name(), value))

      bandwidth = int(w_value)
    elif w_key == 'Measured':
      if not (w_value and w_value.isdigit()):
        raise ValueError("%s 'Measured=' entry needs to have a numeric value: w %s" % (descriptor._name(), value))

      measured = int(w_value)
    elif w_key == 'Unmeasured':
      if w_value != '1':
        raise ValueError("%s 'Unmeasured=' should only have the value of '1': w %s" % (descriptor._name(), value))

      is_unmeasured = True
    else:
      unrecognized_bandwidth_entries.append(w_entry)

  descriptor.bandwidth = bandwidth
  descriptor.measured = measured
  descriptor.is_unmeasured = is_unmeasured
  descriptor.unrecognized_bandwidth_entries = unrecognized_bandwidth_entries


def _parse_p_line(descriptor, entries):
  # "p" ("accept" / "reject") PortList
  # p reject 1-65535
  # example: p accept 80,110,143,443,993,995,6660-6669,6697,7000-7001

  value = _value('p', entries)

  try:
    descriptor.exit_policy = stem.exit_policy.MicroExitPolicy(value)
  except ValueError as exc:
    raise ValueError('%s exit policy is malformed (%s): p %s' % (descriptor._name(), exc, value))


def _parse_m_line(descriptor, entries):
  # "m" methods 1*(algorithm "=" digest)
  # example: m 8,9,10,11,12 sha256=g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs

  all_hashes = []

  for value in _values('m', entries):
    m_comp = value.split(' ')

    if not (descriptor.document and descriptor.document.is_vote):
      vote_status = 'vote' if descriptor.document else '<undefined document>'
      raise ValueError("%s 'm' line should only appear in votes (appeared in a %s): m %s" % (descriptor._name(), vote_status, value))
    elif len(m_comp) < 1:
      raise ValueError("%s 'm' line needs to start with a series of methods: m %s" % (descriptor._name(), value))

    try:
      methods = [int(entry) for entry in m_comp[0].split(',')]
    except ValueError:
      raise ValueError('%s microdescriptor methods should be a series of comma separated integers: m %s' % (descriptor._name(), value))

    hashes = {}

    for entry in m_comp[1:]:
      if '=' not in entry:
        raise ValueError("%s can only have a series of 'algorithm=digest' mappings after the methods: m %s" % (descriptor._name(), value))

      hash_name, digest = entry.split('=', 1)
      hashes[hash_name] = digest

    all_hashes.append((methods, hashes))

  descriptor.microdescriptor_hashes = all_hashes


def _parse_microdescriptor_m_line(descriptor, entries):
  # "m" digest
  # example: m aiUklwBrua82obG5AsTX+iEpkjQA2+AQHxZ7GwMfY70

  descriptor.digest = _base64_to_hex(_value('m', entries), check_if_fingerprint = False)


def _base64_to_hex(identity, check_if_fingerprint = True):
  """
  Decodes a base64 value to hex. For example...

  ::

    >>> _base64_to_hex('p1aag7VwarGxqctS7/fS0y5FU+s')
    'A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB'

  :param str identity: encoded fingerprint from the consensus
  :param bool check_if_fingerprint: asserts that the result is a fingerprint if **True**

  :returns: **str** with the uppercase hex encoding of the relay's fingerprint

  :raises: **ValueError** if the result isn't a valid fingerprint
  """

  # trailing equal signs were stripped from the identity
  missing_padding = len(identity) % 4
  identity += '=' * missing_padding

  try:
    identity_decoded = base64.b64decode(stem.util.str_tools._to_bytes(identity))
  except (TypeError, binascii.Error):
    raise ValueError("Unable to decode identity string '%s'" % identity)

  fingerprint = binascii.b2a_hex(identity_decoded).upper()

  if stem.prereq.is_python_3():
    fingerprint = stem.util.str_tools._to_unicode(fingerprint)

  if check_if_fingerprint:
    if not stem.util.tor_tools.is_valid_fingerprint(fingerprint):
      raise ValueError("Decoded '%s' to be '%s', which isn't a valid fingerprint" % (identity, fingerprint))

  return fingerprint


class RouterStatusEntry(Descriptor):
  """
  Information about an individual router stored within a network status
  document. This is the common parent for concrete status entry types.

  :var stem.descriptor.networkstatus.NetworkStatusDocument document: **\*** document that this descriptor came from

  :var str nickname: **\*** router's nickname
  :var str fingerprint: **\*** router's fingerprint
  :var datetime published: **\*** router's publication
  :var str address: **\*** router's IP address
  :var int or_port: **\*** router's ORPort
  :var int dir_port: **\*** router's DirPort

  :var list flags: **\*** list of :data:`~stem.Flag` associated with the relay

  :var stem.version.Version version: parsed version of tor, this is **None** if
    the relay's using a new versioning scheme
  :var str version_line: versioning information reported by the relay
  """

  ATTRIBUTES = {
    'nickname': (None, _parse_r_line),
    'fingerprint': (None, _parse_r_line),
    'published': (None, _parse_r_line),
    'address': (None, _parse_r_line),
    'or_port': (None, _parse_r_line),
    'dir_port': (None, _parse_r_line),

    'flags': (None, _parse_s_line),

    'version_line': (None, _parse_v_line),
    'version': (None, _parse_v_line),
  }

  PARSER_FOR_LINE = {
    'r': _parse_r_line,
    's': _parse_s_line,
    'v': _parse_v_line,
  }

  def __init__(self, content, validate = False, document = None):
    """
    Parse a router descriptor in a network status document.

    :param str content: router descriptor content to be parsed
    :param NetworkStatusDocument document: document this descriptor came from
    :param bool validate: checks the validity of the content if **True**, skips
      these checks otherwise

    :raises: **ValueError** if the descriptor data is invalid
    """

    super(RouterStatusEntry, self).__init__(content, lazy_load = not validate)
    self.document = document
    entries = _get_descriptor_components(content, validate)

    if validate:
      for keyword in self._required_fields():
        if keyword not in entries:
          raise ValueError("%s must have a '%s' line:\n%s" % (self._name(True), keyword, str(self)))

      for keyword in self._single_fields():
        if keyword in entries and len(entries[keyword]) > 1:
          raise ValueError("%s can only have a single '%s' line, got %i:\n%s" % (self._name(True), keyword, len(entries[keyword]), str(self)))

      if 'r' != list(entries.keys())[0]:
        raise ValueError("%s are expected to start with a 'r' line:\n%s" % (self._name(True), str(self)))

      self._parse(entries, validate)
    else:
      self._entries = entries

  def _name(self, is_plural = False):
    """
    Name for this descriptor type.
    """

    return 'Router status entries' if is_plural else 'Router status entry'

  def _required_fields(self):
    """
    Provides lines that must appear in the descriptor.
    """

    return ()

  def _single_fields(self):
    """
    Provides lines that can only appear in the descriptor once.
    """

    return ()

  def _compare(self, other, method):
    if not isinstance(other, RouterStatusEntry):
      return False

    return method(str(self).strip(), str(other).strip())

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __lt__(self, other):
    return self._compare(other, lambda s, o: s < o)

  def __le__(self, other):
    return self._compare(other, lambda s, o: s <= o)


class RouterStatusEntryV2(RouterStatusEntry):
  """
  Information about an individual router stored within a version 2 network
  status document.

  :var str digest: **\*** router's upper-case hex digest

  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """

  ATTRIBUTES = dict(RouterStatusEntry.ATTRIBUTES, **{
    'digest': (None, _parse_r_line),
  })

  def _name(self, is_plural = False):
    return 'Router status entries (v2)' if is_plural else 'Router status entry (v2)'

  def _required_fields(self):
    return ('r')

  def _single_fields(self):
    return ('r', 's', 'v')

  def _compare(self, other, method):
    if not isinstance(other, RouterStatusEntryV2):
      return False

    return method(str(self).strip(), str(other).strip())

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __lt__(self, other):
    return self._compare(other, lambda s, o: s < o)

  def __le__(self, other):
    return self._compare(other, lambda s, o: s <= o)


class RouterStatusEntryV3(RouterStatusEntry):
  """
  Information about an individual router stored within a version 3 network
  status document.

  :var list or_addresses: **\*** relay's OR addresses, this is a tuple listing
    of the form (address (**str**), port (**int**), is_ipv6 (**bool**))
  :var str digest: **\*** router's upper-case hex digest

  :var int bandwidth: bandwidth claimed by the relay (in kb/s)
  :var int measured: bandwidth measured to be available by the relay, this is a
    unit-less heuristic generated by the Bandwidth authoritites to weight relay
    selection
  :var bool is_unmeasured: bandwidth measurement isn't based on three or more
    measurements
  :var list unrecognized_bandwidth_entries: **\*** bandwidth weighting
    information that isn't yet recognized

  :var stem.exit_policy.MicroExitPolicy exit_policy: router's exit policy

  :var list microdescriptor_hashes: **\*** tuples of two values, the list of
    consensus methods for generating a set of digests and the 'algorithm =>
    digest' mappings

  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """

  ATTRIBUTES = dict(RouterStatusEntry.ATTRIBUTES, **{
    'digest': (None, _parse_r_line),
    'or_addresses': ([], _parse_a_line),

    'bandwidth': (None, _parse_w_line),
    'measured': (None, _parse_w_line),
    'is_unmeasured': (False, _parse_w_line),
    'unrecognized_bandwidth_entries': ([], _parse_w_line),

    'exit_policy': (None, _parse_p_line),
    'microdescriptor_hashes': ([], _parse_m_line),
  })

  PARSER_FOR_LINE = dict(RouterStatusEntry.PARSER_FOR_LINE, **{
    'a': _parse_a_line,
    'w': _parse_w_line,
    'p': _parse_p_line,
    'm': _parse_m_line,
  })

  def _name(self, is_plural = False):
    return 'Router status entries (v3)' if is_plural else 'Router status entry (v3)'

  def _required_fields(self):
    return ('r', 's')

  def _single_fields(self):
    return ('r', 's', 'v', 'w', 'p')

  def _compare(self, other, method):
    if not isinstance(other, RouterStatusEntryV3):
      return False

    return method(str(self).strip(), str(other).strip())

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __lt__(self, other):
    return self._compare(other, lambda s, o: s < o)

  def __le__(self, other):
    return self._compare(other, lambda s, o: s <= o)


class RouterStatusEntryMicroV3(RouterStatusEntry):
  """
  Information about an individual router stored within a microdescriptor
  flavored network status document.

  :var int bandwidth: bandwidth claimed by the relay (in kb/s)
  :var int measured: bandwidth measured to be available by the relay
  :var bool is_unmeasured: bandwidth measurement isn't based on three or more
    measurements
  :var list unrecognized_bandwidth_entries: **\*** bandwidth weighting
    information that isn't yet recognized

  :var str digest: **\*** router's hex encoded digest of our corresponding microdescriptor

  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """

  ATTRIBUTES = dict(RouterStatusEntry.ATTRIBUTES, **{
    'bandwidth': (None, _parse_w_line),
    'measured': (None, _parse_w_line),
    'is_unmeasured': (False, _parse_w_line),
    'unrecognized_bandwidth_entries': ([], _parse_w_line),

    'digest': (None, _parse_microdescriptor_m_line),
  })

  PARSER_FOR_LINE = dict(RouterStatusEntry.PARSER_FOR_LINE, **{
    'w': _parse_w_line,
    'm': _parse_microdescriptor_m_line,
  })

  def _name(self, is_plural = False):
    return 'Router status entries (micro v3)' if is_plural else 'Router status entry (micro v3)'

  def _required_fields(self):
    return ('r', 's', 'm')

  def _single_fields(self):
    return ('r', 's', 'v', 'w', 'm')

  def _compare(self, other, method):
    if not isinstance(other, RouterStatusEntryMicroV3):
      return False

    return method(str(self).strip(), str(other).strip())

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __lt__(self, other):
    return self._compare(other, lambda s, o: s < o)

  def __le__(self, other):
    return self._compare(other, lambda s, o: s <= o)
