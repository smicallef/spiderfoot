# Copyright 2013-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for Tor microdescriptors, which contain a distilled version of a
relay's server descriptor. As of Tor version 0.2.3.3-alpha Tor no longer
downloads server descriptors by default, opting for microdescriptors instead.

Unlike most descriptor documents these aren't available on the metrics site
(since they don't contain any information that the server descriptors don't).

The limited information in microdescriptors make them rather clunky to use
compared with server descriptors. For instance microdescriptors lack the
relay's fingerprint, making it difficut to use them to look up the relay's
other descriptors.

To do so you need to match the microdescriptor's digest against its
corresponding router status entry. For added fun as of this writing the
controller doesn't even surface those router status entries
(:trac:`7953`).

For instance, here's an example that prints the nickname and fignerprints of
the exit relays.

::

  import os

  from stem.control import Controller
  from stem.descriptor import parse_file

  with Controller.from_port(port = 9051) as controller:
    controller.authenticate()

    exit_digests = set()
    data_dir = controller.get_conf('DataDirectory')

    for desc in controller.get_microdescriptors():
      if desc.exit_policy.is_exiting_allowed():
        exit_digests.add(desc.digest)

    print 'Exit Relays:'

    for desc in parse_file(os.path.join(data_dir, 'cached-microdesc-consensus')):
      if desc.digest in exit_digests:
        print '  %s (%s)' % (desc.nickname, desc.fingerprint)

Doing the same is trivial with server descriptors...

::

  from stem.descriptor import parse_file

  print 'Exit Relays:'

  for desc in parse_file('/home/atagar/.tor/cached-descriptors'):
    if desc.exit_policy.is_exiting_allowed():
      print '  %s (%s)' % (desc.nickname, desc.fingerprint)

**Module Overview:**

::

  Microdescriptor - Tor microdescriptor.
"""

import hashlib

import stem.exit_policy

from stem.descriptor import (
  Descriptor,
  _get_descriptor_components,
  _read_until_keywords,
  _value,
  _parse_simple_line,
  _parse_key_block,
)

from stem.descriptor.router_status_entry import (
  _parse_a_line,
  _parse_p_line,
)

try:
  # added in python 3.2
  from functools import lru_cache
except ImportError:
  from stem.util.lru_cache import lru_cache

REQUIRED_FIELDS = (
  'onion-key',
)

SINGLE_FIELDS = (
  'onion-key',
  'ntor-onion-key',
  'family',
  'p',
  'p6',
)


def _parse_file(descriptor_file, validate = False, **kwargs):
  """
  Iterates over the microdescriptors in a file.

  :param file descriptor_file: file with descriptor content
  :param bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :param dict kwargs: additional arguments for the descriptor constructor

  :returns: iterator for Microdescriptor instances in the file

  :raises:
    * **ValueError** if the contents is malformed and validate is True
    * **IOError** if the file can't be read
  """

  while True:
    annotations = _read_until_keywords('onion-key', descriptor_file)

    # read until we reach an annotation or onion-key line
    descriptor_lines = []

    # read the onion-key line, done if we're at the end of the document

    onion_key_line = descriptor_file.readline()

    if onion_key_line:
      descriptor_lines.append(onion_key_line)
    else:
      break

    while True:
      last_position = descriptor_file.tell()
      line = descriptor_file.readline()

      if not line:
        break  # EOF
      elif line.startswith(b'@') or line.startswith(b'onion-key'):
        descriptor_file.seek(last_position)
        break
      else:
        descriptor_lines.append(line)

    if descriptor_lines:
      if descriptor_lines[0].startswith(b'@type'):
        descriptor_lines = descriptor_lines[1:]

      # strip newlines from annotations
      annotations = list(map(bytes.strip, annotations))

      descriptor_text = bytes.join(b'', descriptor_lines)

      yield Microdescriptor(descriptor_text, validate, annotations, **kwargs)
    else:
      break  # done parsing descriptors


def _parse_id_line(descriptor, entries):
  value = _value('id', entries)
  value_comp = value.split()

  if len(value_comp) >= 2:
    descriptor.identifier_type = value_comp[0]
    descriptor.identifier = value_comp[1]
  else:
    raise ValueError("'id' lines should contain both the key type and digest: id %s" % value)


_parse_digest = lambda descriptor, entries: setattr(descriptor, 'digest', hashlib.sha256(descriptor.get_bytes()).hexdigest().upper())
_parse_onion_key_line = _parse_key_block('onion-key', 'onion_key', 'RSA PUBLIC KEY')
_parse_ntor_onion_key_line = _parse_simple_line('ntor-onion-key', 'ntor_onion_key')
_parse_family_line = lambda descriptor, entries: setattr(descriptor, 'family', _value('family', entries).split(' '))
_parse_p6_line = lambda descriptor, entries: setattr(descriptor, 'exit_policy_v6', stem.exit_policy.MicroExitPolicy(_value('p6', entries)))


class Microdescriptor(Descriptor):
  """
  Microdescriptor (`descriptor specification
  <https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_)

  :var str digest: **\*** hex digest for this microdescriptor, this can be used
    to match against the corresponding digest attribute of a
    :class:`~stem.descriptor.router_status_entry.RouterStatusEntryMicroV3`
  :var str onion_key: **\*** key used to encrypt EXTEND cells
  :var str ntor_onion_key: base64 key used to encrypt EXTEND in the ntor protocol
  :var list or_addresses: **\*** alternative for our address/or_port attributes, each
    entry is a tuple of the form (address (**str**), port (**int**), is_ipv6
    (**bool**))
  :var list family: **\*** nicknames or fingerprints of declared family
  :var stem.exit_policy.MicroExitPolicy exit_policy: **\*** relay's exit policy
  :var stem.exit_policy.MicroExitPolicy exit_policy_v6: **\*** exit policy for IPv6
  :var str identifier_type: identity digest key type
  :var str identifier: base64 encoded identity digest, this is only used for collision prevention (:trac:`11743`)

  **\*** attribute is required when we're parsed with validation

  .. versionchanged:: 1.1.0
     Added the identifier and identifier_type attributes.
  """

  ATTRIBUTES = {
    'onion_key': (None, _parse_onion_key_line),
    'ntor_onion_key': (None, _parse_ntor_onion_key_line),
    'or_addresses': ([], _parse_a_line),
    'family': ([], _parse_family_line),
    'exit_policy': (stem.exit_policy.MicroExitPolicy('reject 1-65535'), _parse_p_line),
    'exit_policy_v6': (None, _parse_p6_line),
    'identifier_type': (None, _parse_id_line),
    'identifier': (None, _parse_id_line),
    'digest': (None, _parse_digest),
  }

  PARSER_FOR_LINE = {
    'onion-key': _parse_onion_key_line,
    'ntor-onion-key': _parse_ntor_onion_key_line,
    'a': _parse_a_line,
    'family': _parse_family_line,
    'p': _parse_p_line,
    'p6': _parse_p6_line,
    'id': _parse_id_line,
  }

  def __init__(self, raw_contents, validate = False, annotations = None):
    super(Microdescriptor, self).__init__(raw_contents, lazy_load = not validate)
    self._annotation_lines = annotations if annotations else []
    entries = _get_descriptor_components(raw_contents, validate)

    if validate:
      self.digest = hashlib.sha256(self.get_bytes()).hexdigest().upper()
      self._parse(entries, validate)
      self._check_constraints(entries)
    else:
      self._entries = entries

  @lru_cache()
  def get_annotations(self):
    """
    Provides content that appeared prior to the descriptor. If this comes from
    the cached-microdescs then this commonly contains content like...

    ::

      @last-listed 2013-02-24 00:18:30

    :returns: **dict** with the key/value pairs in our annotations
    """

    annotation_dict = {}

    for line in self._annotation_lines:
      if b' ' in line:
        key, value = line.split(b' ', 1)
        annotation_dict[key] = value
      else:
        annotation_dict[line] = None

    return annotation_dict

  def get_annotation_lines(self):
    """
    Provides the lines of content that appeared prior to the descriptor. This
    is the same as the
    :func:`~stem.descriptor.microdescriptor.Microdescriptor.get_annotations`
    results, but with the unparsed lines and ordering retained.

    :returns: **list** with the lines of annotation that came before this descriptor
    """

    return self._annotation_lines

  def _check_constraints(self, entries):
    """
    Does a basic check that the entries conform to this descriptor type's
    constraints.

    :param dict entries: keyword => (value, pgp key) entries

    :raises: **ValueError** if an issue arises in validation
    """

    for keyword in REQUIRED_FIELDS:
      if keyword not in entries:
        raise ValueError("Microdescriptor must have a '%s' entry" % keyword)

    for keyword in SINGLE_FIELDS:
      if keyword in entries and len(entries[keyword]) > 1:
        raise ValueError("The '%s' entry can only appear once in a microdescriptor" % keyword)

    if 'onion-key' != list(entries.keys())[0]:
      raise ValueError("Microdescriptor must start with a 'onion-key' entry")

  def _name(self, is_plural = False):
    return 'microdescriptors' if is_plural else 'microdescriptor'

  def _compare(self, other, method):
    if not isinstance(other, Microdescriptor):
      return False

    return method(str(self).strip(), str(other).strip())

  def __hash__(self):
    return hash(str(self).strip())

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __lt__(self, other):
    return self._compare(other, lambda s, o: s < o)

  def __le__(self, other):
    return self._compare(other, lambda s, o: s <= o)
