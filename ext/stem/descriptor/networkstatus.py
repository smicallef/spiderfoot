# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for Tor network status documents. This supports both the v2 and v3
dir-spec. Documents can be obtained from a few sources...

* The 'cached-consensus' file in Tor's data directory.

* Archived descriptors provided by CollecTor
  (https://collector.torproject.org/).

* Directory authorities and mirrors via their DirPort.

... and contain the following sections...

* document header
* list of :class:`stem.descriptor.networkstatus.DirectoryAuthority`
* list of :class:`stem.descriptor.router_status_entry.RouterStatusEntry`
* document footer

Of these, the router status entry section can be quite large (on the order of
hundreds of kilobytes). As such we provide a couple of methods for reading
network status documents through :func:`~stem.descriptor.__init__.parse_file`.
For more information see :func:`~stem.descriptor.__init__.DocumentHandler`...

::

  from stem.descriptor import parse_file, DocumentHandler

  with open('.tor/cached-consensus', 'rb') as consensus_file:
    # Processes the routers as we read them in. The routers refer to a document
    # with an unset 'routers' attribute.

    for router in parse_file(consensus_file, 'network-status-consensus-3 1.0', document_handler = DocumentHandler.ENTRIES):
      print router.nickname

**Module Overview:**

::

  NetworkStatusDocument - Network status document
    |- NetworkStatusDocumentV2 - Version 2 network status document
    |- NetworkStatusDocumentV3 - Version 3 network status document
    +- BridgeNetworkStatusDocument - Version 3 network status document for bridges

  KeyCertificate - Certificate used to authenticate an authority
  DocumentSignature - Signature of a document by a directory authority
  DirectoryAuthority - Directory authority as defined in a v3 network status document


.. data:: PackageVersion

  Latest recommended version of a package that's available.

  :var str name: name of the package
  :var str version: latest recommended version
  :var str url: package's url
  :var dict digests: mapping of digest types to their value
"""

import collections
import io

import stem.descriptor.router_status_entry
import stem.util.str_tools
import stem.util.tor_tools
import stem.version

from stem.descriptor import (
  PGP_BLOCK_END,
  Descriptor,
  DocumentHandler,
  _get_descriptor_components,
  _read_until_keywords,
  _value,
  _parse_simple_line,
  _parse_timestamp_line,
  _parse_forty_character_hex,
  _parse_key_block,
)

from stem.descriptor.router_status_entry import (
  RouterStatusEntryV2,
  RouterStatusEntryV3,
  RouterStatusEntryMicroV3,
)

PackageVersion = collections.namedtuple('PackageVersion', [
  'name',
  'version',
  'url',
  'digests',
])

# Version 2 network status document fields, tuples of the form...
# (keyword, is_mandatory)

NETWORK_STATUS_V2_FIELDS = (
  ('network-status-version', True),
  ('dir-source', True),
  ('fingerprint', True),
  ('contact', True),
  ('dir-signing-key', True),
  ('client-versions', False),
  ('server-versions', False),
  ('published', True),
  ('dir-options', False),
  ('directory-signature', True),
)

# Network status document are either a 'vote' or 'consensus', with different
# mandatory fields for each. Both though require that their fields appear in a
# specific order. This is an ordered listing of the following...
#
# (field, in_votes, in_consensus, is_mandatory)

HEADER_STATUS_DOCUMENT_FIELDS = (
  ('network-status-version', True, True, True),
  ('vote-status', True, True, True),
  ('consensus-methods', True, False, False),
  ('consensus-method', False, True, False),
  ('published', True, False, True),
  ('valid-after', True, True, True),
  ('fresh-until', True, True, True),
  ('valid-until', True, True, True),
  ('voting-delay', True, True, True),
  ('client-versions', True, True, False),
  ('server-versions', True, True, False),
  ('package', True, True, False),
  ('known-flags', True, True, True),
  ('flag-thresholds', True, False, False),
  ('params', True, True, False),
)

FOOTER_STATUS_DOCUMENT_FIELDS = (
  ('directory-footer', True, True, False),
  ('bandwidth-weights', False, True, False),
  ('directory-signature', True, True, True),
)

HEADER_FIELDS = [attr[0] for attr in HEADER_STATUS_DOCUMENT_FIELDS]
FOOTER_FIELDS = [attr[0] for attr in FOOTER_STATUS_DOCUMENT_FIELDS]

AUTH_START = 'dir-source'
ROUTERS_START = 'r'
FOOTER_START = 'directory-footer'
V2_FOOTER_START = 'directory-signature'

DEFAULT_PARAMS = {
  'bwweightscale': 10000,
  'cbtdisabled': 0,
  'cbtnummodes': 3,
  'cbtrecentcount': 20,
  'cbtmaxtimeouts': 18,
  'cbtmincircs': 100,
  'cbtquantile': 80,
  'cbtclosequantile': 95,
  'cbttestfreq': 60,
  'cbtmintimeout': 2000,
  'cbtinitialtimeout': 60000,
  'Support022HiddenServices': 1,
  'usecreatefast': 1,
}

# KeyCertificate fields, tuple is of the form...
# (keyword, is_mandatory)

KEY_CERTIFICATE_PARAMS = (
  ('dir-key-certificate-version', True),
  ('dir-address', False),
  ('fingerprint', True),
  ('dir-identity-key', True),
  ('dir-key-published', True),
  ('dir-key-expires', True),
  ('dir-signing-key', True),
  ('dir-key-crosscert', False),
  ('dir-key-certification', True),
)

# all parameters are constrained to int32 range
MIN_PARAM, MAX_PARAM = -2147483648, 2147483647

PARAM_RANGE = {
  'circwindow': (100, 1000),
  'CircuitPriorityHalflifeMsec': (-1, MAX_PARAM),
  'perconnbwrate': (-1, MAX_PARAM),
  'perconnbwburst': (-1, MAX_PARAM),
  'refuseunknownexits': (0, 1),
  'bwweightscale': (1, MAX_PARAM),
  'cbtdisabled': (0, 1),
  'cbtnummodes': (1, 20),
  'cbtrecentcount': (3, 1000),
  'cbtmaxtimeouts': (3, 10000),
  'cbtmincircs': (1, 10000),
  'cbtquantile': (10, 99),
  'cbtclosequantile': (MIN_PARAM, 99),
  'cbttestfreq': (1, MAX_PARAM),
  'cbtmintimeout': (500, MAX_PARAM),
  'UseOptimisticData': (0, 1),
  'Support022HiddenServices': (0, 1),
  'usecreatefast': (0, 1),
  'UseNTorHandshake': (0, 1),
  'FastFlagMinThreshold': (4, MAX_PARAM),
  'NumDirectoryGuards': (0, 10),
  'NumEntryGuards': (1, 10),
  'GuardLifetime': (2592000, 157766400),  # min: 30 days, max: 1826 days
  'NumNTorsPerTAP': (1, 100000),
  'AllowNonearlyExtend': (0, 1),
}


def _parse_file(document_file, document_type = None, validate = False, is_microdescriptor = False, document_handler = DocumentHandler.ENTRIES, **kwargs):
  """
  Parses a network status and iterates over the RouterStatusEntry in it. The
  document that these instances reference have an empty 'routers' attribute to
  allow for limited memory usage.

  :param file document_file: file with network status document content
  :param class document_type: NetworkStatusDocument subclass
  :param bool validate: checks the validity of the document's contents if
    **True**, skips these checks otherwise
  :param bool is_microdescriptor: **True** if this is for a microdescriptor
    consensus, **False** otherwise
  :param stem.descriptor.__init__.DocumentHandler document_handler: method in
    which to parse :class:`~stem.descriptor.networkstatus.NetworkStatusDocument`
  :param dict kwargs: additional arguments for the descriptor constructor

  :returns: :class:`stem.descriptor.networkstatus.NetworkStatusDocument` object

  :raises:
    * **ValueError** if the document_version is unrecognized or the contents is
      malformed and validate is **True**
    * **IOError** if the file can't be read
  """

  # we can't properly default this since NetworkStatusDocumentV3 isn't defined yet

  if document_type is None:
    document_type = NetworkStatusDocumentV3

  if document_type == NetworkStatusDocumentV2:
    document_type, router_type = NetworkStatusDocumentV2, RouterStatusEntryV2
  elif document_type == NetworkStatusDocumentV3:
    router_type = RouterStatusEntryMicroV3 if is_microdescriptor else RouterStatusEntryV3
  elif document_type == BridgeNetworkStatusDocument:
    document_type, router_type = BridgeNetworkStatusDocument, RouterStatusEntryV2
  else:
    raise ValueError("Document type %i isn't recognized (only able to parse v2, v3, and bridge)" % document_type)

  if document_handler == DocumentHandler.DOCUMENT:
    yield document_type(document_file.read(), validate, **kwargs)
    return

  # getting the document without the routers section

  header = _read_until_keywords((ROUTERS_START, FOOTER_START, V2_FOOTER_START), document_file)

  if header and header[0].startswith(b'@type'):
    header = header[1:]

  routers_start = document_file.tell()
  _read_until_keywords((FOOTER_START, V2_FOOTER_START), document_file, skip = True)
  routers_end = document_file.tell()

  footer = document_file.readlines()
  document_content = bytes.join(b'', header + footer)

  if document_handler == DocumentHandler.BARE_DOCUMENT:
    yield document_type(document_content, validate, **kwargs)
  elif document_handler == DocumentHandler.ENTRIES:
    desc_iterator = stem.descriptor.router_status_entry._parse_file(
      document_file,
      validate,
      entry_class = router_type,
      entry_keyword = ROUTERS_START,
      start_position = routers_start,
      end_position = routers_end,
      extra_args = (document_type(document_content, validate),),
      **kwargs
    )

    for desc in desc_iterator:
      yield desc
  else:
    raise ValueError('Unrecognized document_handler: %s' % document_handler)


def _parse_file_key_certs(certificate_file, validate = False):
  """
  Parses a file containing one or more authority key certificates.

  :param file certificate_file: file with key certificates
  :param bool validate: checks the validity of the certificate's contents if
    **True**, skips these checks otherwise

  :returns: iterator for :class:`stem.descriptor.networkstatus.KeyCertificate`
    instance in the file

  :raises:
    * **ValueError** if the key certificate content is invalid and validate is
      **True**
    * **IOError** if the file can't be read
  """

  while True:
    keycert_content = _read_until_keywords('dir-key-certification', certificate_file)

    # we've reached the 'router-signature', now include the pgp style block
    block_end_prefix = PGP_BLOCK_END.split(' ', 1)[0]
    keycert_content += _read_until_keywords(block_end_prefix, certificate_file, True)

    if keycert_content:
      yield stem.descriptor.networkstatus.KeyCertificate(bytes.join(b'', keycert_content), validate = validate)
    else:
      break  # done parsing file


class NetworkStatusDocument(Descriptor):
  """
  Common parent for network status documents.
  """


def _parse_version_line(keyword, attribute, expected_version):
  def _parse(descriptor, entries):
    value = _value(keyword, entries)

    if not value.isdigit():
      raise ValueError('Document has a non-numeric version: %s %s' % (keyword, value))

    setattr(descriptor, attribute, int(value))

    if int(value) != expected_version:
      raise ValueError("Expected a version %i document, but got version '%s' instead" % (expected_version, value))

  return _parse


def _parse_dir_source_line(descriptor, entries):
  value = _value('dir-source', entries)
  dir_source_comp = value.split()

  if len(dir_source_comp) < 3:
    raise ValueError("The 'dir-source' line of a v2 network status document must have three values: dir-source %s" % value)

  if not dir_source_comp[0]:
    # https://trac.torproject.org/7055
    raise ValueError("Authority's hostname can't be blank: dir-source %s" % value)
  elif not stem.util.connection.is_valid_ipv4_address(dir_source_comp[1]):
    raise ValueError("Authority's address isn't a valid IPv4 address: %s" % dir_source_comp[1])
  elif not stem.util.connection.is_valid_port(dir_source_comp[2], allow_zero = True):
    raise ValueError("Authority's DirPort is invalid: %s" % dir_source_comp[2])

  descriptor.hostname = dir_source_comp[0]
  descriptor.address = dir_source_comp[1]
  descriptor.dir_port = None if dir_source_comp[2] == '0' else int(dir_source_comp[2])


_parse_network_status_version_line = _parse_version_line('network-status-version', 'version', 2)
_parse_fingerprint_line = _parse_forty_character_hex('fingerprint', 'fingerprint')
_parse_contact_line = _parse_simple_line('contact', 'contact')
_parse_dir_signing_key_line = _parse_key_block('dir-signing-key', 'signing_key', 'RSA PUBLIC KEY')
_parse_client_versions_line = lambda descriptor, entries: setattr(descriptor, 'client_versions', _value('client-versions', entries).split(','))
_parse_server_versions_line = lambda descriptor, entries: setattr(descriptor, 'server_versions', _value('server-versions', entries).split(','))
_parse_published_line = _parse_timestamp_line('published', 'published')
_parse_dir_options_line = lambda descriptor, entries: setattr(descriptor, 'options', _value('dir-options', entries).split())
_parse_directory_signature_line = _parse_key_block('directory-signature', 'signature', 'SIGNATURE', value_attribute = 'signing_authority')


class NetworkStatusDocumentV2(NetworkStatusDocument):
  """
  Version 2 network status document. These have been deprecated and are no
  longer generated by Tor.

  :var dict routers: fingerprints to :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV2`
    contained in the document

  :var int version: **\*** document version

  :var str hostname: **\*** hostname of the authority
  :var str address: **\*** authority's IP address
  :var int dir_port: **\*** authority's DirPort
  :var str fingerprint: **\*** authority's fingerprint
  :var str contact: **\*** authority's contact information
  :var str signing_key: **\*** authority's public signing key

  :var list client_versions: list of recommended client tor version strings
  :var list server_versions: list of recommended server tor version strings
  :var datetime published: **\*** time when the document was published
  :var list options: **\*** list of things that this authority decides

  :var str signing_authority: **\*** name of the authority signing the document
  :var str signature: **\*** authority's signature for the document

  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """

  ATTRIBUTES = {
    'version': (None, _parse_network_status_version_line),
    'hostname': (None, _parse_dir_source_line),
    'address': (None, _parse_dir_source_line),
    'dir_port': (None, _parse_dir_source_line),
    'fingerprint': (None, _parse_fingerprint_line),
    'contact': (None, _parse_contact_line),
    'signing_key': (None, _parse_dir_signing_key_line),

    'client_versions': ([], _parse_client_versions_line),
    'server_versions': ([], _parse_server_versions_line),
    'published': (None, _parse_published_line),
    'options': ([], _parse_dir_options_line),

    'signing_authority': (None, _parse_directory_signature_line),
    'signatures': (None, _parse_directory_signature_line),
  }

  PARSER_FOR_LINE = {
    'network-status-version': _parse_network_status_version_line,
    'dir-source': _parse_dir_source_line,
    'fingerprint': _parse_fingerprint_line,
    'contact': _parse_contact_line,
    'dir-signing-key': _parse_dir_signing_key_line,
    'client-versions': _parse_client_versions_line,
    'server-versions': _parse_server_versions_line,
    'published': _parse_published_line,
    'dir-options': _parse_dir_options_line,
    'directory-signature': _parse_directory_signature_line,
  }

  def __init__(self, raw_content, validate = False):
    super(NetworkStatusDocumentV2, self).__init__(raw_content, lazy_load = not validate)

    # Splitting the document from the routers. Unlike v3 documents we're not
    # bending over backwards on the validation by checking the field order or
    # that header/footer attributes aren't in the wrong section. This is a
    # deprecated descriptor type - patches welcome if you want those checks.

    document_file = io.BytesIO(raw_content)
    document_content = bytes.join(b'', _read_until_keywords((ROUTERS_START, V2_FOOTER_START), document_file))

    router_iter = stem.descriptor.router_status_entry._parse_file(
      document_file,
      validate,
      entry_class = RouterStatusEntryV2,
      entry_keyword = ROUTERS_START,
      section_end_keywords = (V2_FOOTER_START,),
      extra_args = (self,),
    )

    self.routers = dict((desc.fingerprint, desc) for desc in router_iter)

    entries = _get_descriptor_components(document_content + b'\n' + document_file.read(), validate)

    if validate:
      self._check_constraints(entries)
      self._parse(entries, validate)

      # 'client-versions' and 'server-versions' are only required if 'Versions'
      # is among the options

      if 'Versions' in self.options and not ('client-versions' in entries and 'server-versions' in entries):
        raise ValueError("Version 2 network status documents must have a 'client-versions' and 'server-versions' when 'Versions' is listed among its dir-options:\n%s" % str(self))
    else:
      self._entries = entries

  def _check_constraints(self, entries):
    required_fields = [field for (field, is_mandatory) in NETWORK_STATUS_V2_FIELDS if is_mandatory]
    for keyword in required_fields:
      if keyword not in entries:
        raise ValueError("Network status document (v2) must have a '%s' line:\n%s" % (keyword, str(self)))

    # all recognized fields can only appear once
    single_fields = [field for (field, _) in NETWORK_STATUS_V2_FIELDS]
    for keyword in single_fields:
      if keyword in entries and len(entries[keyword]) > 1:
        raise ValueError("Network status document (v2) can only have a single '%s' line, got %i:\n%s" % (keyword, len(entries[keyword]), str(self)))

    if 'network-status-version' != list(entries.keys())[0]:
      raise ValueError("Network status document (v2) are expected to start with a 'network-status-version' line:\n%s" % str(self))


def _parse_header_network_status_version_line(descriptor, entries):
  # "network-status-version" version

  value = _value('network-status-version', entries)

  if ' ' in value:
    version, flavor = value.split(' ', 1)
  else:
    version, flavor = value, None

  if not version.isdigit():
    raise ValueError('Network status document has a non-numeric version: network-status-version %s' % value)

  descriptor.version = int(version)
  descriptor.version_flavor = flavor
  descriptor.is_microdescriptor = flavor == 'microdesc'

  if descriptor.version != 3:
    raise ValueError("Expected a version 3 network status document, got version '%s' instead" % descriptor.version)


def _parse_header_vote_status_line(descriptor, entries):
  # "vote-status" type
  #
  # The consensus-method and consensus-methods fields are optional since
  # they weren't included in version 1. Setting a default now that we
  # know if we're a vote or not.

  value = _value('vote-status', entries)

  if value == 'consensus':
    descriptor.is_consensus, descriptor.is_vote = True, False
  elif value == 'vote':
    descriptor.is_consensus, descriptor.is_vote = False, True
  else:
    raise ValueError("A network status document's vote-status line can only be 'consensus' or 'vote', got '%s' instead" % value)


def _parse_header_consensus_methods_line(descriptor, entries):
  # "consensus-methods" IntegerList

  if descriptor._lazy_loading and descriptor.is_vote:
    descriptor.consensus_methods = [1]

  value, consensus_methods = _value('consensus-methods', entries), []

  for entry in value.split(' '):
    if not entry.isdigit():
      raise ValueError("A network status document's consensus-methods must be a list of integer values, but was '%s'" % value)

    consensus_methods.append(int(entry))

  descriptor.consensus_methods = consensus_methods


def _parse_header_consensus_method_line(descriptor, entries):
  # "consensus-method" Integer

  if descriptor._lazy_loading and descriptor.is_consensus:
    descriptor.consensus_method = 1

  value = _value('consensus-method', entries)

  if not value.isdigit():
    raise ValueError("A network status document's consensus-method must be an integer, but was '%s'" % value)

  descriptor.consensus_method = int(value)


def _parse_header_voting_delay_line(descriptor, entries):
  # "voting-delay" VoteSeconds DistSeconds

  value = _value('voting-delay', entries)
  value_comp = value.split(' ')

  if len(value_comp) == 2 and value_comp[0].isdigit() and value_comp[1].isdigit():
    descriptor.vote_delay = int(value_comp[0])
    descriptor.dist_delay = int(value_comp[1])
  else:
    raise ValueError("A network status document's 'voting-delay' line must be a pair of integer values, but was '%s'" % value)


def _parse_versions_line(keyword, attribute):
  def _parse(descriptor, entries):
    value, entries = _value(keyword, entries), []

    for entry in value.split(','):
      try:
        entries.append(stem.version._get_version(entry))
      except ValueError:
        raise ValueError("Network status document's '%s' line had '%s', which isn't a parsable tor version: %s %s" % (keyword, entry, keyword, value))

    setattr(descriptor, attribute, entries)

  return _parse


def _parse_header_flag_thresholds_line(descriptor, entries):
  # "flag-thresholds" SP THRESHOLDS

  value, thresholds = _value('flag-thresholds', entries).strip(), {}

  if value:
    for entry in value.split(' '):
      if '=' not in entry:
        raise ValueError("Network status document's 'flag-thresholds' line is expected to be space separated key=value mappings, got: flag-thresholds %s" % value)

      entry_key, entry_value = entry.split('=', 1)

      try:
        if entry_value.endswith('%'):
          # opting for string manipulation rather than just
          # 'float(entry_value) / 100' because floating point arithmetic
          # will lose precision

          thresholds[entry_key] = float('0.' + entry_value[:-1].replace('.', '', 1))
        elif '.' in entry_value:
          thresholds[entry_key] = float(entry_value)
        else:
          thresholds[entry_key] = int(entry_value)
      except ValueError:
        raise ValueError("Network status document's 'flag-thresholds' line is expected to have float values, got: flag-thresholds %s" % value)

  descriptor.flag_thresholds = thresholds


def _parse_header_parameters_line(descriptor, entries):
  # "params" [Parameters]
  # Parameter ::= Keyword '=' Int32
  # Int32 ::= A decimal integer between -2147483648 and 2147483647.
  # Parameters ::= Parameter | Parameters SP Parameter

  if descriptor._lazy_loading:
    descriptor.params = dict(DEFAULT_PARAMS) if descriptor._default_params else {}

  value = _value('params', entries)

  # should only appear in consensus-method 7 or later

  if not descriptor.meets_consensus_method(7):
    raise ValueError("A network status document's 'params' line should only appear in consensus-method 7 or later")

  if value != '':
    descriptor.params = _parse_int_mappings('params', value, True)
    descriptor._check_params_constraints()


def _parse_directory_footer_line(descriptor, entries):
  # nothing to parse, simply checking that we don't have a value

  value = _value('directory-footer', entries)

  if value:
    raise ValueError("A network status document's 'directory-footer' line shouldn't have any content, got 'directory-footer %s'" % value)


def _parse_footer_directory_signature_line(descriptor, entries):
  signatures = []

  for sig_value, block_type, block_contents in entries['directory-signature']:
    if sig_value.count(' ') not in (1, 2):
      raise ValueError("Authority signatures in a network status document are expected to be of the form 'directory-signature [METHOD] FINGERPRINT KEY_DIGEST', received: %s" % sig_value)

    if not block_contents or block_type != 'SIGNATURE':
      raise ValueError("'directory-signature' should be followed by a SIGNATURE block, but was a %s" % block_type)

    if sig_value.count(' ') == 1:
      method = 'sha1'  # default if none was provided
      fingerprint, key_digest = sig_value.split(' ', 1)
    else:
      method, fingerprint, key_digest = sig_value.split(' ', 2)

    signatures.append(DocumentSignature(method, fingerprint, key_digest, block_contents, True))

  descriptor.signatures = signatures


def _parse_package_line(descriptor, entries):
  package_versions = []

  for value, _, _ in entries['package']:
    value_comp = value.split()

    if len(value_comp) < 3:
      raise ValueError("'package' must at least have a 'PackageName Version URL': %s" % value)

    name, version, url = value_comp[:3]
    digests = {}

    for digest_entry in value_comp[3:]:
      if '=' not in digest_entry:
        raise ValueError("'package' digest entries should be 'key=value' pairs: %s" % value)

      key, value = digest_entry.split('=', 1)
      digests[key] = value

    package_versions.append(PackageVersion(name, version, url, digests))

  descriptor.packages = package_versions


_parse_header_valid_after_line = _parse_timestamp_line('valid-after', 'valid_after')
_parse_header_fresh_until_line = _parse_timestamp_line('fresh-until', 'fresh_until')
_parse_header_valid_until_line = _parse_timestamp_line('valid-until', 'valid_until')
_parse_header_client_versions_line = _parse_versions_line('client-versions', 'client_versions')
_parse_header_server_versions_line = _parse_versions_line('server-versions', 'server_versions')
_parse_header_known_flags_line = lambda descriptor, entries: setattr(descriptor, 'known_flags', [entry for entry in _value('known-flags', entries).split(' ') if entry])
_parse_footer_bandwidth_weights_line = lambda descriptor, entries: setattr(descriptor, 'bandwidth_weights', _parse_int_mappings('bandwidth-weights', _value('bandwidth-weights', entries), True))


class NetworkStatusDocumentV3(NetworkStatusDocument):
  """
  Version 3 network status document. This could be either a vote or consensus.

  :var tuple routers: :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3`
    contained in the document

  :var int version: **\*** document version
  :var str version_flavor: **\*** flavor associated with the document (such as 'microdesc')
  :var bool is_consensus: **\*** **True** if the document is a consensus
  :var bool is_vote: **\*** **True** if the document is a vote
  :var bool is_microdescriptor: **\*** **True** if this is a microdescriptor
    flavored document, **False** otherwise
  :var datetime valid_after: **\*** time when the consensus became valid
  :var datetime fresh_until: **\*** time when the next consensus should be produced
  :var datetime valid_until: **\*** time when this consensus becomes obsolete
  :var int vote_delay: **\*** number of seconds allowed for collecting votes
    from all authorities
  :var int dist_delay: **\*** number of seconds allowed for collecting
    signatures from all authorities
  :var list client_versions: list of recommended client tor versions
  :var list server_versions: list of recommended server tor versions
  :var list packages: **\*** list of :data:`~stem.descriptor.networkstatus.PackageVersion` entries
  :var list known_flags: **\*** list of :data:`~stem.Flag` for the router's flags
  :var dict params: **\*** dict of parameter(**str**) => value(**int**) mappings
  :var list directory_authorities: **\*** list of :class:`~stem.descriptor.networkstatus.DirectoryAuthority`
    objects that have generated this document
  :var list signatures: **\*** :class:`~stem.descriptor.networkstatus.DocumentSignature`
    of the authorities that have signed the document

  **Consensus Attributes:**

  :var int consensus_method: method version used to generate this consensus
  :var dict bandwidth_weights: dict of weight(str) => value(int) mappings

  **Vote Attributes:**

  :var list consensus_methods: list of ints for the supported method versions
  :var datetime published: time when the document was published
  :var dict flag_thresholds: **\*** mapping of internal performance thresholds used while making the vote, values are **ints** or **floats**

  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as None if undefined

  .. versionchanged:: 1.4.0
     Added the packages attribute.
  """

  ATTRIBUTES = {
    'version': (None, _parse_header_network_status_version_line),
    'version_flavor': (None, _parse_header_network_status_version_line),
    'is_consensus': (True, _parse_header_vote_status_line),
    'is_vote': (False, _parse_header_vote_status_line),
    'is_microdescriptor': (False, _parse_header_network_status_version_line),
    'consensus_methods': ([], _parse_header_consensus_methods_line),
    'published': (None, _parse_published_line),
    'consensus_method': (None, _parse_header_consensus_method_line),
    'valid_after': (None, _parse_header_valid_after_line),
    'fresh_until': (None, _parse_header_fresh_until_line),
    'valid_until': (None, _parse_header_valid_until_line),
    'vote_delay': (None, _parse_header_voting_delay_line),
    'dist_delay': (None, _parse_header_voting_delay_line),
    'client_versions': ([], _parse_header_client_versions_line),
    'server_versions': ([], _parse_header_server_versions_line),
    'packages': ([], _parse_package_line),
    'known_flags': ([], _parse_header_known_flags_line),
    'flag_thresholds': ({}, _parse_header_flag_thresholds_line),
    'params': ({}, _parse_header_parameters_line),

    'signatures': ([], _parse_footer_directory_signature_line),
    'bandwidth_weights': ({}, _parse_footer_bandwidth_weights_line),
  }

  HEADER_PARSER_FOR_LINE = {
    'network-status-version': _parse_header_network_status_version_line,
    'vote-status': _parse_header_vote_status_line,
    'consensus-methods': _parse_header_consensus_methods_line,
    'consensus-method': _parse_header_consensus_method_line,
    'published': _parse_published_line,
    'valid-after': _parse_header_valid_after_line,
    'fresh-until': _parse_header_fresh_until_line,
    'valid-until': _parse_header_valid_until_line,
    'voting-delay': _parse_header_voting_delay_line,
    'client-versions': _parse_header_client_versions_line,
    'server-versions': _parse_header_server_versions_line,
    'package': _parse_package_line,
    'known-flags': _parse_header_known_flags_line,
    'flag-thresholds': _parse_header_flag_thresholds_line,
    'params': _parse_header_parameters_line,
  }

  FOOTER_PARSER_FOR_LINE = {
    'directory-footer': _parse_directory_footer_line,
    'bandwidth-weights': _parse_footer_bandwidth_weights_line,
    'directory-signature': _parse_footer_directory_signature_line,
  }

  def __init__(self, raw_content, validate = False, default_params = True):
    """
    Parse a v3 network status document.

    :param str raw_content: raw network status document data
    :param bool validate: **True** if the document is to be validated, **False** otherwise
    :param bool default_params: includes defaults in our params dict, otherwise
      it just contains values from the document

    :raises: **ValueError** if the document is invalid
    """

    super(NetworkStatusDocumentV3, self).__init__(raw_content, lazy_load = not validate)
    document_file = io.BytesIO(raw_content)

    self._default_params = default_params
    self._header(document_file, validate)

    self.directory_authorities = tuple(stem.descriptor.router_status_entry._parse_file(
      document_file,
      validate,
      entry_class = DirectoryAuthority,
      entry_keyword = AUTH_START,
      section_end_keywords = (ROUTERS_START, FOOTER_START, V2_FOOTER_START),
      extra_args = (self.is_vote,),
    ))

    if validate and self.is_vote and len(self.directory_authorities) != 1:
      raise ValueError('Votes should only have an authority entry for the one that issued it, got %i: %s' % (len(self.directory_authorities), self.directory_authorities))

    router_iter = stem.descriptor.router_status_entry._parse_file(
      document_file,
      validate,
      entry_class = RouterStatusEntryMicroV3 if self.is_microdescriptor else RouterStatusEntryV3,
      entry_keyword = ROUTERS_START,
      section_end_keywords = (FOOTER_START, V2_FOOTER_START),
      extra_args = (self,),
    )

    self.routers = dict((desc.fingerprint, desc) for desc in router_iter)
    self._footer(document_file, validate)

  def get_unrecognized_lines(self):
    if self._lazy_loading:
      self._parse(self._header_entries, False, parser_for_line = self.HEADER_PARSER_FOR_LINE)
      self._parse(self._footer_entries, False, parser_for_line = self.FOOTER_PARSER_FOR_LINE)
      self._lazy_loading = False

    return super(NetworkStatusDocumentV3, self).get_unrecognized_lines()

  def meets_consensus_method(self, method):
    """
    Checks if we meet the given consensus-method. This works for both votes and
    consensuses, checking our 'consensus-method' and 'consensus-methods'
    entries.

    :param int method: consensus-method to check for

    :returns: **True** if we meet the given consensus-method, and **False** otherwise
    """

    if self.consensus_method is not None:
      return self.consensus_method >= method
    elif self.consensus_methods is not None:
      return bool([x for x in self.consensus_methods if x >= method])
    else:
      return False  # malformed document

  def _compare(self, other, method):
    if not isinstance(other, NetworkStatusDocumentV3):
      return False

    return method(str(self).strip(), str(other).strip())

  def _header(self, document_file, validate):
    content = bytes.join(b'', _read_until_keywords((AUTH_START, ROUTERS_START, FOOTER_START), document_file))
    entries = _get_descriptor_components(content, validate)

    if validate:
      # all known header fields can only appear once except

      for keyword, values in list(entries.items()):
        if len(values) > 1 and keyword in HEADER_FIELDS and keyword != 'package':
          raise ValueError("Network status documents can only have a single '%s' line, got %i" % (keyword, len(values)))

      if self._default_params:
        self.params = dict(DEFAULT_PARAMS)

      self._parse(entries, validate, parser_for_line = self.HEADER_PARSER_FOR_LINE)

      _check_for_missing_and_disallowed_fields(self, entries, HEADER_STATUS_DOCUMENT_FIELDS)
      _check_for_misordered_fields(entries, HEADER_FIELDS)

      # default consensus_method and consensus_methods based on if we're a consensus or vote

      if self.is_consensus and not self.consensus_method:
        self.consensus_method = 1
      elif self.is_vote and not self.consensus_methods:
        self.consensus_methods = [1]
    else:
      self._header_entries = entries
      self._entries.update(entries)

  def _footer(self, document_file, validate):
    entries = _get_descriptor_components(document_file.read(), validate)

    if validate:
      for keyword, values in list(entries.items()):
        # all known footer fields can only appear once except...
        # * 'directory-signature' in a consensus

        if len(values) > 1 and keyword in FOOTER_FIELDS:
          if not (keyword == 'directory-signature' and self.is_consensus):
            raise ValueError("Network status documents can only have a single '%s' line, got %i" % (keyword, len(values)))

      self._parse(entries, validate, parser_for_line = self.FOOTER_PARSER_FOR_LINE)

      # Check that the footer has the right initial line. Prior to consensus
      # method 9 it's a 'directory-signature' and after that footers start with
      # 'directory-footer'.

      if entries:
        if self.meets_consensus_method(9):
          if list(entries.keys())[0] != 'directory-footer':
            raise ValueError("Network status document's footer should start with a 'directory-footer' line in consensus-method 9 or later")
        else:
          if list(entries.keys())[0] != 'directory-signature':
            raise ValueError("Network status document's footer should start with a 'directory-signature' line prior to consensus-method 9")

        _check_for_missing_and_disallowed_fields(self, entries, FOOTER_STATUS_DOCUMENT_FIELDS)
        _check_for_misordered_fields(entries, FOOTER_FIELDS)
    else:
      self._footer_entries = entries
      self._entries.update(entries)

  def _check_params_constraints(self):
    """
    Checks that the params we know about are within their documented ranges.
    """

    for key, value in self.params.items():
      minimum, maximum = PARAM_RANGE.get(key, (MIN_PARAM, MAX_PARAM))

      # there's a few dynamic parameter ranges

      if key == 'cbtclosequantile':
        minimum = self.params.get('cbtquantile', minimum)
      elif key == 'cbtinitialtimeout':
        minimum = self.params.get('cbtmintimeout', minimum)

      if value < minimum or value > maximum:
        raise ValueError("'%s' value on the params line must be in the range of %i - %i, was %i" % (key, minimum, maximum, value))

  def __hash__(self):
    return hash(str(self).strip())

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __lt__(self, other):
    return self._compare(other, lambda s, o: s < o)

  def __le__(self, other):
    return self._compare(other, lambda s, o: s <= o)


def _check_for_missing_and_disallowed_fields(document, entries, fields):
  """
  Checks that we have mandatory fields for our type, and that we don't have
  any fields exclusive to the other (ie, no vote-only fields appear in a
  consensus or vice versa).

  :param NetworkStatusDocumentV3 document: network status document
  :param dict entries: ordered keyword/value mappings of the header or footer
  :param list fields: expected field attributes (either
    **HEADER_STATUS_DOCUMENT_FIELDS** or **FOOTER_STATUS_DOCUMENT_FIELDS**)

  :raises: **ValueError** if we're missing mandatory fields or have fields we shouldn't
  """

  missing_fields, disallowed_fields = [], []

  for field, in_votes, in_consensus, mandatory in fields:
    if mandatory and ((document.is_consensus and in_consensus) or (document.is_vote and in_votes)):
      # mandatory field, check that we have it
      if field not in entries.keys():
        missing_fields.append(field)
    elif (document.is_consensus and not in_consensus) or (document.is_vote and not in_votes):
      # field we shouldn't have, check that we don't
      if field in entries.keys():
        disallowed_fields.append(field)

  if missing_fields:
    raise ValueError('Network status document is missing mandatory field: %s' % ', '.join(missing_fields))

  if disallowed_fields:
    raise ValueError("Network status document has fields that shouldn't appear in this document type or version: %s" % ', '.join(disallowed_fields))


def _check_for_misordered_fields(entries, expected):
  """
  To be valid a network status document's fiends need to appear in a specific
  order. Checks that known fields appear in that order (unrecognized fields
  are ignored).

  :param dict entries: ordered keyword/value mappings of the header or footer
  :param list expected: ordered list of expected fields (either
    **HEADER_FIELDS** or **FOOTER_FIELDS**)

  :raises: **ValueError** if entries aren't properly ordered
  """

  # Earlier validation has ensured that our fields either belong to our
  # document type or are unknown. Remove the unknown fields since they
  # reflect a spec change and can appear anywhere in the document.

  actual = [field for field in entries.keys() if field in expected]

  # Narrow the expected to just what we have. If the lists then match then the
  # order's valid.

  expected = [field for field in expected if field in actual]

  if actual != expected:
    actual_label = ', '.join(actual)
    expected_label = ', '.join(expected)
    raise ValueError("The fields in a section of the document are misordered. It should be '%s' but was '%s'" % (actual_label, expected_label))


def _parse_int_mappings(keyword, value, validate):
  # Parse a series of 'key=value' entries, checking the following:
  # - values are integers
  # - keys are sorted in lexical order

  results, seen_keys = {}, []
  for entry in value.split(' '):
    try:
      if '=' not in entry:
        raise ValueError("must only have 'key=value' entries")

      entry_key, entry_value = entry.split('=', 1)

      try:
        # the int() function accepts things like '+123', but we don't want to
        if entry_value.startswith('+'):
          raise ValueError()

        entry_value = int(entry_value)
      except ValueError:
        raise ValueError("'%s' is a non-numeric value" % entry_value)

      if validate:
        # parameters should be in ascending order by their key
        for prior_key in seen_keys:
          if prior_key > entry_key:
            raise ValueError('parameters must be sorted by their key')

      results[entry_key] = entry_value
      seen_keys.append(entry_key)
    except ValueError as exc:
      if not validate:
        continue

      raise ValueError("Unable to parse network status document's '%s' line (%s): %s'" % (keyword, exc, value))

  return results


def _parse_dirauth_source_line(descriptor, entries):
  # "dir-source" nickname identity address IP dirport orport

  value = _value('dir-source', entries)
  dir_source_comp = value.split(' ')

  if len(dir_source_comp) < 6:
    raise ValueError("Authority entry's 'dir-source' line must have six values: dir-source %s" % value)

  if not stem.util.tor_tools.is_valid_nickname(dir_source_comp[0].rstrip('-legacy')):
    raise ValueError("Authority's nickname is invalid: %s" % dir_source_comp[0])
  elif not stem.util.tor_tools.is_valid_fingerprint(dir_source_comp[1]):
    raise ValueError("Authority's v3ident is invalid: %s" % dir_source_comp[1])
  elif not dir_source_comp[2]:
    # https://trac.torproject.org/7055
    raise ValueError("Authority's hostname can't be blank: dir-source %s" % value)
  elif not stem.util.connection.is_valid_ipv4_address(dir_source_comp[3]):
    raise ValueError("Authority's address isn't a valid IPv4 address: %s" % dir_source_comp[3])
  elif not stem.util.connection.is_valid_port(dir_source_comp[4], allow_zero = True):
    raise ValueError("Authority's DirPort is invalid: %s" % dir_source_comp[4])
  elif not stem.util.connection.is_valid_port(dir_source_comp[5]):
    raise ValueError("Authority's ORPort is invalid: %s" % dir_source_comp[5])

  descriptor.nickname = dir_source_comp[0]
  descriptor.v3ident = dir_source_comp[1]
  descriptor.hostname = dir_source_comp[2]
  descriptor.address = dir_source_comp[3]
  descriptor.dir_port = None if dir_source_comp[4] == '0' else int(dir_source_comp[4])
  descriptor.or_port = int(dir_source_comp[5])
  descriptor.is_legacy = descriptor.nickname.endswith('-legacy')


_parse_legacy_dir_key_line = _parse_forty_character_hex('legacy-dir-key', 'legacy_dir_key')
_parse_vote_digest_line = _parse_forty_character_hex('vote-digest', 'vote_digest')


class DirectoryAuthority(Descriptor):
  """
  Directory authority information obtained from a v3 network status document.

  Authorities can optionally use a legacy format. These are no longer found in
  practice, but have the following differences...

  * The authority's nickname ends with '-legacy'.
  * There's no **contact** or **vote_digest** attribute.

  :var str nickname: **\*** authority's nickname
  :var str v3ident: **\*** identity key fingerprint used to sign votes and consensus
  :var str hostname: **\*** hostname of the authority
  :var str address: **\*** authority's IP address
  :var int dir_port: **\*** authority's DirPort
  :var int or_port: **\*** authority's ORPort
  :var bool is_legacy: **\*** if the authority's using the legacy format
  :var str contact: contact information, this is included if is_legacy is **False**

  **Consensus Attributes:**

  :var str vote_digest: digest of the authority that contributed to the consensus, this is included if is_legacy is **False**

  **Vote Attributes:**

  :var str legacy_dir_key: fingerprint of and obsolete identity key
  :var stem.descriptor.networkstatus.KeyCertificate key_certificate: **\***
    authority's key certificate

  **\*** mandatory attribute

  .. versionchanged:: 1.4.0
     Renamed our 'fingerprint' attribute to 'v3ident' (prior attribute exists
     for backward compatability, but is deprecated).
  """

  ATTRIBUTES = {
    'nickname': (None, _parse_dirauth_source_line),
    'v3ident': (None, _parse_dirauth_source_line),
    'hostname': (None, _parse_dirauth_source_line),
    'address': (None, _parse_dirauth_source_line),
    'dir_port': (None, _parse_dirauth_source_line),
    'or_port': (None, _parse_dirauth_source_line),
    'is_legacy': (False, _parse_dirauth_source_line),
    'contact': (None, _parse_contact_line),
    'vote_digest': (None, _parse_vote_digest_line),
    'legacy_dir_key': (None, _parse_legacy_dir_key_line),
  }

  PARSER_FOR_LINE = {
    'dir-source': _parse_dirauth_source_line,
    'contact': _parse_contact_line,
    'legacy-dir-key': _parse_legacy_dir_key_line,
    'vote-digest': _parse_vote_digest_line,
  }

  def __init__(self, raw_content, validate = False, is_vote = False):
    """
    Parse a directory authority entry in a v3 network status document.

    :param str raw_content: raw directory authority entry information
    :param bool validate: checks the validity of the content if True, skips
      these checks otherwise
    :param bool is_vote: True if this is for a vote, False if it's for a consensus

    :raises: ValueError if the descriptor data is invalid
    """

    super(DirectoryAuthority, self).__init__(raw_content, lazy_load = not validate)
    content = stem.util.str_tools._to_unicode(raw_content)

    # separate the directory authority entry from its key certificate
    key_div = content.find('\ndir-key-certificate-version')

    if key_div != -1:
      self.key_certificate = KeyCertificate(content[key_div + 1:], validate)
      content = content[:key_div + 1]
    else:
      self.key_certificate = None

    entries = _get_descriptor_components(content, validate)

    if validate and 'dir-source' != list(entries.keys())[0]:
      raise ValueError("Authority entries are expected to start with a 'dir-source' line:\n%s" % (content))

    # check that we have mandatory fields

    if validate:
      is_legacy, dir_source_entry = False, entries.get('dir-source')

      if dir_source_entry:
        is_legacy = dir_source_entry[0][0].split()[0].endswith('-legacy')

      required_fields, excluded_fields = ['dir-source'], []

      if not is_legacy:
        required_fields += ['contact']

      if is_vote:
        if not self.key_certificate:
          raise ValueError('Authority votes must have a key certificate:\n%s' % content)

        excluded_fields += ['vote-digest']
      elif not is_vote:
        if self.key_certificate:
          raise ValueError("Authority consensus entries shouldn't have a key certificate:\n%s" % content)

        if not is_legacy:
          required_fields += ['vote-digest']

        excluded_fields += ['legacy-dir-key']

      for keyword in required_fields:
        if keyword not in entries:
          raise ValueError("Authority entries must have a '%s' line:\n%s" % (keyword, content))

      for keyword in entries:
        if keyword in excluded_fields:
          type_label = 'votes' if is_vote else 'consensus entries'
          raise ValueError("Authority %s shouldn't have a '%s' line:\n%s" % (type_label, keyword, content))

      # all known attributes can only appear at most once
      for keyword, values in list(entries.items()):
        if len(values) > 1 and keyword in ('dir-source', 'contact', 'legacy-dir-key', 'vote-digest'):
          raise ValueError("Authority entries can only have a single '%s' line, got %i:\n%s" % (keyword, len(values), content))

      self._parse(entries, validate)
    else:
      self._entries = entries

    # TODO: Due to a bug we had a 'fingerprint' rather than 'v3ident' attribute
    # for a long while. Keeping this around for backward compatability, but
    # this will be dropped in stem's 2.0 release.

    self.fingerprint = self.v3ident

  def _compare(self, other, method):
    if not isinstance(other, DirectoryAuthority):
      return False

    return method(str(self).strip(), str(other).strip())

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __lt__(self, other):
    return self._compare(other, lambda s, o: s < o)

  def __le__(self, other):
    return self._compare(other, lambda s, o: s <= o)


def _parse_dir_address_line(descriptor, entries):
  # "dir-address" IPPort

  value = _value('dir-address', entries)

  if ':' not in value:
    raise ValueError("Key certificate's 'dir-address' is expected to be of the form ADDRESS:PORT: dir-address %s" % value)

  address, dirport = value.split(':', 1)

  if not stem.util.connection.is_valid_ipv4_address(address):
    raise ValueError("Key certificate's address isn't a valid IPv4 address: dir-address %s" % value)
  elif not stem.util.connection.is_valid_port(dirport):
    raise ValueError("Key certificate's dirport is invalid: dir-address %s" % value)

  descriptor.address = address
  descriptor.dir_port = int(dirport)


_parse_dir_key_certificate_version_line = _parse_version_line('dir-key-certificate-version', 'version', 3)
_parse_dir_key_published_line = _parse_timestamp_line('dir-key-published', 'published')
_parse_dir_key_expires_line = _parse_timestamp_line('dir-key-expires', 'expires')
_parse_identity_key_line = _parse_key_block('dir-identity-key', 'identity_key', 'RSA PUBLIC KEY')
_parse_signing_key_line = _parse_key_block('dir-signing-key', 'signing_key', 'RSA PUBLIC KEY')
_parse_dir_key_crosscert_line = _parse_key_block('dir-key-crosscert', 'crosscert', 'ID SIGNATURE')
_parse_dir_key_certification_line = _parse_key_block('dir-key-certification', 'certification', 'SIGNATURE')


class KeyCertificate(Descriptor):
  """
  Directory key certificate for a v3 network status document.

  :var int version: **\*** version of the key certificate
  :var str address: authority's IP address
  :var int dir_port: authority's DirPort
  :var str fingerprint: **\*** authority's fingerprint
  :var str identity_key: **\*** long term authority identity key
  :var datetime published: **\*** time when this key was generated
  :var datetime expires: **\*** time after which this key becomes invalid
  :var str signing_key: **\*** directory server's public signing key
  :var str crosscert: signature made using certificate's signing key
  :var str certification: **\*** signature of this key certificate signed with
    the identity key

  **\*** mandatory attribute
  """

  ATTRIBUTES = {
    'version': (None, _parse_dir_key_certificate_version_line),
    'address': (None, _parse_dir_address_line),
    'dir_port': (None, _parse_dir_address_line),
    'fingerprint': (None, _parse_fingerprint_line),
    'identity_key': (None, _parse_identity_key_line),
    'published': (None, _parse_dir_key_published_line),
    'expires': (None, _parse_dir_key_expires_line),
    'signing_key': (None, _parse_signing_key_line),
    'crosscert': (None, _parse_dir_key_crosscert_line),
    'certification': (None, _parse_dir_key_certification_line),
  }

  PARSER_FOR_LINE = {
    'dir-key-certificate-version': _parse_dir_key_certificate_version_line,
    'dir-address': _parse_dir_address_line,
    'fingerprint': _parse_fingerprint_line,
    'dir-key-published': _parse_dir_key_published_line,
    'dir-key-expires': _parse_dir_key_expires_line,
    'dir-identity-key': _parse_identity_key_line,
    'dir-signing-key': _parse_signing_key_line,
    'dir-key-crosscert': _parse_dir_key_crosscert_line,
    'dir-key-certification': _parse_dir_key_certification_line,
  }

  def __init__(self, raw_content, validate = False):
    super(KeyCertificate, self).__init__(raw_content, lazy_load = not validate)
    entries = _get_descriptor_components(raw_content, validate)

    if validate:
      if 'dir-key-certificate-version' != list(entries.keys())[0]:
        raise ValueError("Key certificates must start with a 'dir-key-certificate-version' line:\n%s" % (raw_content))
      elif 'dir-key-certification' != list(entries.keys())[-1]:
        raise ValueError("Key certificates must end with a 'dir-key-certification' line:\n%s" % (raw_content))

      # check that we have mandatory fields and that our known fields only
      # appear once

      for keyword, is_mandatory in KEY_CERTIFICATE_PARAMS:
        if is_mandatory and keyword not in entries:
          raise ValueError("Key certificates must have a '%s' line:\n%s" % (keyword, raw_content))

        entry_count = len(entries.get(keyword, []))
        if entry_count > 1:
          raise ValueError("Key certificates can only have a single '%s' line, got %i:\n%s" % (keyword, entry_count, raw_content))

      self._parse(entries, validate)
    else:
      self._entries = entries

  def _compare(self, other, method):
    if not isinstance(other, KeyCertificate):
      return False

    return method(str(self).strip(), str(other).strip())

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __lt__(self, other):
    return self._compare(other, lambda s, o: s < o)

  def __le__(self, other):
    return self._compare(other, lambda s, o: s <= o)


class DocumentSignature(object):
  """
  Directory signature of a v3 network status document.

  :var str method: algorithm used to make the signature
  :var str identity: fingerprint of the authority that made the signature
  :var str key_digest: digest of the signing key
  :var str signature: document signature
  :param bool validate: checks validity if **True**

  :raises: **ValueError** if a validity check fails
  """

  def __init__(self, method, identity, key_digest, signature, validate = False):
    # Checking that these attributes are valid. Technically the key
    # digest isn't a fingerprint, but it has the same characteristics.

    if validate:
      if not stem.util.tor_tools.is_valid_fingerprint(identity):
        raise ValueError('Malformed fingerprint (%s) in the document signature' % identity)

      if not stem.util.tor_tools.is_valid_fingerprint(key_digest):
        raise ValueError('Malformed key digest (%s) in the document signature' % key_digest)

    self.method = method
    self.identity = identity
    self.key_digest = key_digest
    self.signature = signature

  def _compare(self, other, method):
    if not isinstance(other, DocumentSignature):
      return False

    for attr in ('method', 'identity', 'key_digest', 'signature'):
      if getattr(self, attr) != getattr(other, attr):
        return method(getattr(self, attr), getattr(other, attr))

    return method(True, True)  # we're equal

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __lt__(self, other):
    return self._compare(other, lambda s, o: s < o)

  def __le__(self, other):
    return self._compare(other, lambda s, o: s <= o)


class BridgeNetworkStatusDocument(NetworkStatusDocument):
  """
  Network status document containing bridges. This is only available through
  the metrics site.

  :var tuple routers: :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV2`
    contained in the document
  :var datetime published: time when the document was published
  """

  def __init__(self, raw_content, validate = False):
    super(BridgeNetworkStatusDocument, self).__init__(raw_content)

    self.published = None

    document_file = io.BytesIO(raw_content)
    published_line = stem.util.str_tools._to_unicode(document_file.readline())

    if published_line.startswith('published '):
      published_line = published_line.split(' ', 1)[1].strip()

      try:
        self.published = stem.util.str_tools._parse_timestamp(published_line)
      except ValueError:
        if validate:
          raise ValueError("Bridge network status document's 'published' time wasn't parsable: %s" % published_line)
    elif validate:
      raise ValueError("Bridge network status documents must start with a 'published' line:\n%s" % stem.util.str_tools._to_unicode(raw_content))

    router_iter = stem.descriptor.router_status_entry._parse_file(
      document_file,
      validate,
      entry_class = RouterStatusEntryV2,
      extra_args = (self,),
    )

    self.routers = dict((desc.fingerprint, desc) for desc in router_iter)
