# Copyright 2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for Tor hidden service descriptors as described in Tor's `rend-spec
<https://gitweb.torproject.org/torspec.git/tree/rend-spec.txt>`_.

Unlike other descriptor types these describe a hidden service rather than a
relay. They're created by the service, and can only be fetched via relays with
the HSDir flag.

**Module Overview:**

::

  HiddenServiceDescriptor - Tor hidden service descriptor.

.. versionadded:: 1.4.0
"""

# TODO: Add a description for how to retrieve them when tor supports that
# (#14847) and then update #15009.

import base64
import binascii
import collections
import hashlib
import io

import stem.util.connection
import stem.util.str_tools

from stem.descriptor import (
  PGP_BLOCK_END,
  Descriptor,
  _get_descriptor_components,
  _read_until_keywords,
  _bytes_for_block,
  _value,
  _parse_simple_line,
  _parse_timestamp_line,
  _parse_key_block,
)

try:
  # added in python 3.2
  from functools import lru_cache
except ImportError:
  from stem.util.lru_cache import lru_cache

REQUIRED_FIELDS = (
  'rendezvous-service-descriptor',
  'version',
  'permanent-key',
  'secret-id-part',
  'publication-time',
  'protocol-versions',
  'signature',
)

INTRODUCTION_POINTS_ATTR = {
  'identifier': None,
  'address': None,
  'port': None,
  'onion_key': None,
  'service_key': None,
  'intro_authentication': [],
}

# introduction-point fields that can only appear once

SINGLE_INTRODUCTION_POINT_FIELDS = [
  'introduction-point',
  'ip-address',
  'onion-port',
  'onion-key',
  'service-key',
]

BASIC_AUTH = 1
STEALTH_AUTH = 2

IntroductionPoint = collections.namedtuple('IntroductionPoints', INTRODUCTION_POINTS_ATTR.keys())


class DecryptionFailure(Exception):
  """
  Failure to decrypt the hidden service descriptor's introduction-points.
  """


def _parse_file(descriptor_file, validate = False, **kwargs):
  """
  Iterates over the hidden service descriptors in a file.

  :param file descriptor_file: file with descriptor content
  :param bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :param dict kwargs: additional arguments for the descriptor constructor

  :returns: iterator for :class:`~stem.descriptor.hidden_service_descriptor.HiddenServiceDescriptor`
    instances in the file

  :raises:
    * **ValueError** if the contents is malformed and validate is **True**
    * **IOError** if the file can't be read
  """

  while True:
    descriptor_content = _read_until_keywords('signature', descriptor_file)

    # we've reached the 'signature', now include the pgp style block
    block_end_prefix = PGP_BLOCK_END.split(' ', 1)[0]
    descriptor_content += _read_until_keywords(block_end_prefix, descriptor_file, True)

    if descriptor_content:
      if descriptor_content[0].startswith(b'@type'):
        descriptor_content = descriptor_content[1:]

      yield HiddenServiceDescriptor(bytes.join(b'', descriptor_content), validate, **kwargs)
    else:
      break  # done parsing file


def _parse_version_line(descriptor, entries):
  value = _value('version', entries)

  if value.isdigit():
    descriptor.version = int(value)
  else:
    raise ValueError('version line must have a positive integer value: %s' % value)


def _parse_protocol_versions_line(descriptor, entries):
  value = _value('protocol-versions', entries)

  try:
    versions = [int(entry) for entry in value.split(',')]
  except ValueError:
    raise ValueError('protocol-versions line has non-numeric versoins: protocol-versions %s' % value)

  for v in versions:
    if v <= 0:
      raise ValueError('protocol-versions must be positive integers: %s' % value)

  descriptor.protocol_versions = versions


def _parse_introduction_points_line(descriptor, entries):
  _, block_type, block_contents = entries['introduction-points'][0]

  if not block_contents or block_type != 'MESSAGE':
    raise ValueError("'introduction-points' should be followed by a MESSAGE block, but was a %s" % block_type)

  descriptor.introduction_points_encoded = block_contents

  try:
    decoded_field = _bytes_for_block(block_contents)
  except TypeError:
    raise ValueError("'introduction-points' isn't base64 encoded content:\n%s" % block_contents)

  auth_types = []

  while decoded_field.startswith(b'service-authentication ') and b'\n' in decoded_field:
    auth_line, decoded_field = decoded_field.split(b'\n', 1)
    auth_line_comp = auth_line.split(b' ')

    if len(auth_line_comp) < 3:
      raise ValueError("Within introduction-points we expected 'service-authentication [auth_type] [auth_data]', but had '%s'" % auth_line)

    auth_types.append((auth_line_comp[1], auth_line_comp[2]))

  descriptor.introduction_points_auth = auth_types
  descriptor.introduction_points_content = decoded_field

_parse_rendezvous_service_descriptor_line = _parse_simple_line('rendezvous-service-descriptor', 'descriptor_id')
_parse_permanent_key_line = _parse_key_block('permanent-key', 'permanent_key', 'RSA PUBLIC KEY')
_parse_secret_id_part_line = _parse_simple_line('secret-id-part', 'secret_id_part')
_parse_publication_time_line = _parse_timestamp_line('publication-time', 'published')
_parse_signature_line = _parse_key_block('signature', 'signature', 'SIGNATURE')


class HiddenServiceDescriptor(Descriptor):
  """
  Hidden service descriptor.

  :var str descriptor_id: **\*** identifier for this descriptor, this is a base32 hash of several fields
  :var int version: **\*** hidden service descriptor version
  :var str permanent_key: **\*** long term key of the hidden service
  :var str secret_id_part: **\*** hash of the time period, cookie, and replica
    values so our descriptor_id can be validated
  :var datetime published: **\*** time in UTC when this descriptor was made
  :var list protocol_versions: **\*** list of **int** versions that are supported when establishing a connection
  :var str introduction_points_encoded: raw introduction points blob
  :var list introduction_points_auth: **\*** tuples of the form
    (auth_method, auth_data) for our introduction_points_content
  :var bytes introduction_points_content: decoded introduction-points content
    without authentication data, if using cookie authentication this is
    encrypted
  :var str signature: signature of the descriptor content

  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """

  ATTRIBUTES = {
    'descriptor_id': (None, _parse_rendezvous_service_descriptor_line),
    'version': (None, _parse_version_line),
    'permanent_key': (None, _parse_permanent_key_line),
    'secret_id_part': (None, _parse_secret_id_part_line),
    'published': (None, _parse_publication_time_line),
    'protocol_versions': ([], _parse_protocol_versions_line),
    'introduction_points_encoded': (None, _parse_introduction_points_line),
    'introduction_points_auth': ([], _parse_introduction_points_line),
    'introduction_points_content': (None, _parse_introduction_points_line),
    'signature': (None, _parse_signature_line),
  }

  PARSER_FOR_LINE = {
    'rendezvous-service-descriptor': _parse_rendezvous_service_descriptor_line,
    'version': _parse_version_line,
    'permanent-key': _parse_permanent_key_line,
    'secret-id-part': _parse_secret_id_part_line,
    'publication-time': _parse_publication_time_line,
    'protocol-versions': _parse_protocol_versions_line,
    'introduction-points': _parse_introduction_points_line,
    'signature': _parse_signature_line,
  }

  def __init__(self, raw_contents, validate = False):
    super(HiddenServiceDescriptor, self).__init__(raw_contents, lazy_load = not validate)
    entries = _get_descriptor_components(raw_contents, validate)

    if validate:
      for keyword in REQUIRED_FIELDS:
        if keyword not in entries:
          raise ValueError("Hidden service descriptor must have a '%s' entry" % keyword)
        elif keyword in entries and len(entries[keyword]) > 1:
          raise ValueError("The '%s' entry can only appear once in a hidden service descriptor" % keyword)

      if 'rendezvous-service-descriptor' != list(entries.keys())[0]:
        raise ValueError("Hidden service descriptor must start with a 'rendezvous-service-descriptor' entry")
      elif 'signature' != list(entries.keys())[-1]:
        raise ValueError("Hidden service descriptor must end with a 'signature' entry")

      self._parse(entries, validate)

      if stem.prereq.is_crypto_available():
        signed_digest = self._digest_for_signature(self.permanent_key, self.signature)
        content_digest = self._digest_for_content(b'rendezvous-service-descriptor ', b'\nsignature\n')

        if signed_digest != content_digest:
          raise ValueError('Decrypted digest does not match local digest (calculated: %s, local: %s)' % (signed_digest, content_digest))
    else:
      self._entries = entries

  @lru_cache()
  def introduction_points(self, authentication_cookie = None):
    """
    Provided this service's introduction points. This provides a list of
    IntroductionPoint instances, which have the following attributes...

      * **identifier** (str): hash of this introduction point's identity key
      * **address** (str): address of this introduction point
      * **port** (int): port where this introduction point is listening
      * **onion_key** (str): public key for communicating with this introduction point
      * **service_key** (str): public key for communicating with this hidden service
      * **intro_authentication** (list): tuples of the form (auth_type, auth_data)
        for establishing a connection

    :param str authentication_cookie: cookie to decrypt the introduction-points
      if it's encrypted

    :returns: **list** of IntroductionPoints instances

    :raises:
      * **ValueError** if the our introduction-points is malformed
      * **DecryptionFailure** if unable to decrypt this field
    """

    content = self.introduction_points_content

    if not content:
      return []
    elif authentication_cookie:
      if not stem.prereq.is_crypto_available():
        raise DecryptionFailure('Decrypting introduction-points requires pycrypto')

      try:
        missing_padding = len(authentication_cookie) % 4
        authentication_cookie = base64.b64decode(stem.util.str_tools._to_bytes(authentication_cookie) + b'=' * missing_padding)
      except TypeError as exc:
        raise DecryptionFailure('authentication_cookie must be a base64 encoded string (%s)' % exc)

      authentication_type = int(binascii.hexlify(content[0:1]), 16)

      if authentication_type == BASIC_AUTH:
        content = HiddenServiceDescriptor._decrypt_basic_auth(content, authentication_cookie)
      elif authentication_type == STEALTH_AUTH:
        content = HiddenServiceDescriptor._decrypt_stealth_auth(content, authentication_cookie)
      else:
        raise DecryptionFailure("Unrecognized authentication type '%s', currently we only support basic auth (%s) and stealth auth (%s)" % (authentication_type, BASIC_AUTH, STEALTH_AUTH))

      if not content.startswith(b'introduction-point '):
        raise DecryptionFailure('Unable to decrypt the introduction-points, maybe this is the wrong key?')
    elif not content.startswith(b'introduction-point '):
      raise DecryptionFailure('introduction-points content is encrypted, you need to provide its authentication_cookie')

    return HiddenServiceDescriptor._parse_introduction_points(content)

  @staticmethod
  def _decrypt_basic_auth(content, authentication_cookie):
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    from Crypto.Util.number import bytes_to_long

    try:
      client_blocks = int(binascii.hexlify(content[1:2]), 16)
    except ValueError:
      raise DecryptionFailure("When using basic auth the content should start with a number of blocks but wasn't a hex digit: %s" % binascii.hexlify(content[1:2]))

    # parse the client id and encrypted session keys

    client_entries_length = client_blocks * 16 * 20
    client_entries = content[2:2 + client_entries_length]
    client_keys = [(client_entries[i:i + 4], client_entries[i + 4:i + 20]) for i in range(0, client_entries_length, 4 + 16)]

    iv = content[2 + client_entries_length:2 + client_entries_length + 16]
    encrypted = content[2 + client_entries_length + 16:]

    client_id = hashlib.sha1(authentication_cookie + iv).digest()[:4]

    for entry_id, encrypted_session_key in client_keys:
      if entry_id != client_id:
        continue  # not the session key for this client

      # try decrypting the session key

      counter = Counter.new(128, initial_value = 0)
      cipher = AES.new(authentication_cookie, AES.MODE_CTR, counter = counter)
      session_key = cipher.decrypt(encrypted_session_key)

      # attempt to decrypt the intro points with the session key

      counter = Counter.new(128, initial_value = bytes_to_long(iv))
      cipher = AES.new(session_key, AES.MODE_CTR, counter = counter)
      decrypted = cipher.decrypt(encrypted)

      # check if the decryption looks correct

      if decrypted.startswith(b'introduction-point '):
        return decrypted

    return content  # nope, unable to decrypt the content

  @staticmethod
  def _decrypt_stealth_auth(content, authentication_cookie):
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    from Crypto.Util.number import bytes_to_long

    # byte 1 = authentication type, 2-17 = input vector, 18 on = encrypted content

    iv, encrypted = content[1:17], content[17:]
    counter = Counter.new(128, initial_value = bytes_to_long(iv))
    cipher = AES.new(authentication_cookie, AES.MODE_CTR, counter = counter)

    return cipher.decrypt(encrypted)

  @staticmethod
  def _parse_introduction_points(content):
    """
    Provides the parsed list of IntroductionPoint for the unencrypted content.
    """

    introduction_points = []
    content_io = io.BytesIO(content)

    while True:
      content = b''.join(_read_until_keywords('introduction-point', content_io, ignore_first = True))

      if not content:
        break  # reached the end

      attr = dict(INTRODUCTION_POINTS_ATTR)
      entries = _get_descriptor_components(content, False)

      for keyword, values in list(entries.items()):
        value, block_type, block_contents = values[0]

        if keyword in SINGLE_INTRODUCTION_POINT_FIELDS and len(values) > 1:
          raise ValueError("'%s' can only appear once in an introduction-point block, but appeared %i times" % (keyword, len(values)))

        if keyword == 'introduction-point':
          attr['identifier'] = value
        elif keyword == 'ip-address':
          if not stem.util.connection.is_valid_ipv4_address(value):
            raise ValueError("'%s' is an invalid IPv4 address" % value)

          attr['address'] = value
        elif keyword == 'onion-port':
          if not stem.util.connection.is_valid_port(value):
            raise ValueError("'%s' is an invalid port" % value)

          attr['port'] = int(value)
        elif keyword == 'onion-key':
          attr['onion_key'] = block_contents
        elif keyword == 'service-key':
          attr['service_key'] = block_contents
        elif keyword == 'intro-authentication':
          auth_entries = []

          for auth_value, _, _ in values:
            if ' ' not in auth_value:
              raise ValueError("We expected 'intro-authentication [auth_type] [auth_data]', but had '%s'" % auth_value)

            auth_type, auth_data = auth_value.split(' ')[:2]
            auth_entries.append((auth_type, auth_data))

      introduction_points.append(IntroductionPoint(**attr))

    return introduction_points
