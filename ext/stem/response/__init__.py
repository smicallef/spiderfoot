# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parses replies from the control socket.

**Module Overview:**

::

  convert - translates a ControlMessage into a particular response subclass

  ControlMessage - Message that's read from the control socket.
    |- SingleLineResponse - Simple tor response only including a single line of information.
    |
    |- from_str - provides a ControlMessage for the given string
    |- is_ok - response had a 250 status
    |- content - provides the parsed message content
    |- raw_content - unparsed socket data
    |- __str__ - content stripped of protocol formatting
    +- __iter__ - ControlLine entries for the content of the message

  ControlLine - String subclass with methods for parsing controller responses.
    |- remainder - provides the unparsed content
    |- is_empty - checks if the remaining content is empty
    |- is_next_quoted - checks if the next entry is a quoted value
    |- is_next_mapping - checks if the next entry is a KEY=VALUE mapping
    |- peek_key - provides the key of the next entry
    |- pop - removes and returns the next entry
    +- pop_mapping - removes and returns the next entry as a KEY=VALUE mapping
"""

__all__ = [
  'add_onion',
  'events',
  'getinfo',
  'getconf',
  'protocolinfo',
  'authchallenge',
  'convert',
  'ControlMessage',
  'ControlLine',
  'SingleLineResponse',
]

import re
import threading

try:
  from StringIO import StringIO
except ImportError:
  from io import StringIO

import stem.socket

KEY_ARG = re.compile('^(\S+)=')

# Escape sequences from the 'esc_for_log' function of tor's 'common/util.c'.
# It's hard to tell what controller functions use this in practice, but direct
# users are...
# - 'COOKIEFILE' field of PROTOCOLINFO responses
# - logged messages about bugs
# - the 'getinfo_helper_listeners' function of control.c

CONTROL_ESCAPES = {r'\\': '\\', r'\"': '\"', r'\'': '\'',
                   r'\r': '\r', r'\n': '\n', r'\t': '\t'}


def convert(response_type, message, **kwargs):
  """
  Converts a :class:`~stem.response.ControlMessage` into a particular kind of
  tor response. This does an in-place conversion of the message from being a
  :class:`~stem.response.ControlMessage` to a subclass for its response type.
  Recognized types include...

  =================== =====
  response_type       Class
  =================== =====
  **GETINFO**         :class:`stem.response.getinfo.GetInfoResponse`
  **GETCONF**         :class:`stem.response.getconf.GetConfResponse`
  **MAPADDRESS**      :class:`stem.response.mapaddress.MapAddressResponse`
  **EVENT**           :class:`stem.response.events.Event` subclass
  **PROTOCOLINFO**    :class:`stem.response.protocolinfo.ProtocolInfoResponse`
  **AUTHCHALLENGE**   :class:`stem.response.authchallenge.AuthChallengeResponse`
  **SINGLELINE**      :class:`stem.response.SingleLineResponse`
  =================== =====

  :param str response_type: type of tor response to convert to
  :param stem.response.ControlMessage message: message to be converted
  :param kwargs: optional keyword arguments to be passed to the parser method

  :raises:
    * :class:`stem.ProtocolError` the message isn't a proper response of
      that type
    * :class:`stem.InvalidArguments` the arguments given as input are
      invalid, this is can only be raised if the response_type is: **GETINFO**,
      **GETCONF**
    * :class:`stem.InvalidRequest` the arguments given as input are
      invalid, this is can only be raised if the response_type is:
      **MAPADDRESS**
    * :class:`stem.OperationFailed` if the action the event represents failed,
      this is can only be raised if the response_type is: **MAPADDRESS**
    * **TypeError** if argument isn't a :class:`~stem.response.ControlMessage`
      or response_type isn't supported
  """

  import stem.response.add_onion
  import stem.response.authchallenge
  import stem.response.events
  import stem.response.getinfo
  import stem.response.getconf
  import stem.response.mapaddress
  import stem.response.protocolinfo

  if not isinstance(message, ControlMessage):
    raise TypeError('Only able to convert stem.response.ControlMessage instances')

  response_types = {
    'ADD_ONION': stem.response.add_onion.AddOnionResponse,
    'AUTHCHALLENGE': stem.response.authchallenge.AuthChallengeResponse,
    'EVENT': stem.response.events.Event,
    'GETINFO': stem.response.getinfo.GetInfoResponse,
    'GETCONF': stem.response.getconf.GetConfResponse,
    'MAPADDRESS': stem.response.mapaddress.MapAddressResponse,
    'SINGLELINE': SingleLineResponse,
    'PROTOCOLINFO': stem.response.protocolinfo.ProtocolInfoResponse,
  }

  try:
    response_class = response_types[response_type]
  except TypeError:
    raise TypeError('Unsupported response type: %s' % response_type)

  message.__class__ = response_class
  message._parse_message(**kwargs)


class ControlMessage(object):
  """
  Message from the control socket. This is iterable and can be stringified for
  individual message components stripped of protocol formatting. Messages are
  never empty.
  """

  @staticmethod
  def from_str(content, msg_type = None, **kwargs):
    """
    Provides a ControlMessage for the given content.

    .. versionadded:: 1.1.0

    :param str content: message to construct the message from
    :param str msg_type: type of tor reply to parse the content as
    :param kwargs: optional keyword arguments to be passed to the parser method

    :returns: stem.response.ControlMessage instance
    """

    msg = stem.socket.recv_message(StringIO(content))

    if msg_type is not None:
      convert(msg_type, msg, **kwargs)

    return msg

  def __init__(self, parsed_content, raw_content):
    if not parsed_content:
      raise ValueError("ControlMessages can't be empty")

    self._parsed_content = parsed_content
    self._raw_content = raw_content

  def is_ok(self):
    """
    Checks if any of our lines have a 250 response.

    :returns: **True** if any lines have a 250 response code, **False** otherwise
    """

    for code, _, _ in self._parsed_content:
      if code == '250':
        return True

    return False

  def content(self, get_bytes = False):
    """
    Provides the parsed message content. These are entries of the form...

    ::

      (status_code, divider, content)

    **status_code**
      Three character code for the type of response (defined in section 4 of
      the control-spec).

    **divider**
      Single character to indicate if this is mid-reply, data, or an end to the
      message (defined in section 2.3 of the control-spec).

    **content**
      The following content is the actual payload of the line.

    For data entries the content is the full multi-line payload with newline
    linebreaks and leading periods unescaped.

    The **status_code** and **divider** are both strings (**bytes** in python
    2.x and **unicode** in python 3.x). The **content** however is **bytes** if
    **get_bytes** is **True**.

    .. versionchanged:: 1.1.0
       Added the get_bytes argument.

    :param bool get_bytes: provides **bytes** for the **content** rather than a **str**

    :returns: **list** of (str, str, str) tuples for the components of this message
    """

    if stem.prereq.is_python_3() and not get_bytes:
      return [(code, div, stem.util.str_tools._to_unicode(content)) for (code, div, content) in self._parsed_content]
    else:
      return list(self._parsed_content)

  def raw_content(self, get_bytes = False):
    """
    Provides the unparsed content read from the control socket.

    .. versionchanged:: 1.1.0
       Added the get_bytes argument.

    :param bool get_bytes: if **True** then this provides **bytes** rather than a **str**

    :returns: **str** of the socket data used to generate this message
    """

    if stem.prereq.is_python_3() and not get_bytes:
      return stem.util.str_tools._to_unicode(self._raw_content)
    else:
      return self._raw_content

  def __str__(self):
    """
    Content of the message, stripped of status code and divider protocol
    formatting.
    """

    return '\n'.join(list(self))

  def __iter__(self):
    """
    Provides :class:`~stem.response.ControlLine` instances for the content of
    the message. This is stripped of status codes and dividers, for instance...

    ::

      250+info/names=
      desc/id/* -- Router descriptors by ID.
      desc/name/* -- Router descriptors by nickname.
      .
      250 OK

    Would provide two entries...

    ::

      1st - "info/names=
             desc/id/* -- Router descriptors by ID.
             desc/name/* -- Router descriptors by nickname."
      2nd - "OK"
    """

    for _, _, content in self._parsed_content:
      if stem.prereq.is_python_3():
        content = stem.util.str_tools._to_unicode(content)

      yield ControlLine(content)

  def __len__(self):
    """
    :returns: number of ControlLines
    """

    return len(self._parsed_content)

  def __getitem__(self, index):
    """
    :returns: :class:`~stem.response.ControlLine` at the index
    """

    content = self._parsed_content[index][2]

    if stem.prereq.is_python_3():
      content = stem.util.str_tools._to_unicode(content)

    return ControlLine(content)


class ControlLine(str):
  """
  String subclass that represents a line of controller output. This behaves as
  a normal string with additional methods for parsing and popping entries from
  a space delimited series of elements like a stack.

  None of these additional methods effect ourselves as a string (which is still
  immutable). All methods are thread safe.
  """

  def __new__(self, value):
    return str.__new__(self, value)

  def __init__(self, value):
    self._remainder = value
    self._remainder_lock = threading.RLock()

  def remainder(self):
    """
    Provides our unparsed content. This is an empty string after we've popped
    all entries.

    :returns: **str** of the unparsed content
    """

    return self._remainder

  def is_empty(self):
    """
    Checks if we have further content to pop or not.

    :returns: **True** if we have additional content, **False** otherwise
    """

    return self._remainder == ''

  def is_next_quoted(self, escaped = False):
    """
    Checks if our next entry is a quoted value or not.

    :param bool escaped: unescapes the CONTROL_ESCAPES escape sequences

    :returns: **True** if the next entry can be parsed as a quoted value, **False** otherwise
    """

    start_quote, end_quote = _get_quote_indices(self._remainder, escaped)
    return start_quote == 0 and end_quote != -1

  def is_next_mapping(self, key = None, quoted = False, escaped = False):
    """
    Checks if our next entry is a KEY=VALUE mapping or not.

    :param str key: checks that the key matches this value, skipping the check if **None**
    :param bool quoted: checks that the mapping is to a quoted value
    :param bool escaped: unescapes the CONTROL_ESCAPES escape sequences

    :returns: **True** if the next entry can be parsed as a key=value mapping,
      **False** otherwise
    """

    remainder = self._remainder  # temp copy to avoid locking
    key_match = KEY_ARG.match(remainder)

    if key_match:
      if key and key != key_match.groups()[0]:
        return False

      if quoted:
        # checks that we have a quoted value and that it comes after the 'key='
        start_quote, end_quote = _get_quote_indices(remainder, escaped)
        return start_quote == key_match.end() and end_quote != -1
      else:
        return True  # we just needed to check for the key
    else:
      return False  # doesn't start with a key

  def peek_key(self):
    """
    Provides the key of the next entry, providing **None** if it isn't a
    key/value mapping.

    :returns: **str** with the next entry's key
    """

    remainder = self._remainder
    key_match = KEY_ARG.match(remainder)

    if key_match:
      return key_match.groups()[0]
    else:
      return None

  def pop(self, quoted = False, escaped = False):
    """
    Parses the next space separated entry, removing it and the space from our
    remaining content. Examples...

    ::

      >>> line = ControlLine("\\"We're all mad here.\\" says the grinning cat.")
      >>> print line.pop(True)
        "We're all mad here."
      >>> print line.pop()
        "says"
      >>> print line.remainder()
        "the grinning cat."

      >>> line = ControlLine("\\"this has a \\\\\\" and \\\\\\\\ in it\\" foo=bar more_data")
      >>> print line.pop(True, True)
        "this has a \\" and \\\\ in it"

    :param bool quoted: parses the next entry as a quoted value, removing the quotes
    :param bool escaped: unescapes the CONTROL_ESCAPES escape sequences

    :returns: **str** of the next space separated entry

    :raises:
      * **ValueError** if quoted is True without the value being quoted
      * **IndexError** if we don't have any remaining content left to parse
    """

    with self._remainder_lock:
      next_entry, remainder = _parse_entry(self._remainder, quoted, escaped)
      self._remainder = remainder
      return next_entry

  def pop_mapping(self, quoted = False, escaped = False):
    """
    Parses the next space separated entry as a KEY=VALUE mapping, removing it
    and the space from our remaining content.

    :param bool quoted: parses the value as being quoted, removing the quotes
    :param bool escaped: unescapes the CONTROL_ESCAPES escape sequences

    :returns: **tuple** of the form (key, value)

    :raises: **ValueError** if this isn't a KEY=VALUE mapping or if quoted is
      **True** without the value being quoted
    :raises: **IndexError** if there's nothing to parse from the line
    """

    with self._remainder_lock:
      if self.is_empty():
        raise IndexError('no remaining content to parse')

      key_match = KEY_ARG.match(self._remainder)

      if not key_match:
        raise ValueError("the next entry isn't a KEY=VALUE mapping: " + self._remainder)

      # parse off the key
      key = key_match.groups()[0]
      remainder = self._remainder[key_match.end():]

      next_entry, remainder = _parse_entry(remainder, quoted, escaped)
      self._remainder = remainder
      return (key, next_entry)


def _parse_entry(line, quoted, escaped):
  """
  Parses the next entry from the given space separated content.

  :param str line: content to be parsed
  :param bool quoted: parses the next entry as a quoted value, removing the quotes
  :param bool escaped: unescapes the CONTROL_ESCAPES escape sequences

  :returns: **tuple** of the form (entry, remainder)

  :raises:
    * **ValueError** if quoted is True without the next value being quoted
    * **IndexError** if there's nothing to parse from the line
  """

  if line == '':
    raise IndexError('no remaining content to parse')

  next_entry, remainder = '', line

  if quoted:
    # validate and parse the quoted value
    start_quote, end_quote = _get_quote_indices(remainder, escaped)

    if start_quote != 0 or end_quote == -1:
      raise ValueError("the next entry isn't a quoted value: " + line)

    next_entry, remainder = remainder[1:end_quote], remainder[end_quote + 1:]
  else:
    # non-quoted value, just need to check if there's more data afterward
    if ' ' in remainder:
      next_entry, remainder = remainder.split(' ', 1)
    else:
      next_entry, remainder = remainder, ''

  if escaped:
    next_entry = _unescape(next_entry)

  return (next_entry, remainder.lstrip())


def _get_quote_indices(line, escaped):
  """
  Provides the indices of the next two quotes in the given content.

  :param str line: content to be parsed
  :param bool escaped: unescapes the CONTROL_ESCAPES escape sequences

  :returns: **tuple** of two ints, indices being -1 if a quote doesn't exist
  """

  indices, quote_index = [], -1

  for _ in range(2):
    quote_index = line.find('"', quote_index + 1)

    # if we have escapes then we need to skip any r'\"' entries
    if escaped:
      # skip check if index is -1 (no match) or 0 (first character)
      while quote_index >= 1 and line[quote_index - 1] == '\\':
        quote_index = line.find('"', quote_index + 1)

    indices.append(quote_index)

  return tuple(indices)


def _unescape(entry):
  # Unescapes the given string with the mappings in CONTROL_ESCAPES.
  #
  # This can't be a simple series of str.replace() calls because replacements
  # need to be excluded from consideration for further unescaping. For
  # instance, '\\t' should be converted to '\t' rather than a tab.

  def _pop_with_unescape(entry):
    # Pop either the first character or the escape sequence conversion the
    # entry starts with. This provides a tuple of...
    #
    #   (unescaped prefix, remaining entry)

    for esc_sequence, replacement in CONTROL_ESCAPES.items():
      if entry.startswith(esc_sequence):
        return (replacement, entry[len(esc_sequence):])

    return (entry[0], entry[1:])

  result = []

  while entry:
    prefix, entry = _pop_with_unescape(entry)
    result.append(prefix)

  return ''.join(result)


class SingleLineResponse(ControlMessage):
  """
  Reply to a request that performs an action rather than querying data. These
  requests only contain a single line, which is 'OK' if successful, and a
  description of the problem if not.

  :var str code: status code for our line
  :var str message: content of the line
  """

  def is_ok(self, strict = False):
    """
    Checks if the response code is "250". If strict is **True** then this
    checks if the response is "250 OK"

    :param bool strict: checks for a "250 OK" message if **True**

    :returns:
      * If strict is **False**: **True** if the response code is "250", **False** otherwise
      * If strict is **True**: **True** if the response is "250 OK", **False** otherwise
    """

    if strict:
      return self.content()[0] == ('250', ' ', 'OK')

    return self.content()[0][0] == '250'

  def _parse_message(self):
    content = self.content()

    if len(content) > 1:
      raise stem.ProtocolError('Received multi-line response')
    elif len(content) == 0:
      raise stem.ProtocolError('Received empty response')
    else:
      self.code, _, self.message = content[0]
