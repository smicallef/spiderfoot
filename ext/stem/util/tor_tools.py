# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Miscellaneous utility functions for working with tor.

.. versionadded:: 1.2.0

**Module Overview:**

::

  is_valid_fingerprint - checks if a string is a valid tor relay fingerprint
  is_valid_nickname - checks if a string is a valid tor relay nickname
  is_valid_circuit_id - checks if a string is a valid tor circuit id
  is_valid_stream_id - checks if a string is a valid tor stream id
  is_valid_connection_id - checks if a string is a valid tor connection id
  is_valid_hidden_service_address - checks if a string is a valid hidden service address
  is_hex_digits - checks if a string is only made up of hex digits
"""

import re

# The control-spec defines the following as...
#
#   Fingerprint = "$" 40*HEXDIG
#   NicknameChar = "a"-"z" / "A"-"Z" / "0" - "9"
#   Nickname = 1*19 NicknameChar
#
#   CircuitID = 1*16 IDChar
#   IDChar = ALPHA / DIGIT
#
# HEXDIG is defined in RFC 5234 as being uppercase and used in RFC 5987 as
# case insensitive. Tor doesn't define this in the spec so flipping a coin
# and going with case insensitive.

NICKNAME_PATTERN = re.compile('^[a-zA-Z0-9]{1,19}$')
CIRC_ID_PATTERN = re.compile('^[a-zA-Z0-9]{1,16}$')

# Hidden service addresses are sixteen base32 characters.

HS_ADDRESS_PATTERN = re.compile('^[a-z2-7]{16}$')


def is_valid_fingerprint(entry, check_prefix = False):
  """
  Checks if a string is a properly formatted relay fingerprint. This checks for
  a '$' prefix if check_prefix is true, otherwise this only validates the hex
  digits.

  :param str entry: string to be checked
  :param bool check_prefix: checks for a '$' prefix

  :returns: **True** if the string could be a relay fingerprint, **False** otherwise
  """

  try:
    if check_prefix:
      if not entry or entry[0] != '$':
        return False

      entry = entry[1:]

    return is_hex_digits(entry, 40)
  except TypeError:
    return False


def is_valid_nickname(entry):
  """
  Checks if a string is a valid format for being a nickname.

  :param str entry: string to be checked

  :returns: **True** if the string could be a nickname, **False** otherwise
  """

  try:
    return bool(NICKNAME_PATTERN.match(entry))
  except TypeError:
    return False


def is_valid_circuit_id(entry):
  """
  Checks if a string is a valid format for being a circuit identifier.

  :returns: **True** if the string could be a circuit id, **False** otherwise
  """

  try:
    return bool(CIRC_ID_PATTERN.match(entry))
  except TypeError:
    return False


def is_valid_stream_id(entry):
  """
  Checks if a string is a valid format for being a stream identifier.
  Currently, this is just an alias to :func:`~stem.util.tor_tools.is_valid_circuit_id`.

  :returns: **True** if the string could be a stream id, **False** otherwise
  """

  return is_valid_circuit_id(entry)


def is_valid_connection_id(entry):
  """
  Checks if a string is a valid format for being a connection identifier.
  Currently, this is just an alias to :func:`~stem.util.tor_tools.is_valid_circuit_id`.

  :returns: **True** if the string could be a connection id, **False** otherwise
  """

  return is_valid_circuit_id(entry)


def is_valid_hidden_service_address(entry):
  """
  Checks if a string is a valid format for being a hidden service address (not
  including the '.onion' suffix).

  :returns: **True** if the string could be a hidden service address, **False** otherwise
  """

  try:
    return bool(HS_ADDRESS_PATTERN.match(entry))
  except TypeError:
    return False


def is_hex_digits(entry, count):
  """
  Checks if a string is the given number of hex digits. Digits represented by
  letters are case insensitive.

  :param str entry: string to be checked
  :param int count: number of hex digits to be checked for

  :returns: **True** if the given number of hex digits, **False** otherwise
  """

  try:
    if len(entry) != count:
      return False

    int(entry, 16)  # attempt to convert it as hex
    return True
  except (ValueError, TypeError):
    return False
