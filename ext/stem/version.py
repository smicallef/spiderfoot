# Copyright 2011-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Tor versioning information and requirements for its features. These can be
easily parsed and compared, for instance...

::

  >>> from stem.version import get_system_tor_version, Requirement
  >>> my_version = get_system_tor_version()
  >>> print(my_version)
  0.2.1.30
  >>> my_version >= Requirement.TORRC_CONTROL_SOCKET
  True

**Module Overview:**

::

  get_system_tor_version - gets the version of our system's tor installation

  Version - Tor versioning information

.. data:: Requirement (enum)

  Enumerations for the version requirements of features.

  ===================================== ===========
  Requirement                           Description
  ===================================== ===========
  **AUTH_SAFECOOKIE**                   SAFECOOKIE authentication method
  **DROPGUARDS**                        DROPGUARDS requests
  **EVENT_AUTHDIR_NEWDESCS**            AUTHDIR_NEWDESC events
  **EVENT_BUILDTIMEOUT_SET**            BUILDTIMEOUT_SET events
  **EVENT_CIRC_MINOR**                  CIRC_MINOR events
  **EVENT_CLIENTS_SEEN**                CLIENTS_SEEN events
  **EVENT_CONF_CHANGED**                CONF_CHANGED events
  **EVENT_DESCCHANGED**                 DESCCHANGED events
  **EVENT_GUARD**                       GUARD events
  **EVENT_HS_DESC_CONTENT**             HS_DESC_CONTENT events
  **EVENT_NEWCONSENSUS**                NEWCONSENSUS events
  **EVENT_NS**                          NS events
  **EVENT_SIGNAL**                      SIGNAL events
  **EVENT_STATUS**                      STATUS_GENERAL, STATUS_CLIENT, and STATUS_SERVER events
  **EVENT_STREAM_BW**                   STREAM_BW events
  **EVENT_TRANSPORT_LAUNCHED**          TRANSPORT_LAUNCHED events
  **EVENT_CONN_BW**                     CONN_BW events
  **EVENT_CIRC_BW**                     CIRC_BW events
  **EVENT_CELL_STATS**                  CELL_STATS events
  **EVENT_TB_EMPTY**                    TB_EMPTY events
  **EVENT_HS_DESC**                     HS_DESC events
  **EXTENDCIRCUIT_PATH_OPTIONAL**       EXTENDCIRCUIT queries can omit the path if the circuit is zero
  **FEATURE_EXTENDED_EVENTS**           'EXTENDED_EVENTS' optional feature
  **FEATURE_VERBOSE_NAMES**             'VERBOSE_NAMES' optional feature
  **GETINFO_CONFIG_TEXT**               'GETINFO config-text' query
  **HSFETCH**                           HSFETCH requests
  **HSPOST**                            HSPOST requests
  **ADD_ONION**                         ADD_ONION and DEL_ONION requests
  **LOADCONF**                          LOADCONF requests
  **MICRODESCRIPTOR_IS_DEFAULT**        Tor gets microdescriptors by default rather than server descriptors
  **TAKEOWNERSHIP**                     TAKEOWNERSHIP requests
  **TORRC_CONTROL_SOCKET**              'ControlSocket <path>' config option
  **TORRC_PORT_FORWARDING**             'PortForwarding' config option
  **TORRC_DISABLE_DEBUGGER_ATTACHMENT** 'DisableDebuggerAttachment' config option
  **TORRC_VIA_STDIN**                   Allow torrc options via 'tor -f -' (:trac:`13865`)
  ===================================== ===========
"""

import os
import re

import stem.util.enum
import stem.util.system

try:
  # added in python 3.2
  from functools import lru_cache
except ImportError:
  from stem.util.lru_cache import lru_cache

# cache for the get_system_tor_version function
VERSION_CACHE = {}


def get_system_tor_version(tor_cmd = 'tor'):
  """
  Queries tor for its version. This is os dependent, only working on linux,
  osx, and bsd.

  :param str tor_cmd: command used to run tor

  :returns: :class:`~stem.version.Version` provided by the tor command

  :raises: **IOError** if unable to query or parse the version
  """

  if tor_cmd not in VERSION_CACHE:
    version_cmd = '%s --version' % tor_cmd

    try:
      version_output = stem.util.system.call(version_cmd)
    except OSError as exc:
      # make the error message nicer if this is due to tor being unavialable

      if 'No such file or directory' in str(exc):
        if os.path.isabs(tor_cmd):
          exc = "Unable to check tor's version. '%s' doesn't exist." % tor_cmd
        else:
          exc = "Unable to run '%s'. Mabye tor isn't in your PATH?" % version_cmd

      raise IOError(exc)

    if version_output:
      # output example:
      # Oct 21 07:19:27.438 [notice] Tor v0.2.1.30. This is experimental software. Do not rely on it for strong anonymity. (Running on Linux i686)
      # Tor version 0.2.1.30.

      last_line = version_output[-1]

      if last_line.startswith('Tor version ') and last_line.endswith('.'):
        try:
          version_str = last_line[12:-1]
          VERSION_CACHE[tor_cmd] = Version(version_str)
        except ValueError as exc:
          raise IOError(exc)
      else:
        raise IOError("Unexpected response from '%s': %s" % (version_cmd, last_line))
    else:
      raise IOError("'%s' didn't have any output" % version_cmd)

  return VERSION_CACHE[tor_cmd]


@lru_cache()
def _get_version(version_str):
  return Version(version_str)


class Version(object):
  """
  Comparable tor version. These are constructed from strings that conform to
  the 'new' style in the `tor version-spec
  <https://gitweb.torproject.org/torspec.git/tree/version-spec.txt>`_,
  such as "0.1.4" or "0.2.2.23-alpha (git-7dcd105be34a4f44)".

  :var int major: major version
  :var int minor: minor version
  :var int micro: micro version
  :var int patch: patch level (**None** if undefined)
  :var str status: status tag such as 'alpha' or 'beta-dev' (**None** if undefined)
  :var str extra: extra information without its parentheses such as
    'git-8be6058d8f31e578' (**None** if undefined)
  :var str git_commit: git commit id (**None** if it wasn't provided)

  :param str version_str: version to be parsed

  :raises: **ValueError** if input isn't a valid tor version
  """

  def __init__(self, version_str):
    self.version_str = version_str
    version_parts = re.match(r'^([0-9]+)\.([0-9]+)\.([0-9]+)(\.[0-9]+)?(-\S*)?( \(\S*\))?$', version_str)
    self._hash = None

    if version_parts:
      major, minor, micro, patch, status, extra = version_parts.groups()

      # The patch and status matches are optional (may be None) and have an extra
      # proceeding period or dash if they exist. Stripping those off.

      if patch:
        patch = int(patch[1:])

      if status:
        status = status[1:]

      if extra:
        extra = extra[2:-1]

      self.major = int(major)
      self.minor = int(minor)
      self.micro = int(micro)
      self.patch = patch
      self.status = status
      self.extra = extra

      if extra and re.match('^git-[0-9a-f]{16}$', extra):
        self.git_commit = extra[4:]
      else:
        self.git_commit = None
    else:
      raise ValueError("'%s' isn't a properly formatted tor version" % version_str)

  def __str__(self):
    """
    Provides the string used to construct the version.
    """

    return self.version_str

  def _compare(self, other, method):
    """
    Compares version ordering according to the spec.
    """

    if not isinstance(other, Version):
      return False

    for attr in ('major', 'minor', 'micro', 'patch'):
      my_version = getattr(self, attr)
      other_version = getattr(other, attr)

      if my_version is None:
        my_version = 0

      if other_version is None:
        other_version = 0

      if my_version != other_version:
        return method(my_version, other_version)

    # According to the version spec...
    #
    #   If we *do* encounter two versions that differ only by status tag, we
    #   compare them lexically as ASCII byte strings.

    my_status = self.status if self.status else ''
    other_status = other.status if other.status else ''

    return method(my_status, other_status)

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __gt__(self, other):
    """
    Checks if this version meets the requirements for a given feature. We can
    be compared to either a :class:`~stem.version.Version` or
    :class:`~stem.version._VersionRequirements`.
    """

    if isinstance(other, _VersionRequirements):
      for rule in other.rules:
        if rule(self):
          return True

      return False

    return self._compare(other, lambda s, o: s > o)

  def __ge__(self, other):
    if isinstance(other, _VersionRequirements):
      for rule in other.rules:
        if rule(self):
          return True

      return False

    return self._compare(other, lambda s, o: s >= o)

  def __hash__(self):
    if self._hash is None:
      my_hash = 0

      for attr in ('major', 'minor', 'micro', 'patch', 'status'):
        my_hash *= 1024

        attr_value = getattr(self, attr)

        if attr_value is not None:
          my_hash += hash(attr_value)

      self._hash = my_hash

    return self._hash


class _VersionRequirements(object):
  """
  Series of version constraints that can be compared to. For instance, this
  allows for comparisons like 'if I'm greater than version X in the 0.2.2
  series, or greater than version Y in the 0.2.3 series'.

  This is a logical 'or' of the series of rules.
  """

  def __init__(self):
    self.rules = []

  def greater_than(self, version, inclusive = True):
    """
    Adds a constraint that we're greater than the given version.

    :param stem.version.Version version: version we're checking against
    :param bool inclusive: if comparison is inclusive or not
    """

    if inclusive:
      self.rules.append(lambda v: version <= v)
    else:
      self.rules.append(lambda v: version < v)

  def less_than(self, version, inclusive = True):
    """
    Adds a constraint that we're less than the given version.

    :param stem.version.Version version: version we're checking against
    :param bool inclusive: if comparison is inclusive or not
    """

    if inclusive:
      self.rules.append(lambda v: version >= v)
    else:
      self.rules.append(lambda v: version > v)

  def in_range(self, from_version, to_version, from_inclusive = True, to_inclusive = False):
    """
    Adds constraint that we're within the range from one version to another.

    :param stem.version.Version from_version: beginning of the comparison range
    :param stem.version.Version to_version: end of the comparison range
    :param bool from_inclusive: if comparison is inclusive with the starting version
    :param bool to_inclusive: if comparison is inclusive with the ending version
    """

    if from_inclusive and to_inclusive:
      new_rule = lambda v: from_version <= v <= to_version
    elif from_inclusive:
      new_rule = lambda v: from_version <= v < to_version
    else:
      new_rule = lambda v: from_version < v < to_version

    self.rules.append(new_rule)

safecookie_req = _VersionRequirements()
safecookie_req.in_range(Version('0.2.2.36'), Version('0.2.3.0'))
safecookie_req.greater_than(Version('0.2.3.13'))

Requirement = stem.util.enum.Enum(
  ('AUTH_SAFECOOKIE', safecookie_req),
  ('DROPGUARDS', Version('0.2.5.1-alpha')),
  ('EVENT_AUTHDIR_NEWDESCS', Version('0.1.1.10-alpha')),
  ('EVENT_BUILDTIMEOUT_SET', Version('0.2.2.7-alpha')),
  ('EVENT_CIRC_MINOR', Version('0.2.3.11-alpha')),
  ('EVENT_CLIENTS_SEEN', Version('0.2.1.10-alpha')),
  ('EVENT_CONF_CHANGED', Version('0.2.3.3-alpha')),
  ('EVENT_DESCCHANGED', Version('0.1.2.2-alpha')),
  ('EVENT_GUARD', Version('0.1.2.5-alpha')),
  ('EVENT_HS_DESC_CONTENT', Version('0.2.7.1-alpha')),
  ('EVENT_NS', Version('0.1.2.3-alpha')),
  ('EVENT_NEWCONSENSUS', Version('0.2.1.13-alpha')),
  ('EVENT_SIGNAL', Version('0.2.3.1-alpha')),
  ('EVENT_STATUS', Version('0.1.2.3-alpha')),
  ('EVENT_STREAM_BW', Version('0.1.2.8-beta')),
  ('EVENT_TRANSPORT_LAUNCHED', Version('0.2.5.0-alpha')),
  ('EVENT_CONN_BW', Version('0.2.5.2-alpha')),
  ('EVENT_CIRC_BW', Version('0.2.5.2-alpha')),
  ('EVENT_CELL_STATS', Version('0.2.5.2-alpha')),
  ('EVENT_TB_EMPTY', Version('0.2.5.2-alpha')),
  ('EVENT_HS_DESC', Version('0.2.5.2-alpha')),
  ('EXTENDCIRCUIT_PATH_OPTIONAL', Version('0.2.2.9')),
  ('FEATURE_EXTENDED_EVENTS', Version('0.2.2.1-alpha')),
  ('FEATURE_VERBOSE_NAMES', Version('0.2.2.1-alpha')),
  ('GETINFO_CONFIG_TEXT', Version('0.2.2.7-alpha')),
  ('HSFETCH', Version('0.2.7.1-alpha')),
  ('HSPOST', Version('0.2.7.1-alpha')),
  ('ADD_ONION', Version('0.2.7.1-alpha')),
  ('LOADCONF', Version('0.2.1.1')),
  ('MICRODESCRIPTOR_IS_DEFAULT', Version('0.2.3.3')),
  ('TAKEOWNERSHIP', Version('0.2.2.28-beta')),
  ('TORRC_CONTROL_SOCKET', Version('0.2.0.30')),
  ('TORRC_PORT_FORWARDING', Version('0.2.3.1-alpha')),
  ('TORRC_DISABLE_DEBUGGER_ATTACHMENT', Version('0.2.3.9')),
  ('TORRC_VIA_STDIN', Version('0.2.6.3-alpha')),
)
