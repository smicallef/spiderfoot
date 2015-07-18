# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import io
import re
import time

import stem
import stem.control
import stem.descriptor.router_status_entry
import stem.response
import stem.version

from stem import str_type, int_type
from stem.util import connection, log, str_tools, tor_tools

# Matches keyword=value arguments. This can't be a simple "(.*)=(.*)" pattern
# because some positional arguments, like circuit paths, can have an equal
# sign.

KW_ARG = re.compile('^(.*) ([A-Za-z0-9_]+)=(\S*)$')
QUOTED_KW_ARG = re.compile('^(.*) ([A-Za-z0-9_]+)="(.*)"$')
CELL_TYPE = re.compile('^[a-z0-9_]+$')


class Event(stem.response.ControlMessage):
  """
  Base for events we receive asynchronously, as described in section 4.1 of the
  `control-spec
  <https://gitweb.torproject.org/torspec.git/tree/control-spec.txt>`_.

  :var str type: event type
  :var int arrived_at: unix timestamp for when the message arrived
  :var list positional_args: positional arguments of the event
  :var dict keyword_args: key/value arguments of the event
  """

  _POSITIONAL_ARGS = ()    # attribute names for recognized positional arguments
  _KEYWORD_ARGS = {}       # map of 'keyword => attribute' for recognized attributes
  _QUOTED = ()             # positional arguments that are quoted
  _OPTIONALLY_QUOTED = ()  # positional arguments that may or may not be quoted
  _SKIP_PARSING = False    # skip parsing contents into our positional_args and keyword_args
  _VERSION_ADDED = stem.version.Version('0.1.1.1-alpha')  # minimum version with control-spec V1 event support

  def _parse_message(self, arrived_at = None):
    if arrived_at is None:
      arrived_at = int(time.time())

    if not str(self).strip():
      raise stem.ProtocolError('Received a blank tor event. Events must at the very least have a type.')

    self.type = str(self).split()[0]
    self.arrived_at = arrived_at

    # if we're a recognized event type then translate ourselves into that subclass

    if self.type in EVENT_TYPE_TO_CLASS:
      self.__class__ = EVENT_TYPE_TO_CLASS[self.type]

    self.positional_args = []
    self.keyword_args = {}

    if not self._SKIP_PARSING:
      self._parse_standard_attr()

    self._parse()

  def _parse_standard_attr(self):
    """
    Most events are of the form...
    650 *( positional_args ) *( key "=" value )

    This parses this standard format, populating our **positional_args** and
    **keyword_args** attributes and creating attributes if it's in our event's
    **_POSITIONAL_ARGS** and **_KEYWORD_ARGS**.
    """

    # Tor events contain some number of positional arguments followed by
    # key/value mappings. Parsing keyword arguments from the end until we hit
    # something that isn't a key/value mapping. The rest are positional.

    content = str(self)

    while True:
      match = QUOTED_KW_ARG.match(content)

      if not match:
        match = KW_ARG.match(content)

      if match:
        content, keyword, value = match.groups()
        self.keyword_args[keyword] = value
      else:
        break

    # Setting attributes for the fields that we recognize.

    self.positional_args = content.split()[1:]
    positional = list(self.positional_args)

    for attr_name in self._POSITIONAL_ARGS:
      attr_value = None

      if positional:
        if attr_name in self._QUOTED or (attr_name in self._OPTIONALLY_QUOTED and positional[0].startswith('"')):
          attr_values = [positional.pop(0)]

          if not attr_values[0].startswith('"'):
            raise stem.ProtocolError("The %s value should be quoted, but didn't have a starting quote: %s" % (attr_name, self))

          while True:
            if not positional:
              raise stem.ProtocolError("The %s value should be quoted, but didn't have an ending quote: %s" % (attr_name, self))

            attr_values.append(positional.pop(0))

            if attr_values[-1].endswith('"'):
              break

          attr_value = ' '.join(attr_values)[1:-1]
        else:
          attr_value = positional.pop(0)

      setattr(self, attr_name, attr_value)

    for controller_attr_name, attr_name in self._KEYWORD_ARGS.items():
      setattr(self, attr_name, self.keyword_args.get(controller_attr_name))

  # method overwritten by our subclasses for special handling that they do
  def _parse(self):
    pass

  def _log_if_unrecognized(self, attr, attr_enum):
    """
    Checks if an attribute exists in a given enumeration, logging a message if
    it isn't. Attributes can either be for a string or collection of strings

    :param str attr: name of the attribute to check
    :param stem.util.enum.Enum enum: enumeration to check against
    """

    attr_values = getattr(self, attr)

    if attr_values:
      if isinstance(attr_values, (bytes, str_type)):
        attr_values = [attr_values]

      for value in attr_values:
        if value not in attr_enum:
          log_id = 'event.%s.unknown_%s.%s' % (self.type.lower(), attr, value)
          unrecognized_msg = "%s event had an unrecognized %s (%s). Maybe a new addition to the control protocol? Full Event: '%s'" % (self.type, attr, value, self)
          log.log_once(log_id, log.INFO, unrecognized_msg)


class AddrMapEvent(Event):
  """
  Event that indicates a new address mapping.

  The ADDRMAP event was one of the first Control Protocol V1 events and was
  introduced in tor version 0.1.1.1-alpha.

  .. versionchanged:: 1.1.0
     Added the cached attribute.

  :var str hostname: address being resolved
  :var str destination: destionation of the resolution, this is usually an ip,
    but could be a hostname if TrackHostExits is enabled or **NONE** if the
    resolution failed
  :var datetime expiry: expiration time of the resolution in local time
  :var str error: error code if the resolution failed
  :var datetime utc_expiry: expiration time of the resolution in UTC
  :var bool cached: **True** if the resolution will be kept until it expires,
    **False** otherwise or **None** if undefined
  """

  _POSITIONAL_ARGS = ('hostname', 'destination', 'expiry')
  _KEYWORD_ARGS = {
    'error': 'error',
    'EXPIRES': 'utc_expiry',
    'CACHED': 'cached',
  }
  _OPTIONALLY_QUOTED = ('expiry')

  def _parse(self):
    if self.destination == '<error>':
      self.destination = None

    if self.expiry is not None:
      if self.expiry == 'NEVER':
        self.expiry = None
      else:
        try:
          self.expiry = stem.util.str_tools._parse_timestamp(self.expiry)
        except ValueError:
          raise stem.ProtocolError('Unable to parse date in ADDRMAP event: %s' % self)

    if self.utc_expiry is not None:
      self.utc_expiry = stem.util.str_tools._parse_timestamp(self.utc_expiry)

    if self.cached is not None:
      if self.cached == 'YES':
        self.cached = True
      elif self.cached == 'NO':
        self.cached = False
      else:
        raise stem.ProtocolError("An ADDRMAP event's CACHED mapping can only be 'YES' or 'NO': %s" % self)


class AuthDirNewDescEvent(Event):
  """
  Event specific to directory authorities, indicating that we just received new
  descriptors. The descriptor type contained within this event is unspecified
  so the descriptor contents are left unparsed.

  The AUTHDIR_NEWDESCS event was introduced in tor version 0.1.1.10-alpha.

  :var stem.AuthDescriptorAction action: what is being done with the descriptor
  :var str message: explanation of why we chose this action
  :var str descriptor: content of the descriptor
  """

  _SKIP_PARSING = True
  _VERSION_ADDED = stem.version.Requirement.EVENT_AUTHDIR_NEWDESCS

  def _parse(self):
    lines = str(self).split('\n')

    if len(lines) < 5:
      raise stem.ProtocolError("AUTHDIR_NEWDESCS events must contain lines for at least the type, action, message, descriptor, and terminating 'OK'")
    elif lines[-1] != 'OK':
      raise stem.ProtocolError("AUTHDIR_NEWDESCS doesn't end with an 'OK'")

    # TODO: For stem 2.0.0 we should consider changing 'descriptor' to a
    # ServerDescriptor instance.

    self.action = lines[1]
    self.message = lines[2]
    self.descriptor = '\n'.join(lines[3:-1])


class BandwidthEvent(Event):
  """
  Event emitted every second with the bytes sent and received by tor.

  The BW event was one of the first Control Protocol V1 events and was
  introduced in tor version 0.1.1.1-alpha.

  :var long read: bytes received by tor that second
  :var long written: bytes sent by tor that second
  """

  _POSITIONAL_ARGS = ('read', 'written')

  def _parse(self):
    if not self.read:
      raise stem.ProtocolError('BW event is missing its read value')
    elif not self.written:
      raise stem.ProtocolError('BW event is missing its written value')
    elif not self.read.isdigit() or not self.written.isdigit():
      raise stem.ProtocolError("A BW event's bytes sent and received should be a positive numeric value, received: %s" % self)

    self.read = int_type(self.read)
    self.written = int_type(self.written)


class BuildTimeoutSetEvent(Event):
  """
  Event indicating that the timeout value for a circuit has changed. This was
  first added in tor version 0.2.2.7.

  The BUILDTIMEOUT_SET event was introduced in tor version 0.2.2.7-alpha.

  :var stem.TimeoutSetType set_type: way in which the timeout is changing
  :var int total_times: circuit build times tor used to determine the timeout
  :var int timeout: circuit timeout value in milliseconds
  :var int xm: Pareto parameter Xm in milliseconds
  :var float alpha: Pareto parameter alpha
  :var float quantile: CDF quantile cutoff point
  :var float timeout_rate: ratio of circuits that have time out
  :var int close_timeout: duration to keep measurement circuits in milliseconds
  :var float close_rate: ratio of measurement circuits that are closed
  """

  _POSITIONAL_ARGS = ('set_type',)
  _KEYWORD_ARGS = {
    'TOTAL_TIMES': 'total_times',
    'TIMEOUT_MS': 'timeout',
    'XM': 'xm',
    'ALPHA': 'alpha',
    'CUTOFF_QUANTILE': 'quantile',
    'TIMEOUT_RATE': 'timeout_rate',
    'CLOSE_MS': 'close_timeout',
    'CLOSE_RATE': 'close_rate',
  }
  _VERSION_ADDED = stem.version.Requirement.EVENT_BUILDTIMEOUT_SET

  def _parse(self):
    # convert our integer and float parameters

    for param in ('total_times', 'timeout', 'xm', 'close_timeout'):
      param_value = getattr(self, param)

      if param_value is not None:
        try:
          setattr(self, param, int(param_value))
        except ValueError:
          raise stem.ProtocolError('The %s of a BUILDTIMEOUT_SET should be an integer: %s' % (param, self))

    for param in ('alpha', 'quantile', 'timeout_rate', 'close_rate'):
      param_value = getattr(self, param)

      if param_value is not None:
        try:
          setattr(self, param, float(param_value))
        except ValueError:
          raise stem.ProtocolError('The %s of a BUILDTIMEOUT_SET should be a float: %s' % (param, self))

    self._log_if_unrecognized('set_type', stem.TimeoutSetType)


class CircuitEvent(Event):
  """
  Event that indicates that a circuit has changed.

  The fingerprint or nickname values in our 'path' may be **None** if the
  VERBOSE_NAMES feature isn't enabled. The option was first introduced in tor
  version 0.1.2.2, and on by default after 0.2.2.1.

  The CIRC event was one of the first Control Protocol V1 events and was
  introduced in tor version 0.1.1.1-alpha.

  .. versionchanged:: 1.4.0
     Added the socks_username and socks_password attributes which is used for
     `stream isolation
     <https://gitweb.torproject.org/torspec.git/tree/proposals/171-separate-streams.txt>`_.

  :var str id: circuit identifier
  :var stem.CircStatus status: reported status for the circuit
  :var tuple path: relays involved in the circuit, these are
    **(fingerprint, nickname)** tuples
  :var tuple build_flags: :data:`~stem.CircBuildFlag` attributes
    governing how the circuit is built
  :var stem.CircPurpose purpose: purpose that the circuit is intended for
  :var stem.HiddenServiceState hs_state: status if this is a hidden service circuit
  :var str rend_query: circuit's rendezvous-point if this is hidden service related
  :var datetime created: time when the circuit was created or cannibalized
  :var stem.CircClosureReason reason: reason for the circuit to be closed
  :var stem.CircClosureReason remote_reason: remote side's reason for the circuit to be closed
  :var str socks_username: username for using this circuit
  :var str socks_password: password for using this circuit
  """

  _POSITIONAL_ARGS = ('id', 'status', 'path')
  _KEYWORD_ARGS = {
    'BUILD_FLAGS': 'build_flags',
    'PURPOSE': 'purpose',
    'HS_STATE': 'hs_state',
    'REND_QUERY': 'rend_query',
    'TIME_CREATED': 'created',
    'REASON': 'reason',
    'REMOTE_REASON': 'remote_reason',
    'SOCKS_USERNAME': 'socks_username',
    'SOCKS_PASSWORD': 'socks_password',
  }

  def _parse(self):
    self.path = tuple(stem.control._parse_circ_path(self.path))

    if self.build_flags is not None:
      self.build_flags = tuple(self.build_flags.split(','))

    if self.created is not None:
      try:
        self.created = str_tools._parse_iso_timestamp(self.created)
      except ValueError as exc:
        raise stem.ProtocolError('Unable to parse create date (%s): %s' % (exc, self))

    if not tor_tools.is_valid_circuit_id(self.id):
      raise stem.ProtocolError("Circuit IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.id, self))

    self._log_if_unrecognized('status', stem.CircStatus)
    self._log_if_unrecognized('build_flags', stem.CircBuildFlag)
    self._log_if_unrecognized('purpose', stem.CircPurpose)
    self._log_if_unrecognized('hs_state', stem.HiddenServiceState)
    self._log_if_unrecognized('reason', stem.CircClosureReason)
    self._log_if_unrecognized('remote_reason', stem.CircClosureReason)

  def _compare(self, other, method):
    if not isinstance(other, CircuitEvent):
      return False

    for attr in ('id', 'status', 'path', 'build_flags', 'purpose', 'hs_state', 'rend_query', 'created', 'reason', 'remote_reason', 'socks_username', 'socks_port'):
      my_attr = getattr(self, attr)
      other_attr = getattr(other, attr)

      # Our id attribute is technically a string, but Tor conventionally uses
      # ints. Attempt to handle as ints if that's the case so we get numeric
      # ordering.

      if attr == 'id' and my_attr and other_attr:
        if my_attr.isdigit() and other_attr.isdigit():
          my_attr = int(my_attr)
          other_attr = int(other_attr)

      if my_attr is None:
        my_attr = ''

      if other_attr is None:
        other_attr = ''

      if my_attr != other_attr:
        return method(my_attr, other_attr)

    return True

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __gt__(self, other):
    return self._compare(other, lambda s, o: s > o)

  def __ge__(self, other):
    return self._compare(other, lambda s, o: s >= o)


class CircMinorEvent(Event):
  """
  Event providing information about minor changes in our circuits. This was
  first added in tor version 0.2.3.11.

  The CIRC_MINOR event was introduced in tor version 0.2.3.11-alpha.

  :var str id: circuit identifier
  :var stem.CircEvent event: type of change in the circuit
  :var tuple path: relays involved in the circuit, these are
    **(fingerprint, nickname)** tuples
  :var tuple build_flags: :data:`~stem.CircBuildFlag` attributes
    governing how the circuit is built
  :var stem.CircPurpose purpose: purpose that the circuit is intended for
  :var stem.HiddenServiceState hs_state: status if this is a hidden service circuit
  :var str rend_query: circuit's rendezvous-point if this is hidden service related
  :var datetime created: time when the circuit was created or cannibalized
  :var stem.CircPurpose old_purpose: prior purpose for the circuit
  :var stem.HiddenServiceState old_hs_state: prior status as a hidden service circuit
  """

  _POSITIONAL_ARGS = ('id', 'event', 'path')
  _KEYWORD_ARGS = {
    'BUILD_FLAGS': 'build_flags',
    'PURPOSE': 'purpose',
    'HS_STATE': 'hs_state',
    'REND_QUERY': 'rend_query',
    'TIME_CREATED': 'created',
    'OLD_PURPOSE': 'old_purpose',
    'OLD_HS_STATE': 'old_hs_state',
  }
  _VERSION_ADDED = stem.version.Requirement.EVENT_CIRC_MINOR

  def _parse(self):
    self.path = tuple(stem.control._parse_circ_path(self.path))

    if self.build_flags is not None:
      self.build_flags = tuple(self.build_flags.split(','))

    if self.created is not None:
      try:
        self.created = str_tools._parse_iso_timestamp(self.created)
      except ValueError as exc:
        raise stem.ProtocolError('Unable to parse create date (%s): %s' % (exc, self))

    if not tor_tools.is_valid_circuit_id(self.id):
      raise stem.ProtocolError("Circuit IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.id, self))

    self._log_if_unrecognized('event', stem.CircEvent)
    self._log_if_unrecognized('build_flags', stem.CircBuildFlag)
    self._log_if_unrecognized('purpose', stem.CircPurpose)
    self._log_if_unrecognized('hs_state', stem.HiddenServiceState)
    self._log_if_unrecognized('old_purpose', stem.CircPurpose)
    self._log_if_unrecognized('old_hs_state', stem.HiddenServiceState)


class ClientsSeenEvent(Event):
  """
  Periodic event on bridge relays that provides a summary of our users.

  The CLIENTS_SEEN event was introduced in tor version 0.2.1.10-alpha.

  :var datetime start_time: time in UTC that we started collecting these stats
  :var dict locales: mapping of country codes to a rounded count for the number of users
  :var dict ip_versions: mapping of ip protocols to a rounded count for the number of users
  """

  _KEYWORD_ARGS = {
    'TimeStarted': 'start_time',
    'CountrySummary': 'locales',
    'IPVersions': 'ip_versions',
  }
  _VERSION_ADDED = stem.version.Requirement.EVENT_CLIENTS_SEEN

  def _parse(self):
    if self.start_time is not None:
      self.start_time = stem.util.str_tools._parse_timestamp(self.start_time)

    if self.locales is not None:
      locale_to_count = {}

      for entry in self.locales.split(','):
        if '=' not in entry:
          raise stem.ProtocolError("The CLIENTS_SEEN's CountrySummary should be a comma separated listing of '<locale>=<count>' mappings: %s" % self)

        locale, count = entry.split('=', 1)

        if len(locale) != 2:
          raise stem.ProtocolError("Locales should be a two character code, got '%s': %s" % (locale, self))
        elif not count.isdigit():
          raise stem.ProtocolError('Locale count was non-numeric (%s): %s' % (count, self))
        elif locale in locale_to_count:
          raise stem.ProtocolError("CountrySummary had multiple mappings for '%s': %s" % (locale, self))

        locale_to_count[locale] = int(count)

      self.locales = locale_to_count

    if self.ip_versions is not None:
      protocol_to_count = {}

      for entry in self.ip_versions.split(','):
        if '=' not in entry:
          raise stem.ProtocolError("The CLIENTS_SEEN's IPVersions should be a comma separated listing of '<protocol>=<count>' mappings: %s" % self)

        protocol, count = entry.split('=', 1)

        if not count.isdigit():
          raise stem.ProtocolError('IP protocol count was non-numeric (%s): %s' % (count, self))

        protocol_to_count[protocol] = int(count)

      self.ip_versions = protocol_to_count


class ConfChangedEvent(Event):
  """
  Event that indicates that our configuration changed, either in response to a
  SETCONF or RELOAD signal.

  The CONF_CHANGED event was introduced in tor version 0.2.3.3-alpha.

  :var dict config: mapping of configuration options to their new values
    (**None** if the option is being unset)
  """

  _SKIP_PARSING = True
  _VERSION_ADDED = stem.version.Requirement.EVENT_CONF_CHANGED

  def _parse(self):
    self.config = {}

    # Skip first and last line since they're the header and footer. For
    # instance...
    #
    # 650-CONF_CHANGED
    # 650-ExitNodes=caerSidi
    # 650-ExitPolicy
    # 650-MaxCircuitDirtiness=20
    # 650 OK

    for line in str(self).splitlines()[1:-1]:
      if '=' in line:
        key, value = line.split('=', 1)
      else:
        key, value = line, None

      self.config[key] = value


class DescChangedEvent(Event):
  """
  Event that indicates that our descriptor has changed.

  The DESCCHANGED event was introduced in tor version 0.1.2.2-alpha.
  """

  _VERSION_ADDED = stem.version.Requirement.EVENT_DESCCHANGED


class GuardEvent(Event):
  """
  Event that indicates that our guard relays have changed. The 'endpoint' could
  be either a...

  * fingerprint
  * 'fingerprint=nickname' pair

  The derived 'endpoint_*' attributes are generally more useful.

  The GUARD event was introduced in tor version 0.1.2.5-alpha.

  :var stem.GuardType guard_type: purpose the guard relay is for
  :var str endpoint: relay that the event concerns
  :var str endpoint_fingerprint: endpoint's finterprint
  :var str endpoint_nickname: endpoint's nickname if it was provided
  :var stem.GuardStatus status: status of the guard relay
  """

  _VERSION_ADDED = stem.version.Requirement.EVENT_GUARD
  _POSITIONAL_ARGS = ('guard_type', 'endpoint', 'status')

  def _parse(self):
    self.endpoint_fingerprint = None
    self.endpoint_nickname = None

    try:
      self.endpoint_fingerprint, self.endpoint_nickname = \
        stem.control._parse_circ_entry(self.endpoint)
    except stem.ProtocolError:
      raise stem.ProtocolError("GUARD's endpoint doesn't match a ServerSpec: %s" % self)

    self._log_if_unrecognized('guard_type', stem.GuardType)
    self._log_if_unrecognized('status', stem.GuardStatus)


class HSDescEvent(Event):
  """
  Event triggered when we fetch a hidden service descriptor that currently isn't in our cache.

  The HS_DESC event was introduced in tor version 0.2.5.2-alpha.

  .. versionadded:: 1.2.0

  .. versionchanged:: 1.3.0
     Added the reason attribute.

  :var stem.HSDescAction action: what is happening with the descriptor
  :var str address: hidden service address
  :var stem.HSAuth authentication: service's authentication method
  :var str directory: hidden service directory servicing the request
  :var str directory_fingerprint: hidden service directory's finterprint
  :var str directory_nickname: hidden service directory's nickname if it was provided
  :var str descriptor_id: descriptor identifier
  :var stem.HSDescReason reason: reason the descriptor failed to be fetched
  """

  _VERSION_ADDED = stem.version.Requirement.EVENT_HS_DESC
  _POSITIONAL_ARGS = ('action', 'address', 'authentication', 'directory', 'descriptor_id')
  _KEYWORD_ARGS = {'REASON': 'reason'}

  def _parse(self):
    self.directory_fingerprint = None
    self.directory_nickname = None

    try:
      self.directory_fingerprint, self.directory_nickname = \
        stem.control._parse_circ_entry(self.directory)
    except stem.ProtocolError:
      raise stem.ProtocolError("HS_DESC's directory doesn't match a ServerSpec: %s" % self)

    self._log_if_unrecognized('action', stem.HSDescAction)
    self._log_if_unrecognized('authentication', stem.HSAuth)


class HSDescContentEvent(Event):
  """
  Provides the content of hidden service descriptors we fetch.

  The HS_DESC_CONTENT event was introduced in tor version 0.2.7.1-alpha.

  .. versionadded:: 1.4.0

  :var str address: hidden service address
  :var str descriptor_id: descriptor identifier
  :var str directory: hidden service directory servicing the request
  :var str directory_fingerprint: hidden service directory's finterprint
  :var str directory_nickname: hidden service directory's nickname if it was provided
  :var stem.descriptor.hidden_service_descriptor.HiddenServiceDescriptor descriptor: descriptor that was retrieved
  """

  _VERSION_ADDED = stem.version.Requirement.EVENT_HS_DESC_CONTENT
  _POSITIONAL_ARGS = ('address', 'descriptor_id', 'directory')

  def _parse(self):
    if self.address == 'UNKNOWN':
      self.address = None

    self.directory_fingerprint = None
    self.directory_nickname = None

    try:
      self.directory_fingerprint, self.directory_nickname = \
        stem.control._parse_circ_entry(self.directory)
    except stem.ProtocolError:
      raise stem.ProtocolError("HS_DESC_CONTENT's directory doesn't match a ServerSpec: %s" % self)

    # skip the first line (our positional arguments) and last ('OK')

    desc_content = str_tools._to_bytes('\n'.join(str(self).splitlines()[1:-1]))
    self.descriptor = None

    if desc_content:
      self.descriptor = list(stem.descriptor.hidden_service_descriptor._parse_file(io.BytesIO(desc_content)))[0]


class LogEvent(Event):
  """
  Tor logging event. These are the most visible kind of event since, by
  default, tor logs at the NOTICE :data:`~stem.Runlevel` to stdout.

  The logging events were some of the first Control Protocol V1 events
  and were introduced in tor version 0.1.1.1-alpha.

  :var stem.Runlevel runlevel: runlevel of the logged message
  :var str message: logged message
  """

  _SKIP_PARSING = True

  def _parse(self):
    self.runlevel = self.type
    self._log_if_unrecognized('runlevel', stem.Runlevel)

    # message is our content, minus the runlevel and ending "OK" if a
    # multi-line message

    self.message = str(self)[len(self.runlevel) + 1:].rstrip('\nOK')


class NetworkStatusEvent(Event):
  """
  Event for when our copy of the consensus has changed. This was introduced in
  tor version 0.1.2.3.

  The NS event was introduced in tor version 0.1.2.3-alpha.

  :var list desc: :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3` for the changed descriptors
  """

  _SKIP_PARSING = True
  _VERSION_ADDED = stem.version.Requirement.EVENT_NS

  def _parse(self):
    content = str(self).lstrip('NS\n').rstrip('\nOK')

    # TODO: For stem 2.0.0 consider changing 'desc' to 'descriptors' to match
    # our other events.

    self.desc = list(stem.descriptor.router_status_entry._parse_file(
      io.BytesIO(str_tools._to_bytes(content)),
      True,
      entry_class = stem.descriptor.router_status_entry.RouterStatusEntryV3,
    ))


class NewConsensusEvent(Event):
  """
  Event for when we have a new consensus. This is similar to
  :class:`~stem.response.events.NetworkStatusEvent`, except that it contains
  the whole consensus so anything not listed is implicitly no longer
  recommended.

  The NEWCONSENSUS event was introduced in tor version 0.2.1.13-alpha.

  :var list desc: :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3` for the changed descriptors
  """

  _SKIP_PARSING = True
  _VERSION_ADDED = stem.version.Requirement.EVENT_NEWCONSENSUS

  def _parse(self):
    content = str(self).lstrip('NEWCONSENSUS\n').rstrip('\nOK')

    # TODO: For stem 2.0.0 consider changing 'desc' to 'descriptors' to match
    # our other events.

    self.desc = list(stem.descriptor.router_status_entry._parse_file(
      io.BytesIO(str_tools._to_bytes(content)),
      True,
      entry_class = stem.descriptor.router_status_entry.RouterStatusEntryV3,
    ))


class NewDescEvent(Event):
  """
  Event that indicates that a new descriptor is available.

  The fingerprint or nickname values in our 'relays' may be **None** if the
  VERBOSE_NAMES feature isn't enabled. The option was first introduced in tor
  version 0.1.2.2, and on by default after 0.2.2.1.

  The NEWDESC event was one of the first Control Protocol V1 events and was
  introduced in tor version 0.1.1.1-alpha.

  :var tuple relays: **(fingerprint, nickname)** tuples for the relays with
    new descriptors
  """

  def _parse(self):
    self.relays = tuple([stem.control._parse_circ_entry(entry) for entry in str(self).split()[1:]])


class ORConnEvent(Event):
  """
  Event that indicates a change in a relay connection. The 'endpoint' could be
  any of several things including a...

  * fingerprint
  * nickname
  * 'fingerprint=nickname' pair
  * address:port

  The derived 'endpoint_*' attributes are generally more useful.

  The ORCONN event was one of the first Control Protocol V1 events and was
  introduced in tor version 0.1.1.1-alpha. Its id attribute was added in
  version 0.2.5.2-alpha.

  .. versionchanged:: 1.2.0
     Added the id attribute.

  :var str id: connection identifier
  :var str endpoint: relay that the event concerns
  :var str endpoint_fingerprint: endpoint's finterprint if it was provided
  :var str endpoint_nickname: endpoint's nickname if it was provided
  :var str endpoint_address: endpoint's address if it was provided
  :var int endpoint_port: endpoint's port if it was provided
  :var stem.ORStatus status: state of the connection
  :var stem.ORClosureReason reason: reason for the connection to be closed
  :var int circ_count: number of established and pending circuits
  """

  _POSITIONAL_ARGS = ('endpoint', 'status')
  _KEYWORD_ARGS = {
    'REASON': 'reason',
    'NCIRCS': 'circ_count',
    'ID': 'id',
  }

  def _parse(self):
    self.endpoint_fingerprint = None
    self.endpoint_nickname = None
    self.endpoint_address = None
    self.endpoint_port = None

    try:
      self.endpoint_fingerprint, self.endpoint_nickname = \
        stem.control._parse_circ_entry(self.endpoint)
    except stem.ProtocolError:
      if ':' not in self.endpoint:
        raise stem.ProtocolError("ORCONN endpoint is neither a relay nor 'address:port': %s" % self)

      address, port = self.endpoint.split(':', 1)

      if not connection.is_valid_port(port):
        raise stem.ProtocolError("ORCONN's endpoint location's port is invalid: %s" % self)

      self.endpoint_address = address
      self.endpoint_port = int(port)

    if self.circ_count is not None:
      if not self.circ_count.isdigit():
        raise stem.ProtocolError('ORCONN event got a non-numeric circuit count (%s): %s' % (self.circ_count, self))

      self.circ_count = int(self.circ_count)

    if self.id and not tor_tools.is_valid_connection_id(self.id):
      raise stem.ProtocolError("Connection IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.id, self))

    self._log_if_unrecognized('status', stem.ORStatus)
    self._log_if_unrecognized('reason', stem.ORClosureReason)


class SignalEvent(Event):
  """
  Event that indicates that tor has received and acted upon a signal being sent
  to the process. As of tor version 0.2.4.6 the only signals conveyed by this
  event are...

  * RELOAD
  * DUMP
  * DEBUG
  * NEWNYM
  * CLEARDNSCACHE

  The SIGNAL event was introduced in tor version 0.2.3.1-alpha.

  :var stem.Signal signal: signal that tor received
  """

  _POSITIONAL_ARGS = ('signal',)
  _VERSION_ADDED = stem.version.Requirement.EVENT_SIGNAL

  def _parse(self):
    # log if we recieved an unrecognized signal
    expected_signals = (
      stem.Signal.RELOAD,
      stem.Signal.DUMP,
      stem.Signal.DEBUG,
      stem.Signal.NEWNYM,
      stem.Signal.CLEARDNSCACHE,
    )

    self._log_if_unrecognized('signal', expected_signals)


class StatusEvent(Event):
  """
  Notification of a change in tor's state. These are generally triggered for
  the same sort of things as log messages of the NOTICE level or higher.
  However, unlike :class:`~stem.response.events.LogEvent` these contain well
  formed data.

  The STATUS_GENERAL, STATUS_CLIENT, STATUS_SERVER events were introduced
  in tor version 0.1.2.3-alpha.

  :var stem.StatusType status_type: category of the status event
  :var stem.Runlevel runlevel: runlevel of the logged message
  :var str action: activity that caused this message
  :var dict arguments: attributes about the event
  """

  _POSITIONAL_ARGS = ('runlevel', 'action')
  _VERSION_ADDED = stem.version.Requirement.EVENT_STATUS

  def _parse(self):
    if self.type == 'STATUS_GENERAL':
      self.status_type = stem.StatusType.GENERAL
    elif self.type == 'STATUS_CLIENT':
      self.status_type = stem.StatusType.CLIENT
    elif self.type == 'STATUS_SERVER':
      self.status_type = stem.StatusType.SERVER
    else:
      raise ValueError("BUG: Unrecognized status type (%s), likely an EVENT_TYPE_TO_CLASS addition without revising how 'status_type' is assigned." % self.type)

    # Just an alias for our parent class' keyword_args since that already
    # parses these for us. Unlike our other event types Tor commonly supplies
    # arbitrary key/value pairs for these, so making an alias here to better
    # draw attention that the StatusEvent will likely have them.

    self.arguments = self.keyword_args

    self._log_if_unrecognized('runlevel', stem.Runlevel)


class StreamEvent(Event):
  """
  Event that indicates that a stream has changed.

  The STREAM event was one of the first Control Protocol V1 events and was
  introduced in tor version 0.1.1.1-alpha.

  :var str id: stream identifier
  :var stem.StreamStatus status: reported status for the stream
  :var str circ_id: circuit that the stream is attached to, this is **None** of
    the stream is unattached
  :var str target: destination of the stream
  :var str target_address: destination address (ip, hostname, or '(Tor_internal)')
  :var int target_port: destination port
  :var stem.StreamClosureReason reason: reason for the stream to be closed
  :var stem.StreamClosureReason remote_reason: remote side's reason for the stream to be closed
  :var stem.StreamSource source: origin of the REMAP request
  :var str source_addr: requester of the connection
  :var str source_address: requester address (ip or hostname)
  :var int source_port: requester port
  :var stem.StreamPurpose purpose: purpose for the stream
  """

  _POSITIONAL_ARGS = ('id', 'status', 'circ_id', 'target')
  _KEYWORD_ARGS = {
    'REASON': 'reason',
    'REMOTE_REASON': 'remote_reason',
    'SOURCE': 'source',
    'SOURCE_ADDR': 'source_addr',
    'PURPOSE': 'purpose',
  }

  def _parse(self):
    if self.target is None:
      raise stem.ProtocolError("STREAM event didn't have a target: %s" % self)
    else:
      if ':' not in self.target:
        raise stem.ProtocolError("Target location must be of the form 'address:port': %s" % self)

      address, port = self.target.rsplit(':', 1)

      if not connection.is_valid_port(port, allow_zero = True):
        raise stem.ProtocolError("Target location's port is invalid: %s" % self)

      self.target_address = address
      self.target_port = int(port)

    if self.source_addr is None:
      self.source_address = None
      self.source_port = None
    else:
      if ':' not in self.source_addr:
        raise stem.ProtocolError("Source location must be of the form 'address:port': %s" % self)

      address, port = self.source_addr.split(':', 1)

      if not connection.is_valid_port(port, allow_zero = True):
        raise stem.ProtocolError("Source location's port is invalid: %s" % self)

      self.source_address = address
      self.source_port = int(port)

    # spec specifies a circ_id of zero if the stream is unattached

    if self.circ_id == '0':
      self.circ_id = None

    self._log_if_unrecognized('reason', stem.StreamClosureReason)
    self._log_if_unrecognized('remote_reason', stem.StreamClosureReason)
    self._log_if_unrecognized('purpose', stem.StreamPurpose)


class StreamBwEvent(Event):
  """
  Event (emitted approximately every second) with the bytes sent and received
  by the application since the last such event on this stream.

  The STREAM_BW event was introduced in tor version 0.1.2.8-beta.

  :var str id: stream identifier
  :var long written: bytes sent by the application
  :var long read: bytes received by the application
  """

  _POSITIONAL_ARGS = ('id', 'written', 'read')
  _VERSION_ADDED = stem.version.Requirement.EVENT_STREAM_BW

  def _parse(self):
    if not tor_tools.is_valid_stream_id(self.id):
      raise stem.ProtocolError("Stream IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.id, self))
    elif not self.written:
      raise stem.ProtocolError('STREAM_BW event is missing its written value')
    elif not self.read:
      raise stem.ProtocolError('STREAM_BW event is missing its read value')
    elif not self.read.isdigit() or not self.written.isdigit():
      raise stem.ProtocolError("A STREAM_BW event's bytes sent and received should be a positive numeric value, received: %s" % self)

    self.read = int_type(self.read)
    self.written = int_type(self.written)


class TransportLaunchedEvent(Event):
  """
  Event triggered when a pluggable transport is launched.

  The TRANSPORT_LAUNCHED event was introduced in tor version 0.2.5.0-alpha.

  .. versionadded:: 1.1.0

  :var str type: 'server' or 'client'
  :var str name: name of the pluggable transport
  :var str address: IPv4 or IPv6 address where the transport is listening for
    connections
  :var int port: port where the transport is listening for connections
  """

  _POSITIONAL_ARGS = ('type', 'name', 'address', 'port')
  _VERSION_ADDED = stem.version.Requirement.EVENT_TRANSPORT_LAUNCHED

  def _parse(self):
    if self.type not in ('server', 'client'):
      raise stem.ProtocolError("Transport type should either be 'server' or 'client': %s" % self)

    if not connection.is_valid_ipv4_address(self.address) and \
       not connection.is_valid_ipv6_address(self.address):
      raise stem.ProtocolError("Transport address isn't a valid IPv4 or IPv6 address: %s" % self)

    if not connection.is_valid_port(self.port):
      raise stem.ProtocolError('Transport port is invalid: %s' % self)

    self.port = int(self.port)


class ConnectionBandwidthEvent(Event):
  """
  Event emitted every second with the bytes sent and received by tor on a
  per-connection basis.

  The CONN_BW event was introduced in tor version 0.2.5.2-alpha.

  .. versionadded:: 1.2.0

  :var str id: connection identifier
  :var stem.ConnectionType type: connection type
  :var long read: bytes received by tor that second
  :var long written: bytes sent by tor that second
  """

  _KEYWORD_ARGS = {
    'ID': 'id',
    'TYPE': 'type',
    'READ': 'read',
    'WRITTEN': 'written',
  }

  _VERSION_ADDED = stem.version.Requirement.EVENT_CONN_BW

  def _parse(self):
    if not self.id:
      raise stem.ProtocolError('CONN_BW event is missing its id')
    elif not self.type:
      raise stem.ProtocolError('CONN_BW event is missing its type')
    elif not self.read:
      raise stem.ProtocolError('CONN_BW event is missing its read value')
    elif not self.written:
      raise stem.ProtocolError('CONN_BW event is missing its written value')
    elif not self.read.isdigit() or not self.written.isdigit():
      raise stem.ProtocolError("A CONN_BW event's bytes sent and received should be a positive numeric value, received: %s" % self)
    elif not tor_tools.is_valid_connection_id(self.id):
      raise stem.ProtocolError("Connection IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.id, self))

    self.read = int_type(self.read)
    self.written = int_type(self.written)

    self._log_if_unrecognized('type', stem.ConnectionType)


class CircuitBandwidthEvent(Event):
  """
  Event emitted every second with the bytes sent and received by tor on a
  per-circuit basis.

  The CIRC_BW event was introduced in tor version 0.2.5.2-alpha.

  .. versionadded:: 1.2.0

  :var str id: circuit identifier
  :var long read: bytes received by tor that second
  :var long written: bytes sent by tor that second
  """

  _KEYWORD_ARGS = {
    'ID': 'id',
    'READ': 'read',
    'WRITTEN': 'written',
  }

  _VERSION_ADDED = stem.version.Requirement.EVENT_CIRC_BW

  def _parse(self):
    if not self.id:
      raise stem.ProtocolError('CIRC_BW event is missing its id')
    elif not self.read:
      raise stem.ProtocolError('CIRC_BW event is missing its read value')
    elif not self.written:
      raise stem.ProtocolError('CIRC_BW event is missing its written value')
    elif not self.read.isdigit() or not self.written.isdigit():
      raise stem.ProtocolError("A CIRC_BW event's bytes sent and received should be a positive numeric value, received: %s" % self)
    elif not tor_tools.is_valid_circuit_id(self.id):
      raise stem.ProtocolError("Circuit IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.id, self))

    self.read = int_type(self.read)
    self.written = int_type(self.written)


class CellStatsEvent(Event):
  """
  Event emitted every second with a count of the number of cells types broken
  down by the circuit. **These events are only emitted if TestingTorNetwork is
  set.**

  The CELL_STATS event was introduced in tor version 0.2.5.2-alpha.

  .. versionadded:: 1.2.0

  :var str id: circuit identifier
  :var str inbound_queue: inbound queue identifier
  :var str inbound_connection: inbound connection identifier
  :var dict inbound_added: mapping of added inbound cell types to their count
  :var dict inbound_removed: mapping of removed inbound cell types to their count
  :var dict inbound_time: mapping of inbound cell types to the time they took to write in milliseconds
  :var str outbound_queue: outbound queue identifier
  :var str outbound_connection: outbound connection identifier
  :var dict outbound_added: mapping of added outbound cell types to their count
  :var dict outbound_removed: mapping of removed outbound cell types to their count
  :var dict outbound_time: mapping of outbound cell types to the time they took to write in milliseconds
  """

  _KEYWORD_ARGS = {
    'ID': 'id',
    'InboundQueue': 'inbound_queue',
    'InboundConn': 'inbound_connection',
    'InboundAdded': 'inbound_added',
    'InboundRemoved': 'inbound_removed',
    'InboundTime': 'inbound_time',
    'OutboundQueue': 'outbound_queue',
    'OutboundConn': 'outbound_connection',
    'OutboundAdded': 'outbound_added',
    'OutboundRemoved': 'outbound_removed',
    'OutboundTime': 'outbound_time',
  }

  _VERSION_ADDED = stem.version.Requirement.EVENT_CELL_STATS

  def _parse(self):
    if self.id and not tor_tools.is_valid_circuit_id(self.id):
      raise stem.ProtocolError("Circuit IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.id, self))
    elif self.inbound_queue and not tor_tools.is_valid_circuit_id(self.inbound_queue):
      raise stem.ProtocolError("Queue IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.inbound_queue, self))
    elif self.inbound_connection and not tor_tools.is_valid_connection_id(self.inbound_connection):
      raise stem.ProtocolError("Connection IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.inbound_connection, self))
    elif self.outbound_queue and not tor_tools.is_valid_circuit_id(self.outbound_queue):
      raise stem.ProtocolError("Queue IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.outbound_queue, self))
    elif self.outbound_connection and not tor_tools.is_valid_connection_id(self.outbound_connection):
      raise stem.ProtocolError("Connection IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.outbound_connection, self))

    self.inbound_added = _parse_cell_type_mapping(self.inbound_added)
    self.inbound_removed = _parse_cell_type_mapping(self.inbound_removed)
    self.inbound_time = _parse_cell_type_mapping(self.inbound_time)
    self.outbound_added = _parse_cell_type_mapping(self.outbound_added)
    self.outbound_removed = _parse_cell_type_mapping(self.outbound_removed)
    self.outbound_time = _parse_cell_type_mapping(self.outbound_time)


class TokenBucketEmptyEvent(Event):
  """
  Event emitted when refilling an empty token bucket. **These events are only
  emitted if TestingTorNetwork is set.**

  The TB_EMPTY event was introduced in tor version 0.2.5.2-alpha.

  .. versionadded:: 1.2.0

  :var stem.TokenBucket bucket: bucket being refilled
  :var str id: connection identifier
  :var int read: time in milliseconds since the read bucket was last refilled
  :var int written: time in milliseconds since the write bucket was last refilled
  :var int last_refill: time in milliseconds the bucket has been empty since last refilled
  """

  _POSITIONAL_ARGS = ('bucket',)
  _KEYWORD_ARGS = {
    'ID': 'id',
    'READ': 'read',
    'WRITTEN': 'written',
    'LAST': 'last_refill',
  }

  _VERSION_ADDED = stem.version.Requirement.EVENT_TB_EMPTY

  def _parse(self):
    if self.id and not tor_tools.is_valid_connection_id(self.id):
      raise stem.ProtocolError("Connection IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.id, self))
    elif not self.read.isdigit():
      raise stem.ProtocolError("A TB_EMPTY's READ value should be a positive numeric value, received: %s" % self)
    elif not self.written.isdigit():
      raise stem.ProtocolError("A TB_EMPTY's WRITTEN value should be a positive numeric value, received: %s" % self)
    elif not self.last_refill.isdigit():
      raise stem.ProtocolError("A TB_EMPTY's LAST value should be a positive numeric value, received: %s" % self)

    self.read = int(self.read)
    self.written = int(self.written)
    self.last_refill = int(self.last_refill)

    self._log_if_unrecognized('bucket', stem.TokenBucket)


def _parse_cell_type_mapping(mapping):
  """
  Parses a mapping of the form...

    key1:value1,key2:value2...

  ... in which keys are strings and values are integers.

  :param str mapping: value to be parsed

  :returns: dict of **str => int** mappings

  :rasies: **stem.ProtocolError** if unable to parse the mapping
  """

  if mapping is None:
    return None

  results = {}

  for entry in mapping.split(','):
    if ':' not in entry:
      raise stem.ProtocolError("Mappings are expected to be of the form 'key:value', got '%s': %s" % (entry, mapping))

    key, value = entry.split(':', 1)

    if not CELL_TYPE.match(key):
      raise stem.ProtocolError("Key had invalid characters, got '%s': %s" % (key, mapping))
    elif not value.isdigit():
      raise stem.ProtocolError("Values should just be integers, got '%s': %s" % (value, mapping))

    results[key] = int(value)

  return results


EVENT_TYPE_TO_CLASS = {
  'ADDRMAP': AddrMapEvent,
  'AUTHDIR_NEWDESCS': AuthDirNewDescEvent,
  'BUILDTIMEOUT_SET': BuildTimeoutSetEvent,
  'BW': BandwidthEvent,
  'CELL_STATS': CellStatsEvent,
  'CIRC': CircuitEvent,
  'CIRC_BW': CircuitBandwidthEvent,
  'CIRC_MINOR': CircMinorEvent,
  'CLIENTS_SEEN': ClientsSeenEvent,
  'CONF_CHANGED': ConfChangedEvent,
  'CONN_BW': ConnectionBandwidthEvent,
  'DEBUG': LogEvent,
  'DESCCHANGED': DescChangedEvent,
  'ERR': LogEvent,
  'GUARD': GuardEvent,
  'HS_DESC': HSDescEvent,
  'HS_DESC_CONTENT': HSDescContentEvent,
  'INFO': LogEvent,
  'NEWCONSENSUS': NewConsensusEvent,
  'NEWDESC': NewDescEvent,
  'NOTICE': LogEvent,
  'NS': NetworkStatusEvent,
  'ORCONN': ORConnEvent,
  'SIGNAL': SignalEvent,
  'STATUS_CLIENT': StatusEvent,
  'STATUS_GENERAL': StatusEvent,
  'STATUS_SERVER': StatusEvent,
  'STREAM': StreamEvent,
  'STREAM_BW': StreamBwEvent,
  'TB_EMPTY': TokenBucketEmptyEvent,
  'TRANSPORT_LAUNCHED': TransportLaunchedEvent,
  'WARN': LogEvent,

  # accounting for a bug in tor 0.2.0.22
  'STATUS_SEVER': StatusEvent,
}
