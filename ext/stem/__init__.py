# Copyright 2011-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Library for working with the tor process.

**Module Overview:**

::

  ControllerError - Base exception raised when using the controller.
    |- ProtocolError - Malformed socket data.
    |- OperationFailed - Tor was unable to successfully complete the operation.
    |  |- UnsatisfiableRequest - Tor was unable to satisfy a valid request.
    |  |  +- CircuitExtensionFailed - Attempt to make or extend a circuit failed.
    |  |- DescriptorUnavailable - The given relay descriptor is unavailable.
    |  +- InvalidRequest - Invalid request.
    |     +- InvalidArguments - Invalid request parameters.
    +- SocketError - Communication with the socket failed.
       +- SocketClosed - Socket has been shut down.

.. data:: Runlevel (enum)

  Rating of importance used for event logging.

  =========== ===========
  Runlevel    Description
  =========== ===========
  **ERR**     critical issues that impair tor's ability to function
  **WARN**    non-critical issues the user should be aware of
  **NOTICE**  information that may be helpful to the user
  **INFO**    high level runtime information
  **DEBUG**   low level runtime information
  =========== ===========

.. data:: Signal (enum)

  Signals that the tor process will accept.

  ========================= ===========
  Signal                    Description
  ========================= ===========
  **RELOAD** or **HUP**     reloads our torrc
  **SHUTDOWN** or **INT**   shut down, waiting ShutdownWaitLength first if we're a relay
  **DUMP** or **USR1**      dumps information about open connections and circuits to our log
  **DEBUG** or **USR2**     switch our logging to the DEBUG runlevel
  **HALT** or **TERM**      exit tor immediately
  **NEWNYM**                switch to new circuits, so new application requests don't share any circuits with old ones (this also clears our DNS cache)
  **CLEARDNSCACHE**         clears cached DNS results
  **HEARTBEAT**             trigger a heartbeat log message
  ========================= ===========

.. data:: Flag (enum)

  Flag assigned to tor relays by the authorities to indicate various
  characteristics.

  **Note:** The BADDIRECTORY flag was `removed from tor <https://gitweb.torproject.org/torspec.git/commit/dir-spec.txt?id=2f012f1>`_.

  ================= ===========
  Flag              Description
  ================= ===========
  **AUTHORITY**     relay is a directory authority
  **BADEXIT**       relay shouldn't be used as an exit due to being either problematic or malicious (`wiki <https://trac.torproject.org/projects/tor/wiki/doc/badRelays>`_)
  **BADDIRECTORY**  relay shouldn't be used for directory information
  **EXIT**          relay's exit policy makes it more useful as an exit rather than middle hop
  **FAST**          relay's suitable for high-bandwidth circuits
  **GUARD**         relay's suitable for being an entry guard (first hop)
  **HSDIR**         relay is being used as a v2 hidden service directory
  **NAMED**         relay can be referred to by its nickname
  **RUNNING**       relay is currently usable
  **STABLE**        relay's suitable for long-lived circuits
  **UNNAMED**       relay isn't currently bound to a nickname
  **V2DIR**         relay supports the v2 directory protocol
  **VALID**         relay has been validated
  ================= ===========

.. data:: CircStatus (enum)

  Statuses that a circuit can be in. Tor may provide statuses not in this enum.

  ============ ===========
  CircStatus   Description
  ============ ===========
  **LAUNCHED** new circuit was created
  **BUILT**    circuit finished being created and can accept traffic
  **EXTENDED** circuit has been extended by a hop
  **FAILED**   circuit construction failed
  **CLOSED**   circuit has been closed
  ============ ===========

.. data:: CircBuildFlag (enum)

  Attributes about how a circuit is built. These were introduced in tor version
  0.2.3.11. Tor may provide flags not in this enum.

  ================= ===========
  CircBuildFlag     Description
  ================= ===========
  **ONEHOP_TUNNEL** single hop circuit to fetch directory information
  **IS_INTERNAL**   circuit that won't be used for client traffic
  **NEED_CAPACITY** circuit only includes high capacity relays
  **NEED_UPTIME**   circuit only includes relays with a high uptime
  ================= ===========

.. data:: CircPurpose (enum)

  Description of what a circuit is intended for. These were introduced in tor
  version 0.2.1.6. Tor may provide purposes not in this enum.

  ==================== ===========
  CircPurpose          Description
  ==================== ===========
  **GENERAL**          client traffic or fetching directory information
  **HS_CLIENT_INTRO**  client side introduction point for a hidden service circuit
  **HS_CLIENT_REND**   client side hidden service rendezvous circuit
  **HS_SERVICE_INTRO** server side introduction point for a hidden service circuit
  **HS_SERVICE_REND**  server side hidden service rendezvous circuit
  **TESTING**          testing to see if we're reachable, so we can be used as a relay
  **CONTROLLER**       circuit that was built by a controller
  **MEASURE_TIMEOUT**  circuit being kept around to see how long it takes
  ==================== ===========

.. data:: CircClosureReason (enum)

  Reason that a circuit is being closed or failed to be established. Tor may
  provide reasons not in this enum.

  ========================= ===========
  CircClosureReason         Description
  ========================= ===========
  **NONE**                  no reason given
  **TORPROTOCOL**           violation in the tor protocol
  **INTERNAL**              internal error
  **REQUESTED**             requested by the client via a TRUNCATE command
  **HIBERNATING**           relay is currently hibernating
  **RESOURCELIMIT**         relay is out of memory, sockets, or circuit IDs
  **CONNECTFAILED**         unable to contact the relay
  **OR_IDENTITY**           relay had the wrong OR identification
  **OR_CONN_CLOSED**        connection failed after being established
  **FINISHED**              circuit has expired (see tor's MaxCircuitDirtiness config option)
  **TIMEOUT**               circuit construction timed out
  **DESTROYED**             circuit unexpectedly closed
  **NOPATH**                not enough relays to make a circuit
  **NOSUCHSERVICE**         requested hidden service does not exist
  **MEASUREMENT_EXPIRED**   same as **TIMEOUT** except that it was left open for measurement purposes
  ========================= ===========

.. data:: CircEvent (enum)

  Type of change reflected in a circuit by a CIRC_MINOR event. Tor may provide
  event types not in this enum.

  ===================== ===========
  CircEvent             Description
  ===================== ===========
  **PURPOSE_CHANGED**   circuit purpose or hidden service state has changed
  **CANNIBALIZED**      circuit connections are being reused for a different circuit
  ===================== ===========

.. data:: HiddenServiceState (enum)

  State that a hidden service circuit can have. These were introduced in tor
  version 0.2.3.11. Tor may provide states not in this enum.

  Enumerations fall into four groups based on their prefix...

  ======= ===========
  Prefix  Description
  ======= ===========
  HSCI_*  client-side introduction-point
  HSCR_*  client-side rendezvous-point
  HSSI_*  service-side introduction-point
  HSSR_*  service-side rendezvous-point
  ======= ===========

  ============================= ===========
  HiddenServiceState            Description
  ============================= ===========
  **HSCI_CONNECTING**           connecting to the introductory point
  **HSCI_INTRO_SENT**           sent INTRODUCE1 and awaiting a reply
  **HSCI_DONE**                 received a reply, circuit is closing
  **HSCR_CONNECTING**           connecting to the introductory point
  **HSCR_ESTABLISHED_IDLE**     rendezvous-point established, awaiting an introduction
  **HSCR_ESTABLISHED_WAITING**  introduction received, awaiting a rend
  **HSCR_JOINED**               connected to the hidden service
  **HSSI_CONNECTING**           connecting to the introductory point
  **HSSI_ESTABLISHED**          established introductory point
  **HSSR_CONNECTING**           connecting to the introductory point
  **HSSR_JOINED**               connected to the rendezvous-point
  ============================= ===========

.. data:: RelayEndReason (enum)

  Reasons why the stream is to be closed.

  =================== ===========
  RelayEndReason      Description
  =================== ===========
  **MISC**            none of the following reasons
  **RESOLVEFAILED**   unable to resolve the hostname
  **CONNECTREFUSED**  remote host refused the connection
  **EXITPOLICY**      OR refuses to connect to the destination
  **DESTROY**         circuit is being shut down
  **DONE**            connection has been closed
  **TIMEOUT**         connection timed out
  **NOROUTE**         routing error while contacting the destination
  **HIBERNATING**     relay is temporarily hibernating
  **INTERNAL**        internal error at the relay
  **RESOURCELIMIT**   relay has insufficient resources to service the request
  **CONNRESET**       connection was unexpectedly reset
  **TORPROTOCOL**     violation in the tor protocol
  **NOTDIRECTORY**    directory information requested from a relay that isn't mirroring it
  =================== ===========

.. data:: StreamStatus (enum)

  State that a stream going through tor can have. Tor may provide states not in
  this enum.

  ================= ===========
  StreamStatus      Description
  ================= ===========
  **NEW**           request for a new connection
  **NEWRESOLVE**    request to resolve an address
  **REMAP**         address is being re-mapped to another
  **SENTCONNECT**   sent a connect cell along a circuit
  **SENTRESOLVE**   sent a resolve cell along a circuit
  **SUCCEEDED**     stream has been established
  **FAILED**        stream is detached, and won't be re-established
  **DETACHED**      stream is detached, but might be re-established
  **CLOSED**        stream has closed
  ================= ===========

.. data:: StreamClosureReason (enum)

  Reason that a stream is being closed or failed to be established. This
  includes all values in the :data:`~stem.RelayEndReason` enumeration as
  well as the following. Tor may provide reasons not in this enum.

  ===================== ===========
  StreamClosureReason   Description
  ===================== ===========
  **END**               endpoint has sent a RELAY_END cell
  **PRIVATE_ADDR**      endpoint was a private address (127.0.0.1, 10.0.0.1, etc)
  ===================== ===========

.. data:: StreamSource (enum)

  Cause of a stream being remapped to another address. Tor may provide sources
  not in this enum.

  ============= ===========
  StreamSource  Description
  ============= ===========
  **CACHE**     tor is remapping because of a cached answer
  **EXIT**      exit relay requested the remap
  ============= ===========

.. data:: StreamPurpose (enum)

  Purpsoe of the stream. This is only provided with new streams and tor may
  provide purposes not in this enum.

  ================= ===========
  StreamPurpose     Description
  ================= ===========
  **DIR_FETCH**     fetching directory information (descriptors, consensus, etc)
  **DIR_UPLOAD**    uploading our descriptor to an authority
  **DNS_REQUEST**   user initiated DNS request
  **DIRPORT_TEST**  checking that our directory port is reachable externally
  **USER**          either relaying user traffic or not one of the above categories
  ================= ===========

.. data:: ORStatus (enum)

  State that an OR connection can have. Tor may provide states not in this
  enum.

  =============== ===========
  ORStatus        Description
  =============== ===========
  **NEW**         received OR connection, starting server-side handshake
  **LAUNCHED**    launched outbound OR connection, starting client-side handshake
  **CONNECTED**   OR connection has been established
  **FAILED**      attempt to establish OR connection failed
  **CLOSED**      OR connection has been closed
  =============== ===========

.. data:: ORClosureReason (enum)

  Reason that an OR connection is being closed or failed to be established. Tor
  may provide reasons not in this enum.

  =================== ===========
  ORClosureReason     Description
  =================== ===========
  **DONE**            OR connection shut down cleanly
  **CONNECTREFUSED**  got a ECONNREFUSED when connecting to the relay
  **IDENTITY**        identity of the relay wasn't what we expected
  **CONNECTRESET**    got a ECONNRESET or similar error from relay
  **TIMEOUT**         got a ETIMEOUT or similar error from relay
  **NOROUTE**         got a ENOTCONN, ENETUNREACH, ENETDOWN, EHOSTUNREACH, or similar error from relay
  **IOERROR**         got a different kind of error from relay
  **RESOURCELIMIT**   relay has insufficient resources to service the request
  **MISC**            connection refused for another reason
  **PT_MISSING**      no pluggable transport was available
  =================== ===========

.. data:: AuthDescriptorAction (enum)

  Actions that directory authorities might take with relay descriptors. Tor may
  provide reasons not in this enum.

  ===================== ===========
  AuthDescriptorAction  Description
  ===================== ===========
  **ACCEPTED**          accepting the descriptor as the newest version
  **DROPPED**           descriptor rejected without notifying the relay
  **REJECTED**          relay notified that its descriptor has been rejected
  ===================== ===========

.. data:: StatusType (enum)

  Sources for tor status events. Tor may provide types not in this enum.

  ============= ===========
  StatusType    Description
  ============= ===========
  **GENERAL**   general tor activity, not specifically as a client or relay
  **CLIENT**    related to our activity as a tor client
  **SERVER**    related to our activity as a tor relay
  ============= ===========

.. data:: GuardType (enum)

  Use a guard relay can be for. Tor may provide types not in this enum.

  =========== ===========
  GuardType   Description
  =========== ===========
  **ENTRY**   used to connect to the tor network
  =========== ===========

.. data:: GuardStatus (enum)

  Status a guard relay can have. Tor may provide types not in this enum.

  ============= ===========
  GuardStatus   Description
  ============= ===========
  **NEW**       new guard that we weren't previously using
  **DROPPED**   removed from use as one of our guards
  **UP**        guard is now reachable
  **DOWN**      guard is now unreachable
  **BAD**       consensus or relay considers this relay to be unusable as a guard
  **GOOD**      consensus or relay considers this relay to be usable as a guard
  ============= ===========

.. data:: TimeoutSetType (enum)

  Way in which the timeout value of a circuit is changing. Tor may provide
  types not in this enum.

  =============== ===========
  TimeoutSetType  Description
  =============== ===========
  **COMPUTED**    tor has computed a new timeout based on prior circuits
  **RESET**       timeout reverted to its default
  **SUSPENDED**   timeout reverted to its default until network connectivity has recovered
  **DISCARD**     throwing out timeout value from when the network was down
  **RESUME**      resumed calculations to determine the proper timeout
  =============== ===========

.. data:: ConnectionType (enum)

  Purpose for a tor connection. Tor may provide types not in this enum.

  The meaning behind these values is a bit unclear, pending :trac:`10086`.

  =============== ===========
  ConnectionType  Description
  =============== ===========
  **OR**          carrying traffic within the tor network
  **DIR**         fetching or sending tor descriptor data
  **EXIT**        carrying traffic between the tor network and an external destination
  =============== ===========

.. data:: TokenBucket (enum)

  Bucket categories of TB_EMPTY events.

  =============== ===========
  TokenBucket     Description
  =============== ===========
  **GLOBAL**      global token bucket
  **RELAY**       relay token bucket
  **ORCONN**      bucket used for OR connections
  =============== ===========

.. data:: HSDescAction (enum)

  Action beeing taken in a HS_DESC event.

  =============== ===========
  HSDescAction    Description
  =============== ===========
  **REQUESTED**   uncached hidden service descriptor is being requested
  **UPLOAD**      descriptor is being uploaded with HSPOST
  **RECEIVED**    hidden service descriptor has been retrieved
  **UPLOADED**    descriptor was uploaded with HSPOST
  **IGNORE**      fetched descriptor was ignored because we already have its v0 descriptor
  **FAILED**      we were unable to retrieve the descriptor
  =============== ===========

.. data:: HSDescReason (enum)

  Reason for the hidden service descriptor to fail to be fetched.

  =================== ===========
  HSDescReason        Description
  =================== ===========
  **BAD_DESC**        descriptor was unparseable
  **QUERY_REJECTED**  hidden service directory refused to provide the descriptor
  **UPLOAD_REJECTED** descriptor was rejected by the hidden service directory
  **NOT_FOUND**       descriptor with the given identifier wasn't found
  **UNEXPECTED**      failure type is unknown
  =================== ===========

.. data:: HSAuth (enum)

  Type of authentication being used for a HS_DESC event.

  ================= ===========
  HSAuth            Description
  ================= ===========
  **NO_AUTH**       no authentication
  **BASIC_AUTH**    general hidden service authentication
  **STEALTH_AUTH**  authentication method that hides service activity from unauthorized clients
  **UNKNOWN**       unrecognized method of authentication
  ================= ===========
"""

__version__ = '1.4.1'
__author__ = 'Damian Johnson'
__contact__ = 'atagar@torproject.org'
__url__ = 'https://stem.torproject.org/'
__license__ = 'LGPLv3'

__all__ = [
  'descriptor',
  'response',
  'util',
  'connection',
  'control',
  'exit_policy',
  'prereq',
  'process',
  'socket',
  'version',
  'ControllerError',
  'ProtocolError',
  'OperationFailed',
  'UnsatisfiableRequest',
  'CircuitExtensionFailed',
  'DescriptorUnavailable',
  'InvalidRequest',
  'InvalidArguments',
  'SocketError',
  'SocketClosed',
  'Runlevel',
  'Signal',
  'Flag',
  'CircStatus',
  'CircBuildFlag',
  'CircPurpose',
  'CircClosureReason',
  'CircEvent',
  'HiddenServiceState',
  'HSAuth',
  'HSDescAction',
  'HSDescReason',
  'RelayEndReason',
  'StreamStatus',
  'StreamClosureReason',
  'StreamSource',
  'StreamPurpose',
  'ORStatus',
  'ORClosureReason',
  'AuthDescriptorAction',
  'StatusType',
  'GuardType',
  'GuardStatus',
  'TimeoutSetType',
]

import stem.prereq

if stem.prereq.is_python_3():
  str_type = str
  int_type = int
else:
  str_type = unicode
  int_type = long

import stem.util.enum

# Constant to indicate an undefined argument default. Usually we'd use None for
# this, but users will commonly provide None as the argument so need something
# else fairly unique...

UNDEFINED = '<Undefined_ >'


class ControllerError(Exception):
  'Base error for controller communication issues.'


class ProtocolError(ControllerError):
  'Malformed content from the control socket.'


class OperationFailed(ControllerError):
  """
  Base exception class for failed operations that return an error code

  :var str code: error code returned by Tor
  :var str message: error message returned by Tor or a human readable error
    message
  """

  def __init__(self, code = None, message = None):
    super(ControllerError, self).__init__(message)
    self.code = code
    self.message = message


class UnsatisfiableRequest(OperationFailed):
  """
  Exception raised if Tor was unable to process our request.
  """


class CircuitExtensionFailed(UnsatisfiableRequest):
  """
  An attempt to create or extend a circuit failed.

  :var stem.response.CircuitEvent circ: response notifying us of the failure
  """

  def __init__(self, message, circ = None):
    super(CircuitExtensionFailed, self).__init__(message = message)
    self.circ = circ


class DescriptorUnavailable(OperationFailed):
  """
  Tor was unable to provide a descriptor for the given relay.
  """

  def __init__(self, message):
    super(DescriptorUnavailable, self).__init__(message = message)


class InvalidRequest(OperationFailed):
  """
  Exception raised when the request was invalid or malformed.
  """


class InvalidArguments(InvalidRequest):
  """
  Exception class for requests which had invalid arguments.

  :var str code: error code returned by Tor
  :var str message: error message returned by Tor or a human readable error
    message
  :var list arguments: a list of arguments which were invalid
  """

  def __init__(self, code = None, message = None, arguments = None):
    super(InvalidArguments, self).__init__(code, message)
    self.arguments = arguments


class SocketError(ControllerError):
  'Error arose while communicating with the control socket.'


class SocketClosed(SocketError):
  'Control socket was closed before completing the message.'

Runlevel = stem.util.enum.UppercaseEnum(
  'DEBUG',
  'INFO',
  'NOTICE',
  'WARN',
  'ERR',
)

Flag = stem.util.enum.Enum(
  ('AUTHORITY', 'Authority'),
  ('BADEXIT', 'BadExit'),
  ('BADDIRECTORY', 'BadDirectory'),
  ('EXIT', 'Exit'),
  ('FAST', 'Fast'),
  ('GUARD', 'Guard'),
  ('HSDIR', 'HSDir'),
  ('NAMED', 'Named'),
  ('RUNNING', 'Running'),
  ('STABLE', 'Stable'),
  ('UNNAMED', 'Unnamed'),
  ('V2DIR', 'V2Dir'),
  ('V3DIR', 'V3Dir'),
  ('VALID', 'Valid'),
)

Signal = stem.util.enum.UppercaseEnum(
  'RELOAD',
  'HUP',
  'SHUTDOWN',
  'INT',
  'DUMP',
  'USR1',
  'DEBUG',
  'USR2',
  'HALT',
  'TERM',
  'NEWNYM',
  'CLEARDNSCACHE',
  'HEARTBEAT',
)

CircStatus = stem.util.enum.UppercaseEnum(
  'LAUNCHED',
  'BUILT',
  'EXTENDED',
  'FAILED',
  'CLOSED',
)

CircBuildFlag = stem.util.enum.UppercaseEnum(
  'ONEHOP_TUNNEL',
  'IS_INTERNAL',
  'NEED_CAPACITY',
  'NEED_UPTIME',
)

CircPurpose = stem.util.enum.UppercaseEnum(
  'GENERAL',
  'HS_CLIENT_INTRO',
  'HS_CLIENT_REND',
  'HS_SERVICE_INTRO',
  'HS_SERVICE_REND',
  'TESTING',
  'CONTROLLER',
  'MEASURE_TIMEOUT',
)

CircClosureReason = stem.util.enum.UppercaseEnum(
  'NONE',
  'TORPROTOCOL',
  'INTERNAL',
  'REQUESTED',
  'HIBERNATING',
  'RESOURCELIMIT',
  'CONNECTFAILED',
  'OR_IDENTITY',
  'OR_CONN_CLOSED',
  'FINISHED',
  'TIMEOUT',
  'DESTROYED',
  'NOPATH',
  'NOSUCHSERVICE',
  'MEASUREMENT_EXPIRED',
)

CircEvent = stem.util.enum.UppercaseEnum(
  'PURPOSE_CHANGED',
  'CANNIBALIZED',
)

HiddenServiceState = stem.util.enum.UppercaseEnum(
  'HSCI_CONNECTING',
  'HSCI_INTRO_SENT',
  'HSCI_DONE',
  'HSCR_CONNECTING',
  'HSCR_ESTABLISHED_IDLE',
  'HSCR_ESTABLISHED_WAITING',
  'HSCR_JOINED',
  'HSSI_CONNECTING',
  'HSSI_ESTABLISHED',
  'HSSR_CONNECTING',
  'HSSR_JOINED',
)

RelayEndReason = stem.util.enum.UppercaseEnum(
  'MISC',
  'RESOLVEFAILED',
  'CONNECTREFUSED',
  'EXITPOLICY',
  'DESTROY',
  'DONE',
  'TIMEOUT',
  'NOROUTE',
  'HIBERNATING',
  'INTERNAL',
  'RESOURCELIMIT',
  'CONNRESET',
  'TORPROTOCOL',
  'NOTDIRECTORY',
)

StreamStatus = stem.util.enum.UppercaseEnum(
  'NEW',
  'NEWRESOLVE',
  'REMAP',
  'SENTCONNECT',
  'SENTRESOLVE',
  'SUCCEEDED',
  'FAILED',
  'DETACHED',
  'CLOSED',
)

# StreamClosureReason is a superset of RelayEndReason
StreamClosureReason = stem.util.enum.UppercaseEnum(*(RelayEndReason.keys() + [
  'END',
  'PRIVATE_ADDR',
]))

StreamSource = stem.util.enum.UppercaseEnum(
  'CACHE',
  'EXIT',
)

StreamPurpose = stem.util.enum.UppercaseEnum(
  'DIR_FETCH',
  'DIR_UPLOAD',
  'DNS_REQUEST',
  'DIRPORT_TEST',
  'USER',
)

ORStatus = stem.util.enum.UppercaseEnum(
  'NEW',
  'LAUNCHED',
  'CONNECTED',
  'FAILED',
  'CLOSED',
)

ORClosureReason = stem.util.enum.UppercaseEnum(
  'DONE',
  'CONNECTREFUSED',
  'IDENTITY',
  'CONNECTRESET',
  'TIMEOUT',
  'NOROUTE',
  'IOERROR',
  'RESOURCELIMIT',
  'MISC',
  'PT_MISSING',
)

AuthDescriptorAction = stem.util.enum.UppercaseEnum(
  'ACCEPTED',
  'DROPPED',
  'REJECTED',
)

StatusType = stem.util.enum.UppercaseEnum(
  'GENERAL',
  'CLIENT',
  'SERVER',
)

GuardType = stem.util.enum.UppercaseEnum(
  'ENTRY',
)

GuardStatus = stem.util.enum.UppercaseEnum(
  'NEW',
  'UP',
  'DOWN',
  'BAD',
  'GOOD',
  'DROPPED',
)

TimeoutSetType = stem.util.enum.UppercaseEnum(
  'COMPUTED',
  'RESET',
  'SUSPENDED',
  'DISCARD',
  'RESUME',
)

ConnectionType = stem.util.enum.UppercaseEnum(
  'OR',
  'DIR',
  'EXIT',
)

TokenBucket = stem.util.enum.UppercaseEnum(
  'GLOBAL',
  'RELAY',
  'ORCONN',
)

HSDescAction = stem.util.enum.UppercaseEnum(
  'REQUESTED',
  'UPLOAD',
  'RECEIVED',
  'UPLOADED',
  'IGNORE',
  'FAILED',
)

HSDescReason = stem.util.enum.UppercaseEnum(
  'BAD_DESC',
  'QUERY_REJECTED',
  'UPLOAD_REJECTED',
  'NOT_FOUND',
  'UNEXPECTED',
)

HSAuth = stem.util.enum.UppercaseEnum(
  'NO_AUTH',
  'BASIC_AUTH',
  'STEALTH_AUTH',
  'UNKNOWN',
)
