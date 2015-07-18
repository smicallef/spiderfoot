# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import stem.response
import stem.socket
import stem.version

from stem.connection import AuthMethod
from stem.util import log


class ProtocolInfoResponse(stem.response.ControlMessage):
  """
  Version one PROTOCOLINFO query response.

  The protocol_version is the only mandatory data for a valid PROTOCOLINFO
  response, so all other values are None if undefined or empty if a collection.

  :var int protocol_version: protocol version of the response
  :var stem.version.Version tor_version: version of the tor process
  :var tuple auth_methods: :data:`stem.connection.AuthMethod` types that tor will accept
  :var tuple unknown_auth_methods: strings of unrecognized auth methods
  :var str cookie_path: path of tor's authentication cookie
  """

  def _parse_message(self):
    # Example:
    #   250-PROTOCOLINFO 1
    #   250-AUTH METHODS=COOKIE COOKIEFILE="/home/atagar/.tor/control_auth_cookie"
    #   250-VERSION Tor="0.2.1.30"
    #   250 OK

    self.protocol_version = None
    self.tor_version = None
    self.auth_methods = ()
    self.unknown_auth_methods = ()
    self.cookie_path = None

    auth_methods, unknown_auth_methods = [], []
    remaining_lines = list(self)

    if not self.is_ok() or not remaining_lines.pop() == 'OK':
      raise stem.ProtocolError("PROTOCOLINFO response didn't have an OK status:\n%s" % self)

    # sanity check that we're a PROTOCOLINFO response
    if not remaining_lines[0].startswith('PROTOCOLINFO'):
      raise stem.ProtocolError('Message is not a PROTOCOLINFO response:\n%s' % self)

    while remaining_lines:
      line = remaining_lines.pop(0)
      line_type = line.pop()

      if line_type == 'PROTOCOLINFO':
        # Line format:
        #   FirstLine = "PROTOCOLINFO" SP PIVERSION CRLF
        #   PIVERSION = 1*DIGIT

        if line.is_empty():
          raise stem.ProtocolError("PROTOCOLINFO response's initial line is missing the protocol version: %s" % line)

        try:
          self.protocol_version = int(line.pop())
        except ValueError:
          raise stem.ProtocolError('PROTOCOLINFO response version is non-numeric: %s' % line)

        # The piversion really should be '1' but, according to the spec, tor
        # does not necessarily need to provide the PROTOCOLINFO version that we
        # requested. Log if it's something we aren't expecting but still make
        # an effort to parse like a v1 response.

        if self.protocol_version != 1:
          log.info("We made a PROTOCOLINFO version 1 query but got a version %i response instead. We'll still try to use it, but this may cause problems." % self.protocol_version)
      elif line_type == 'AUTH':
        # Line format:
        #   AuthLine = "250-AUTH" SP "METHODS=" AuthMethod *("," AuthMethod)
        #              *(SP "COOKIEFILE=" AuthCookieFile) CRLF
        #   AuthMethod = "NULL" / "HASHEDPASSWORD" / "COOKIE"
        #   AuthCookieFile = QuotedString

        # parse AuthMethod mapping
        if not line.is_next_mapping('METHODS'):
          raise stem.ProtocolError("PROTOCOLINFO response's AUTH line is missing its mandatory 'METHODS' mapping: %s" % line)

        for method in line.pop_mapping()[1].split(','):
          if method == 'NULL':
            auth_methods.append(AuthMethod.NONE)
          elif method == 'HASHEDPASSWORD':
            auth_methods.append(AuthMethod.PASSWORD)
          elif method == 'COOKIE':
            auth_methods.append(AuthMethod.COOKIE)
          elif method == 'SAFECOOKIE':
            auth_methods.append(AuthMethod.SAFECOOKIE)
          else:
            unknown_auth_methods.append(method)
            message_id = 'stem.response.protocolinfo.unknown_auth_%s' % method
            log.log_once(message_id, log.INFO, "PROTOCOLINFO response included a type of authentication that we don't recognize: %s" % method)

            # our auth_methods should have a single AuthMethod.UNKNOWN entry if
            # any unknown authentication methods exist
            if AuthMethod.UNKNOWN not in auth_methods:
              auth_methods.append(AuthMethod.UNKNOWN)

        # parse optional COOKIEFILE mapping (quoted and can have escapes)
        if line.is_next_mapping('COOKIEFILE', True, True):
          self.cookie_path = line.pop_mapping(True, True)[1]
      elif line_type == 'VERSION':
        # Line format:
        #   VersionLine = "250-VERSION" SP "Tor=" TorVersion OptArguments CRLF
        #   TorVersion = QuotedString

        if not line.is_next_mapping('Tor', True):
          raise stem.ProtocolError("PROTOCOLINFO response's VERSION line is missing its mandatory tor version mapping: %s" % line)

        try:
          self.tor_version = stem.version.Version(line.pop_mapping(True)[1])
        except ValueError as exc:
          raise stem.ProtocolError(exc)
      else:
        log.debug("Unrecognized PROTOCOLINFO line type '%s', ignoring it: %s" % (line_type, line))

    self.auth_methods = tuple(auth_methods)
    self.unknown_auth_methods = tuple(unknown_auth_methods)
