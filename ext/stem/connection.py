# Copyright 2011-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Functions for connecting and authenticating to the tor process.

The :func:`~stem.connection.connect` function give an easy, one line
method for getting an authenticated control connection. This is handy for CLI
applications and the python interactive interpreter, but does several things
that makes it undesirable for applications (uses stdin/stdout, suppresses
exceptions, etc).

::

  import sys

  from stem.connection import connect

  if __name__ == '__main__':
    controller = connect()

    if not controller:
      sys.exit(1)  # unable to get a connection

    print 'Tor is running version %s' % controller.get_version()
    controller.close()

::

  % python example.py
  Tor is running version 0.2.4.10-alpha-dev (git-8be6058d8f31e578)

... or if Tor isn't running...

::

  % python example.py
  [Errno 111] Connection refused

The :func:`~stem.connection.authenticate` function, however, gives easy but
fine-grained control over the authentication process. For instance...

::

  import sys
  import getpass
  import stem.connection
  import stem.socket

  try:
    control_socket = stem.socket.ControlPort(port = 9051)
  except stem.SocketError as exc:
    print 'Unable to connect to port 9051 (%s)' % exc
    sys.exit(1)

  try:
    stem.connection.authenticate(control_socket)
  except stem.connection.IncorrectSocketType:
    print 'Please check in your torrc that 9051 is the ControlPort.'
    print 'Maybe you configured it to be the ORPort or SocksPort instead?'
    sys.exit(1)
  except stem.connection.MissingPassword:
    controller_password = getpass.getpass('Controller password: ')

    try:
      stem.connection.authenticate_password(control_socket, controller_password)
    except stem.connection.PasswordAuthFailed:
      print 'Unable to authenticate, password is incorrect'
      sys.exit(1)
  except stem.connection.AuthenticationFailure as exc:
    print 'Unable to authenticate: %s' % exc
    sys.exit(1)

**Module Overview:**

::

  connect - Simple method for getting authenticated control connection

  authenticate - Main method for authenticating to a control socket
  authenticate_none - Authenticates to an open control socket
  authenticate_password - Authenticates to a socket supporting password auth
  authenticate_cookie - Authenticates to a socket supporting cookie auth
  authenticate_safecookie - Authenticates to a socket supporting safecookie auth

  get_protocolinfo - Issues a PROTOCOLINFO query

  AuthenticationFailure - Base exception raised for authentication failures
    |- UnrecognizedAuthMethods - Authentication methods are unsupported
    |- IncorrectSocketType - Socket does not speak the tor control protocol
    |
    |- OpenAuthFailed - Failure when authenticating by an open socket
    |  +- OpenAuthRejected - Tor rejected this method of authentication
    |
    |- PasswordAuthFailed - Failure when authenticating by a password
    |  |- PasswordAuthRejected - Tor rejected this method of authentication
    |  |- IncorrectPassword - Password was rejected
    |  +- MissingPassword - Socket supports password auth but wasn't attempted
    |
    |- CookieAuthFailed - Failure when authenticating by a cookie
    |  |- CookieAuthRejected - Tor rejected this method of authentication
    |  |- IncorrectCookieValue - Authentication cookie was rejected
    |  |- IncorrectCookieSize - Size of the cookie file is incorrect
    |  |- UnreadableCookieFile - Unable to read the contents of the auth cookie
    |  +- AuthChallengeFailed - Failure completing the authchallenge request
    |     |- AuthChallengeUnsupported - Tor doesn't recognize the AUTHCHALLENGE command
    |     |- AuthSecurityFailure - Server provided the wrong nonce credentials
    |     |- InvalidClientNonce - The client nonce is invalid
    |     +- UnrecognizedAuthChallengeMethod - AUTHCHALLENGE does not support the given methods.
    |
    +- MissingAuthInfo - Unexpected PROTOCOLINFO response, missing auth info
       |- NoAuthMethods - Missing any methods for authenticating
       +- NoAuthCookie - Supports cookie auth but doesn't have its path

.. data:: AuthMethod (enum)

  Enumeration of PROTOCOLINFO responses for supported authentication methods.

  ============== ===========
  AuthMethod     Description
  ============== ===========
  **NONE**       No authentication required.
  **PASSWORD**   Password required, see tor's HashedControlPassword option.
  **COOKIE**     Contents of the cookie file required, see tor's CookieAuthentication option.
  **SAFECOOKIE** Need to reply to a hmac challenge using the contents of the cookie file.
  **UNKNOWN**    Tor provided one or more authentication methods that we don't recognize, probably something new.
  ============== ===========
"""

import binascii
import getpass
import os

import stem.control
import stem.response
import stem.socket
import stem.util.connection
import stem.util.enum
import stem.util.str_tools
import stem.util.system
import stem.version

from stem.util import log

AuthMethod = stem.util.enum.Enum('NONE', 'PASSWORD', 'COOKIE', 'SAFECOOKIE', 'UNKNOWN')

CLIENT_HASH_CONSTANT = b'Tor safe cookie authentication controller-to-server hash'
SERVER_HASH_CONSTANT = b'Tor safe cookie authentication server-to-controller hash'

MISSING_PASSWORD_BUG_MSG = """
BUG: You provided a password but despite this stem reported that it was
missing. This shouldn't happen - please let us know about it!

  http://bugs.torproject.org
"""

UNRECOGNIZED_AUTH_TYPE_MSG = """
Tor is using a type of authentication we do not recognize...

  {auth_methods}

Please check that stem is up to date and if there is an existing issue on
'http://bugs.torproject.org'. If there isn't one then let us know!
"""


UNREADABLE_COOKIE_FILE_MSG = """
We were unable to read tor's authentication cookie...

  Path: {path}
  Issue: {issue}
"""

WRONG_PORT_TYPE_MSG = """
Please check in your torrc that {port} is the ControlPort. Maybe you
configured it to be the ORPort or SocksPort instead?
"""

WRONG_SOCKET_TYPE_MSG = """
Unable to connect to tor. Are you sure the interface you specified belongs to
tor?
"""

CONNECT_MESSAGES = {
  'general_auth_failure': 'Unable to authenticate: {error}',
  'incorrect_password': 'Incorrect password',
  'no_control_port': "Unable to connect to tor. Maybe it's running without a ControlPort?",
  'password_prompt': 'Tor controller password:',
  'needs_password': 'Tor requires a password to authenticate',
  'socket_doesnt_exist': "The socket file you specified ({path}) doesn't exist",
  'tor_isnt_running': "Unable to connect to tor. Are you sure it's running?",
  'unable_to_use_port': 'Unable to connect to {address}:{port}: {error}',
  'unable_to_use_socket': "Unable to connect to '{path}': {error}",
  'missing_password_bug': MISSING_PASSWORD_BUG_MSG.strip(),
  'uncrcognized_auth_type': UNRECOGNIZED_AUTH_TYPE_MSG.strip(),
  'unreadable_cookie_file': UNREADABLE_COOKIE_FILE_MSG.strip(),
  'wrong_port_type': WRONG_PORT_TYPE_MSG.strip(),
  'wrong_socket_type': WRONG_SOCKET_TYPE_MSG.strip(),
}


def connect(control_port = ('127.0.0.1', 9051), control_socket = '/var/run/tor/control', password = None, password_prompt = False, chroot_path = None, controller = stem.control.Controller):
  """
  Convenience function for quickly getting a control connection. This is very
  handy for debugging or CLI setup, handling setup and prompting for a password
  if necessary (and none is provided). If any issues arise this prints a
  description of the problem and returns **None**.

  If both a **control_port** and **control_socket** are provided then the
  **control_socket** is tried first, and this provides a generic error message
  if they're both unavailable.

  In much the same vein as git porcelain commands, users should not rely on
  details of how this works. Messages and details of this function's behavior
  could change in the future.

  .. versionadded:: 1.2.0

  :param tuple contol_port: address and port tuple, for instance **('127.0.0.1', 9051)**
  :param str path: path where the control socket is located
  :param str password: passphrase to authenticate to the socket
  :param bool password_prompt: prompt for the controller password if it wasn't
    supplied
  :param str chroot_path: path prefix if in a chroot environment
  :param Class controller: :class:`~stem.control.BaseController` subclass to be
    returned, this provides a :class:`~stem.socket.ControlSocket` if **None**

  :returns: authenticated control connection, the type based on the controller argument

  :raises: **ValueError** if given an invalid control_port, or both
    **control_port** and **control_socket** are **None**
  """

  if control_port is None and control_socket is None:
    raise ValueError('Neither a control port nor control socket were provided. Nothing to connect to.')
  elif control_port:
    if len(control_port) != 2:
      raise ValueError('The control_port argument for connect() should be an (address, port) tuple.')
    elif not stem.util.connection.is_valid_ipv4_address(control_port[0]):
      raise ValueError("'%s' isn't a vaid IPv4 address" % control_port[0])
    elif not stem.util.connection.is_valid_port(control_port[1]):
      raise ValueError("'%s' isn't a valid port" % control_port[1])

  control_connection, error_msg = None, ''

  if control_socket:
    if os.path.exists(control_socket):
      try:
        control_connection = stem.socket.ControlSocketFile(control_socket)
      except stem.SocketError as exc:
        error_msg = CONNECT_MESSAGES['unable_to_use_socket'].format(path = control_socket, error = exc)
    else:
      error_msg = CONNECT_MESSAGES['socket_doesnt_exist'].format(path = control_socket)

  if control_port and not control_connection:
    address, port = control_port

    try:
      control_connection = stem.socket.ControlPort(address, port)
    except stem.SocketError as exc:
      error_msg = CONNECT_MESSAGES['unable_to_use_port'].format(address = address, port = port, error = exc)

  # If unable to connect to either a control socket or port then finally fail
  # out. If we only attempted to connect to one of them then provide the error
  # output from that. Otherwise we provide a more generic error message.
  #
  # We check for a 'tor.real' process name because that's what TBB uses.

  if not control_connection:
    if control_socket and control_port:
      is_tor_running = stem.util.system.is_running('tor') or stem.util.system.is_running('tor.real')
      error_msg = CONNECT_MESSAGES['no_control_port'] if is_tor_running else CONNECT_MESSAGES['tor_isnt_running']

    print(error_msg)
    return None

  return _connect_auth(control_connection, password, password_prompt, chroot_path, controller)


def connect_port(address = '127.0.0.1', port = 9051, password = None, chroot_path = None, controller = stem.control.Controller):
  """
  Convenience function for quickly getting a control connection. This is very
  handy for debugging or CLI setup, handling setup and prompting for a password
  if necessary (and none is provided). If any issues arise this prints a
  description of the problem and returns **None**.

  .. deprecated:: 1.2.0
     Use :func:`~stem.connection.connect` instead.

  :param str address: ip address of the controller
  :param int port: port number of the controller
  :param str password: passphrase to authenticate to the socket
  :param str chroot_path: path prefix if in a chroot environment
  :param Class controller: :class:`~stem.control.BaseController` subclass to be
    returned, this provides a :class:`~stem.socket.ControlSocket` if **None**

  :returns: authenticated control connection, the type based on the controller argument
  """

  try:
    control_port = stem.socket.ControlPort(address, port)
  except stem.SocketError as exc:
    print(exc)
    return None

  return _connect_auth(control_port, password, True, chroot_path, controller)


def connect_socket_file(path = '/var/run/tor/control', password = None, chroot_path = None, controller = stem.control.Controller):
  """
  Convenience function for quickly getting a control connection. For more
  information see the :func:`~stem.connection.connect_port` function.

  In much the same vein as git porcelain commands, users should not rely on
  details of how this works. Messages or details of this function's behavior
  might change in the future.

  .. deprecated:: 1.2.0
     Use :func:`~stem.connection.connect` instead.

  :param str path: path where the control socket is located
  :param str password: passphrase to authenticate to the socket
  :param str chroot_path: path prefix if in a chroot environment
  :param Class controller: :class:`~stem.control.BaseController` subclass to be
    returned, this provides a :class:`~stem.socket.ControlSocket` if **None**

  :returns: authenticated control connection, the type based on the controller argument
  """

  try:
    control_socket = stem.socket.ControlSocketFile(path)
  except stem.SocketError as exc:
    print(exc)
    return None

  return _connect_auth(control_socket, password, True, chroot_path, controller)


def _connect_auth(control_socket, password, password_prompt, chroot_path, controller):
  """
  Helper for the connect_* functions that authenticates the socket and
  constructs the controller.

  :param stem.socket.ControlSocket control_socket: socket being authenticated to
  :param str password: passphrase to authenticate to the socket
  :param bool password_prompt: prompt for the controller password if it wasn't
    supplied
  :param str chroot_path: path prefix if in a chroot environment
  :param Class controller: :class:`~stem.control.BaseController` subclass to be
    returned, this provides a :class:`~stem.socket.ControlSocket` if **None**

  :returns: authenticated control connection, the type based on the controller argument
  """

  try:
    authenticate(control_socket, password, chroot_path)

    if controller is None:
      return control_socket
    else:
      return controller(control_socket, is_authenticated = True)
  except IncorrectSocketType:
    if isinstance(control_socket, stem.socket.ControlPort):
      print(CONNECT_MESSAGES['wrong_port_type'].format(port = control_socket.get_port()))
    else:
      print(CONNECT_MESSAGES['wrong_socket_type'])

    control_socket.close()
    return None
  except UnrecognizedAuthMethods as exc:
    print(CONNECT_MESSAGES['uncrcognized_auth_type'].format(auth_methods = ', '.join(exc.unknown_auth_methods)))
    control_socket.close()
    return None
  except IncorrectPassword:
    print(CONNECT_MESSAGES['incorrect_password'])
    control_socket.close()
    return None
  except MissingPassword:
    if password is not None:
      control_socket.close()
      raise ValueError(CONNECT_MESSAGES['missing_password_bug'])

    if password_prompt:
      try:
        password = getpass.getpass(CONNECT_MESSAGES['password_prompt'] + ' ')
      except KeyboardInterrupt:
        control_socket.close()
        return None

      return _connect_auth(control_socket, password, password_prompt, chroot_path, controller)
    else:
      print(CONNECT_MESSAGES['needs_password'])
      control_socket.close()
      return None
  except UnreadableCookieFile as exc:
    print(CONNECT_MESSAGES['unreadable_cookie_file'].format(path = exc.cookie_path, issue = str(exc)))
    control_socket.close()
    return None
  except AuthenticationFailure as exc:
    print(CONNECT_MESSAGES['general_auth_failure'].format(error = exc))
    control_socket.close()
    return None


def authenticate(controller, password = None, chroot_path = None, protocolinfo_response = None):
  """
  Authenticates to a control socket using the information provided by a
  PROTOCOLINFO response. In practice this will often be all we need to
  authenticate, raising an exception if all attempts to authenticate fail.

  All exceptions are subclasses of AuthenticationFailure so, in practice,
  callers should catch the types of authentication failure that they care
  about, then have a :class:`~stem.connection.AuthenticationFailure` catch-all
  at the end.

  This can authenticate to either a :class:`~stem.control.BaseController` or
  :class:`~stem.socket.ControlSocket`.

  :param controller: tor controller or socket to be authenticated
  :param str password: passphrase to present to the socket if it uses password
    authentication (skips password auth if **None**)
  :param str chroot_path: path prefix if in a chroot environment
  :param stem.response.protocolinfo.ProtocolInfoResponse protocolinfo_response:
    tor protocolinfo response, this is retrieved on our own if **None**

  :raises: If all attempts to authenticate fails then this will raise a
    :class:`~stem.connection.AuthenticationFailure` subclass. Since this may
    try multiple authentication methods it may encounter multiple exceptions.
    If so then the exception this raises is prioritized as follows...

    * :class:`stem.connection.IncorrectSocketType`

      The controller does not speak the tor control protocol. Most often this
      happened because the user confused the SocksPort or ORPort with the
      ControlPort.

    * :class:`stem.connection.UnrecognizedAuthMethods`

      All of the authentication methods tor will accept are new and
      unrecognized. Please upgrade stem and, if that doesn't work, file a
      ticket on 'trac.torproject.org' and I'd be happy to add support.

    * :class:`stem.connection.MissingPassword`

      We were unable to authenticate but didn't attempt password authentication
      because none was provided. You should prompt the user for a password and
      try again via 'authenticate_password'.

    * :class:`stem.connection.IncorrectPassword`

      We were provided with a password but it was incorrect.

    * :class:`stem.connection.IncorrectCookieSize`

      Tor allows for authentication by reading it a cookie file, but that file
      is the wrong size to be an authentication cookie.

    * :class:`stem.connection.UnreadableCookieFile`

      Tor allows for authentication by reading it a cookie file, but we can't
      read that file (probably due to permissions).

    * **\***:class:`stem.connection.IncorrectCookieValue`

      Tor allows for authentication by reading it a cookie file, but rejected
      the contents of that file.

    * **\***:class:`stem.connection.AuthChallengeUnsupported`

      Tor doesn't recognize the AUTHCHALLENGE command. This is probably a Tor
      version prior to SAFECOOKIE being implement, but this exception shouldn't
      arise because we won't attempt SAFECOOKIE auth unless Tor claims to
      support it.

    * **\***:class:`stem.connection.UnrecognizedAuthChallengeMethod`

      Tor couldn't recognize the AUTHCHALLENGE method Stem sent to it. This
      shouldn't happen at all.

    * **\***:class:`stem.connection.InvalidClientNonce`

      Tor says that the client nonce provided by Stem during the AUTHCHALLENGE
      process is invalid.

    * **\***:class:`stem.connection.AuthSecurityFailure`

      Nonce value provided by the server was invalid.

    * **\***:class:`stem.connection.OpenAuthRejected`

      Tor says that it allows for authentication without any credentials, but
      then rejected our authentication attempt.

    * **\***:class:`stem.connection.MissingAuthInfo`

      Tor provided us with a PROTOCOLINFO reply that is technically valid, but
      missing the information we need to authenticate.

    * **\***:class:`stem.connection.AuthenticationFailure`

      There are numerous other ways that authentication could have failed
      including socket failures, malformed controller responses, etc. These
      mostly constitute transient failures or bugs.

    **\*** In practice it is highly unusual for this to occur, being more of a
    theoretical possibility rather than something you should expect. It's fine
    to treat these as errors. If you have a use case where this commonly
    happens, please file a ticket on 'trac.torproject.org'.

    In the future new :class:`~stem.connection.AuthenticationFailure`
    subclasses may be added to allow for better error handling.
  """

  if not protocolinfo_response:
    try:
      protocolinfo_response = get_protocolinfo(controller)
    except stem.ProtocolError:
      raise IncorrectSocketType('unable to use the control socket')
    except stem.SocketError as exc:
      raise AuthenticationFailure('socket connection failed (%s)' % exc)

  auth_methods = list(protocolinfo_response.auth_methods)
  auth_exceptions = []

  if len(auth_methods) == 0:
    raise NoAuthMethods('our PROTOCOLINFO response did not have any methods for authenticating')

  # remove authentication methods that are either unknown or for which we don't
  # have an input
  if AuthMethod.UNKNOWN in auth_methods:
    auth_methods.remove(AuthMethod.UNKNOWN)

    unknown_methods = protocolinfo_response.unknown_auth_methods
    plural_label = 's' if len(unknown_methods) > 1 else ''
    methods_label = ', '.join(unknown_methods)

    # we... er, can't do anything with only unrecognized auth types
    if not auth_methods:
      exc_msg = 'unrecognized authentication method%s (%s)' % (plural_label, methods_label)
      auth_exceptions.append(UnrecognizedAuthMethods(exc_msg, unknown_methods))
    else:
      log.debug('Authenticating to a socket with unrecognized auth method%s, ignoring them: %s' % (plural_label, methods_label))

  if protocolinfo_response.cookie_path is None:
    for cookie_auth_method in (AuthMethod.COOKIE, AuthMethod.SAFECOOKIE):
      if cookie_auth_method in auth_methods:
        auth_methods.remove(cookie_auth_method)

        exc_msg = 'our PROTOCOLINFO response did not have the location of our authentication cookie'
        auth_exceptions.append(NoAuthCookie(exc_msg, cookie_auth_method == AuthMethod.SAFECOOKIE))

  if AuthMethod.PASSWORD in auth_methods and password is None:
    auth_methods.remove(AuthMethod.PASSWORD)
    auth_exceptions.append(MissingPassword('no passphrase provided'))

  # iterating over AuthMethods so we can try them in this order
  for auth_type in (AuthMethod.NONE, AuthMethod.PASSWORD, AuthMethod.SAFECOOKIE, AuthMethod.COOKIE):
    if auth_type not in auth_methods:
      continue

    try:
      if auth_type == AuthMethod.NONE:
        authenticate_none(controller, False)
      elif auth_type == AuthMethod.PASSWORD:
        authenticate_password(controller, password, False)
      elif auth_type in (AuthMethod.COOKIE, AuthMethod.SAFECOOKIE):
        cookie_path = protocolinfo_response.cookie_path

        if chroot_path:
          cookie_path = os.path.join(chroot_path, cookie_path.lstrip(os.path.sep))

        if auth_type == AuthMethod.SAFECOOKIE:
          authenticate_safecookie(controller, cookie_path, False)
        else:
          authenticate_cookie(controller, cookie_path, False)

      return  # success!
    except OpenAuthRejected as exc:
      auth_exceptions.append(exc)
    except IncorrectPassword as exc:
      auth_exceptions.append(exc)
    except PasswordAuthRejected as exc:
      # Since the PROTOCOLINFO says password auth is available we can assume
      # that if PasswordAuthRejected is raised it's being raised in error.
      log.debug('The authenticate_password method raised a PasswordAuthRejected when password auth should be available. Stem may need to be corrected to recognize this response: %s' % exc)
      auth_exceptions.append(IncorrectPassword(str(exc)))
    except AuthSecurityFailure as exc:
      log.info('Tor failed to provide the nonce expected for safecookie authentication. (%s)' % exc)
      auth_exceptions.append(exc)
    except (InvalidClientNonce, UnrecognizedAuthChallengeMethod, AuthChallengeFailed) as exc:
      auth_exceptions.append(exc)
    except (IncorrectCookieSize, UnreadableCookieFile, IncorrectCookieValue) as exc:
      auth_exceptions.append(exc)
    except CookieAuthRejected as exc:
      auth_func = 'authenticate_safecookie' if exc.is_safecookie else 'authenticate_cookie'

      log.debug('The %s method raised a CookieAuthRejected when cookie auth should be available. Stem may need to be corrected to recognize this response: %s' % (auth_func, exc))
      auth_exceptions.append(IncorrectCookieValue(str(exc), exc.cookie_path, exc.is_safecookie))
    except stem.ControllerError as exc:
      auth_exceptions.append(AuthenticationFailure(str(exc)))

  # All authentication attempts failed. Raise the exception that takes priority
  # according to our pydocs.

  for exc_type in AUTHENTICATE_EXCEPTIONS:
    for auth_exc in auth_exceptions:
      if isinstance(auth_exc, exc_type):
        raise auth_exc

  # We really, really shouldn't get here. It means that auth_exceptions is
  # either empty or contains something that isn't an AuthenticationFailure.

  raise AssertionError('BUG: Authentication failed without providing a recognized exception: %s' % str(auth_exceptions))


def authenticate_none(controller, suppress_ctl_errors = True):
  """
  Authenticates to an open control socket. All control connections need to
  authenticate before they can be used, even if tor hasn't been configured to
  use any authentication.

  If authentication fails tor will disconnect and we'll make a best effort
  attempt to re-establish the connection. This may not succeed, so check
  :func:`~stem.socket.ControlSocket.is_alive` before using the socket further.

  This can authenticate to either a :class:`~stem.control.BaseController` or
  :class:`~stem.socket.ControlSocket`.

  For general usage use the :func:`~stem.connection.authenticate` function
  instead.

  :param controller: tor controller or socket to be authenticated
  :param bool suppress_ctl_errors: reports raised
    :class:`~stem.ControllerError` as authentication rejection if
    **True**, otherwise they're re-raised

  :raises: :class:`stem.connection.OpenAuthRejected` if the empty authentication credentials aren't accepted
  """

  try:
    auth_response = _msg(controller, 'AUTHENTICATE')

    # if we got anything but an OK response then error
    if str(auth_response) != 'OK':
      try:
        controller.connect()
      except:
        pass

      raise OpenAuthRejected(str(auth_response), auth_response)
  except stem.ControllerError as exc:
    try:
      controller.connect()
    except:
      pass

    if not suppress_ctl_errors:
      raise exc
    else:
      raise OpenAuthRejected('Socket failed (%s)' % exc)


def authenticate_password(controller, password, suppress_ctl_errors = True):
  """
  Authenticates to a control socket that uses a password (via the
  HashedControlPassword torrc option). Quotes in the password are escaped.

  If authentication fails tor will disconnect and we'll make a best effort
  attempt to re-establish the connection. This may not succeed, so check
  :func:`~stem.socket.ControlSocket.is_alive` before using the socket further.

  If you use this function directly, rather than
  :func:`~stem.connection.authenticate`, we may mistakenly raise a
  PasswordAuthRejected rather than IncorrectPassword. This is because we rely
  on tor's error messaging which is liable to change in future versions
  (:trac:`4817`).

  This can authenticate to either a :class:`~stem.control.BaseController` or
  :class:`~stem.socket.ControlSocket`.

  For general usage use the :func:`~stem.connection.authenticate` function
  instead.

  :param controller: tor controller or socket to be authenticated
  :param str password: passphrase to present to the socket
  :param bool suppress_ctl_errors: reports raised
    :class:`~stem.ControllerError` as authentication rejection if
    **True**, otherwise they're re-raised

  :raises:
    * :class:`stem.connection.PasswordAuthRejected` if the socket doesn't
      accept password authentication
    * :class:`stem.connection.IncorrectPassword` if the authentication
      credentials aren't accepted
  """

  # Escapes quotes. Tor can include those in the password hash, in which case
  # it expects escaped quotes from the controller. For more information see...
  # https://trac.torproject.org/projects/tor/ticket/4600

  password = password.replace('"', '\\"')

  try:
    auth_response = _msg(controller, 'AUTHENTICATE "%s"' % password)

    # if we got anything but an OK response then error
    if str(auth_response) != 'OK':
      try:
        controller.connect()
      except:
        pass

      # all we have to go on is the error message from tor...
      # Password did not match HashedControlPassword value value from configuration...
      # Password did not match HashedControlPassword *or*...

      if 'Password did not match HashedControlPassword' in str(auth_response):
        raise IncorrectPassword(str(auth_response), auth_response)
      else:
        raise PasswordAuthRejected(str(auth_response), auth_response)
  except stem.ControllerError as exc:
    try:
      controller.connect()
    except:
      pass

    if not suppress_ctl_errors:
      raise exc
    else:
      raise PasswordAuthRejected('Socket failed (%s)' % exc)


def authenticate_cookie(controller, cookie_path, suppress_ctl_errors = True):
  """
  Authenticates to a control socket that uses the contents of an authentication
  cookie (generated via the CookieAuthentication torrc option). This does basic
  validation that this is a cookie before presenting the contents to the
  socket.

  The :class:`~stem.connection.IncorrectCookieSize` and
  :class:`~stem.connection.UnreadableCookieFile` exceptions take precedence
  over the other types.

  If authentication fails tor will disconnect and we'll make a best effort
  attempt to re-establish the connection. This may not succeed, so check
  :func:`~stem.socket.ControlSocket.is_alive` before using the socket further.

  If you use this function directly, rather than
  :func:`~stem.connection.authenticate`, we may mistakenly raise a
  :class:`~stem.connection.CookieAuthRejected` rather than
  :class:`~stem.connection.IncorrectCookieValue`. This is because we rely on
  tor's error messaging which is liable to change in future versions
  (:trac:`4817`).

  This can authenticate to either a :class:`~stem.control.BaseController` or
  :class:`~stem.socket.ControlSocket`.

  For general usage use the :func:`~stem.connection.authenticate` function
  instead.

  :param controller: tor controller or socket to be authenticated
  :param str cookie_path: path of the authentication cookie to send to tor
  :param bool suppress_ctl_errors: reports raised
    :class:`~stem.ControllerError` as authentication rejection if
    **True**, otherwise they're re-raised

  :raises:
    * :class:`stem.connection.IncorrectCookieSize` if the cookie file's size
      is wrong
    * :class:`stem.connection.UnreadableCookieFile` if the cookie file doesn't
      exist or we're unable to read it
    * :class:`stem.connection.CookieAuthRejected` if cookie authentication is
      attempted but the socket doesn't accept it
    * :class:`stem.connection.IncorrectCookieValue` if the cookie file's value
      is rejected
  """

  cookie_data = _read_cookie(cookie_path, False)

  try:
    # binascii.b2a_hex() takes a byte string and returns one too. With python 3
    # this is a problem because string formatting for byte strings includes the
    # b'' wrapper...
    #
    #   >>> "AUTHENTICATE %s" % b'content'
    #   "AUTHENTICATE b'content'"
    #
    # This seems dumb but oh well. Converting the result to unicode so it won't
    # misbehave.

    auth_token_hex = binascii.b2a_hex(stem.util.str_tools._to_bytes(cookie_data))
    msg = 'AUTHENTICATE %s' % stem.util.str_tools._to_unicode(auth_token_hex)
    auth_response = _msg(controller, msg)

    # if we got anything but an OK response then error
    if str(auth_response) != 'OK':
      try:
        controller.connect()
      except:
        pass

      # all we have to go on is the error message from tor...
      # ... Authentication cookie did not match expected value.
      # ... *or* authentication cookie.

      if '*or* authentication cookie.' in str(auth_response) or \
         'Authentication cookie did not match expected value.' in str(auth_response):
        raise IncorrectCookieValue(str(auth_response), cookie_path, False, auth_response)
      else:
        raise CookieAuthRejected(str(auth_response), cookie_path, False, auth_response)
  except stem.ControllerError as exc:
    try:
      controller.connect()
    except:
      pass

    if not suppress_ctl_errors:
      raise exc
    else:
      raise CookieAuthRejected('Socket failed (%s)' % exc, cookie_path, False)


def authenticate_safecookie(controller, cookie_path, suppress_ctl_errors = True):
  """
  Authenticates to a control socket using the safe cookie method, which is
  enabled by setting the CookieAuthentication torrc option on Tor client's which
  support it.

  Authentication with this is a two-step process...

  1. send a nonce to the server and receives a challenge from the server for
     the cookie's contents
  2. generate a hash digest using the challenge received in the first step, and
     use it to authenticate the controller

  The :class:`~stem.connection.IncorrectCookieSize` and
  :class:`~stem.connection.UnreadableCookieFile` exceptions take precedence
  over the other exception types.

  The :class:`~stem.connection.AuthChallengeUnsupported`,
  :class:`~stem.connection.UnrecognizedAuthChallengeMethod`,
  :class:`~stem.connection.InvalidClientNonce` and
  :class:`~stem.connection.CookieAuthRejected` exceptions are next in the order
  of precedence. Depending on the reason, one of these is raised if the first
  (AUTHCHALLENGE) step fails.

  In the second (AUTHENTICATE) step,
  :class:`~stem.connection.IncorrectCookieValue` or
  :class:`~stem.connection.CookieAuthRejected` maybe raised.

  If authentication fails tor will disconnect and we'll make a best effort
  attempt to re-establish the connection. This may not succeed, so check
  :func:`~stem.socket.ControlSocket.is_alive` before using the socket further.

  For general usage use the :func:`~stem.connection.authenticate` function
  instead.

  :param controller: tor controller or socket to be authenticated
  :param str cookie_path: path of the authentication cookie to send to tor
  :param bool suppress_ctl_errors: reports raised
    :class:`~stem.ControllerError` as authentication rejection if
    **True**, otherwise they're re-raised

  :raises:
    * :class:`stem.connection.IncorrectCookieSize` if the cookie file's size
      is wrong
    * :class:`stem.connection.UnreadableCookieFile` if the cookie file doesn't
      exist or we're unable to read it
    * :class:`stem.connection.CookieAuthRejected` if cookie authentication is
      attempted but the socket doesn't accept it
    * :class:`stem.connection.IncorrectCookieValue` if the cookie file's value
      is rejected
    * :class:`stem.connection.UnrecognizedAuthChallengeMethod` if the Tor
      client fails to recognize the AuthChallenge method
    * :class:`stem.connection.AuthChallengeUnsupported` if AUTHCHALLENGE is
      unimplemented, or if unable to parse AUTHCHALLENGE response
    * :class:`stem.connection.AuthSecurityFailure` if AUTHCHALLENGE's response
      looks like a security attack
    * :class:`stem.connection.InvalidClientNonce` if stem's AUTHCHALLENGE
      client nonce is rejected for being invalid
  """

  cookie_data = _read_cookie(cookie_path, True)
  client_nonce = os.urandom(32)

  try:
    client_nonce_hex = stem.util.str_tools._to_unicode(binascii.b2a_hex(client_nonce))
    authchallenge_response = _msg(controller, 'AUTHCHALLENGE SAFECOOKIE %s' % client_nonce_hex)

    if not authchallenge_response.is_ok():
      try:
        controller.connect()
      except:
        pass

      authchallenge_response_str = str(authchallenge_response)

      if 'Authentication required.' in authchallenge_response_str:
        raise AuthChallengeUnsupported("SAFECOOKIE authentication isn't supported", cookie_path)
      elif 'AUTHCHALLENGE only supports' in authchallenge_response_str:
        raise UnrecognizedAuthChallengeMethod(authchallenge_response_str, cookie_path)
      elif 'Invalid base16 client nonce' in authchallenge_response_str:
        raise InvalidClientNonce(authchallenge_response_str, cookie_path)
      elif 'Cookie authentication is disabled' in authchallenge_response_str:
        raise CookieAuthRejected(authchallenge_response_str, cookie_path, True)
      else:
        raise AuthChallengeFailed(authchallenge_response, cookie_path)
  except stem.ControllerError as exc:
    try:
      controller.connect()
    except:
      pass

    if not suppress_ctl_errors:
      raise exc
    else:
      raise AuthChallengeFailed('Socket failed (%s)' % exc, cookie_path, True)

  try:
    stem.response.convert('AUTHCHALLENGE', authchallenge_response)
  except stem.ProtocolError as exc:
    if not suppress_ctl_errors:
      raise exc
    else:
      raise AuthChallengeFailed('Unable to parse AUTHCHALLENGE response: %s' % exc, cookie_path)

  expected_server_hash = stem.util.connection._hmac_sha256(
    SERVER_HASH_CONSTANT,
    cookie_data + client_nonce + authchallenge_response.server_nonce)

  if not stem.util.connection._cryptovariables_equal(authchallenge_response.server_hash, expected_server_hash):
    raise AuthSecurityFailure('Tor provided the wrong server nonce', cookie_path)

  try:
    client_hash = stem.util.connection._hmac_sha256(
      CLIENT_HASH_CONSTANT,
      cookie_data + client_nonce + authchallenge_response.server_nonce)

    auth_response = _msg(controller, 'AUTHENTICATE %s' % stem.util.str_tools._to_unicode(binascii.b2a_hex(client_hash)))
  except stem.ControllerError as exc:
    try:
      controller.connect()
    except:
      pass

    if not suppress_ctl_errors:
      raise exc
    else:
      raise CookieAuthRejected('Socket failed (%s)' % exc, cookie_path, True, auth_response)

  # if we got anything but an OK response then err
  if not auth_response.is_ok():
    try:
      controller.connect()
    except:
      pass

    # all we have to go on is the error message from tor...
    # ... Safe cookie response did not match expected value
    # ... *or* authentication cookie.

    if '*or* authentication cookie.' in str(auth_response) or \
       'Safe cookie response did not match expected value' in str(auth_response):
      raise IncorrectCookieValue(str(auth_response), cookie_path, True, auth_response)
    else:
      raise CookieAuthRejected(str(auth_response), cookie_path, True, auth_response)


def get_protocolinfo(controller):
  """
  Issues a PROTOCOLINFO query to a control socket, getting information about
  the tor process running on it. If the socket is already closed then it is
  first reconnected.

  According to the control spec the cookie_file is an absolute path. However,
  this often is not the case (especially for the Tor Browser Bundle). If the
  path is relative then we'll make an attempt (which may not work) to correct
  this (:trac:`1101`).

  This can authenticate to either a :class:`~stem.control.BaseController` or
  :class:`~stem.socket.ControlSocket`.

  :param controller: tor controller or socket to be queried

  :returns: :class:`~stem.response.protocolinfo.ProtocolInfoResponse` provided by tor

  :raises:
    * :class:`stem.ProtocolError` if the PROTOCOLINFO response is
      malformed
    * :class:`stem.SocketError` if problems arise in establishing or
      using the socket
  """

  try:
    protocolinfo_response = _msg(controller, 'PROTOCOLINFO 1')
  except:
    protocolinfo_response = None

  # Tor hangs up on sockets after receiving a PROTOCOLINFO query if it isn't
  # next followed by authentication. Transparently reconnect if that happens.

  if not protocolinfo_response or str(protocolinfo_response) == 'Authentication required.':
    controller.connect()

    try:
      protocolinfo_response = _msg(controller, 'PROTOCOLINFO 1')
    except stem.SocketClosed as exc:
      raise stem.SocketError(exc)

  stem.response.convert('PROTOCOLINFO', protocolinfo_response)

  # attempt to expand relative cookie paths

  if protocolinfo_response.cookie_path:
    _expand_cookie_path(protocolinfo_response, stem.util.system.pid_by_name, 'tor')

  # attempt to expand relative cookie paths via the control port or socket file

  if isinstance(controller, stem.socket.ControlSocket):
    control_socket = controller
  else:
    control_socket = controller.get_socket()

  if isinstance(control_socket, stem.socket.ControlPort):
    if control_socket.get_address() == '127.0.0.1':
      pid_method = stem.util.system.pid_by_port
      _expand_cookie_path(protocolinfo_response, pid_method, control_socket.get_port())
  elif isinstance(control_socket, stem.socket.ControlSocketFile):
    pid_method = stem.util.system.pid_by_open_file
    _expand_cookie_path(protocolinfo_response, pid_method, control_socket.get_socket_path())

  return protocolinfo_response


def _msg(controller, message):
  """
  Sends and receives a message with either a
  :class:`~stem.socket.ControlSocket` or :class:`~stem.control.BaseController`.
  """

  if isinstance(controller, stem.socket.ControlSocket):
    controller.send(message)
    return controller.recv()
  else:
    return controller.msg(message)


def _read_cookie(cookie_path, is_safecookie):
  """
  Provides the contents of a given cookie file.

  :param str cookie_path: absolute path of the cookie file
  :param bool is_safecookie: **True** if this was for SAFECOOKIE
    authentication, **False** if for COOKIE

  :raises:
    * :class:`stem.connection.UnreadableCookieFile` if the cookie file is
      unreadable
    * :class:`stem.connection.IncorrectCookieSize` if the cookie size is
      incorrect (not 32 bytes)
  """

  if not os.path.exists(cookie_path):
    exc_msg = "Authentication failed: '%s' doesn't exist" % cookie_path
    raise UnreadableCookieFile(exc_msg, cookie_path, is_safecookie)

  # Abort if the file isn't 32 bytes long. This is to avoid exposing arbitrary
  # file content to the port.
  #
  # Without this a malicious socket could, for instance, claim that
  # '~/.bash_history' or '~/.ssh/id_rsa' was its authentication cookie to trick
  # us into reading it for them with our current permissions.
  #
  # https://trac.torproject.org/projects/tor/ticket/4303

  auth_cookie_size = os.path.getsize(cookie_path)

  if auth_cookie_size != 32:
    exc_msg = "Authentication failed: authentication cookie '%s' is the wrong size (%i bytes instead of 32)" % (cookie_path, auth_cookie_size)
    raise IncorrectCookieSize(exc_msg, cookie_path, is_safecookie)

  try:
    with open(cookie_path, 'rb', 0) as f:
      return f.read()
  except IOError as exc:
    exc_msg = "Authentication failed: unable to read '%s' (%s)" % (cookie_path, exc)
    raise UnreadableCookieFile(exc_msg, cookie_path, is_safecookie)


def _expand_cookie_path(protocolinfo_response, pid_resolver, pid_resolution_arg):
  """
  Attempts to expand a relative cookie path with the given pid resolver. This
  leaves the cookie_path alone if it's already absolute, **None**, or the
  system calls fail.
  """

  cookie_path = protocolinfo_response.cookie_path
  if cookie_path and not os.path.isabs(cookie_path):
    try:
      tor_pid = pid_resolver(pid_resolution_arg)

      if not tor_pid:
        raise IOError('pid lookup failed')

      tor_cwd = stem.util.system.cwd(tor_pid)

      if not tor_cwd:
        raise IOError('cwd lookup failed')

      cookie_path = stem.util.system.expand_path(cookie_path, tor_cwd)
    except IOError as exc:
      resolver_labels = {
        stem.util.system.pid_by_name: ' by name',
        stem.util.system.pid_by_port: ' by port',
        stem.util.system.pid_by_open_file: ' by socket file',
      }

      pid_resolver_label = resolver_labels.get(pid_resolver, '')
      log.debug('unable to expand relative tor cookie path%s: %s' % (pid_resolver_label, exc))

  protocolinfo_response.cookie_path = cookie_path


class AuthenticationFailure(Exception):
  """
  Base error for authentication failures.

  :var stem.socket.ControlMessage auth_response: AUTHENTICATE response from the
    control socket, **None** if one wasn't received
  """

  def __init__(self, message, auth_response = None):
    super(AuthenticationFailure, self).__init__(message)
    self.auth_response = auth_response


class UnrecognizedAuthMethods(AuthenticationFailure):
  """
  All methods for authenticating aren't recognized.

  :var list unknown_auth_methods: authentication methods that weren't recognized
  """

  def __init__(self, message, unknown_auth_methods):
    super(UnrecognizedAuthMethods, self).__init__(message)
    self.unknown_auth_methods = unknown_auth_methods


class IncorrectSocketType(AuthenticationFailure):
  'Socket does not speak the control protocol.'


class OpenAuthFailed(AuthenticationFailure):
  'Failure to authenticate to an open socket.'


class OpenAuthRejected(OpenAuthFailed):
  'Attempt to connect to an open control socket was rejected.'


class PasswordAuthFailed(AuthenticationFailure):
  'Failure to authenticate with a password.'


class PasswordAuthRejected(PasswordAuthFailed):
  'Socket does not support password authentication.'


class IncorrectPassword(PasswordAuthFailed):
  'Authentication password incorrect.'


class MissingPassword(PasswordAuthFailed):
  "Password authentication is supported but we weren't provided with one."


class CookieAuthFailed(AuthenticationFailure):
  """
  Failure to authenticate with an authentication cookie.

  :param str cookie_path: location of the authentication cookie we attempted
  :param bool is_safecookie: **True** if this was for SAFECOOKIE
    authentication, **False** if for COOKIE
  :param stem.response.ControlMessage auth_response: reply to our
    authentication attempt
  """

  def __init__(self, message, cookie_path, is_safecookie, auth_response = None):
    super(CookieAuthFailed, self).__init__(message, auth_response)
    self.is_safecookie = is_safecookie
    self.cookie_path = cookie_path


class CookieAuthRejected(CookieAuthFailed):
  'Socket does not support password authentication.'


class IncorrectCookieValue(CookieAuthFailed):
  'Authentication cookie value was rejected.'


class IncorrectCookieSize(CookieAuthFailed):
  'Aborted because the cookie file is the wrong size.'


class UnreadableCookieFile(CookieAuthFailed):
  'Error arose in reading the authentication cookie.'


class AuthChallengeFailed(CookieAuthFailed):
  """
  AUTHCHALLENGE command has failed.
  """

  def __init__(self, message, cookie_path):
    super(AuthChallengeFailed, self).__init__(message, cookie_path, True)


class AuthChallengeUnsupported(AuthChallengeFailed):
  """
  AUTHCHALLENGE isn't implemented.
  """


class UnrecognizedAuthChallengeMethod(AuthChallengeFailed):
  """
  Tor couldn't recognize our AUTHCHALLENGE method.

  :var str authchallenge_method: AUTHCHALLENGE method that Tor couldn't recognize
  """

  def __init__(self, message, cookie_path, authchallenge_method):
    super(UnrecognizedAuthChallengeMethod, self).__init__(message, cookie_path)
    self.authchallenge_method = authchallenge_method


class AuthSecurityFailure(AuthChallengeFailed):
  'AUTHCHALLENGE response is invalid.'


class InvalidClientNonce(AuthChallengeFailed):
  'AUTHCHALLENGE request contains an invalid client nonce.'


class MissingAuthInfo(AuthenticationFailure):
  """
  The PROTOCOLINFO response didn't have enough information to authenticate.
  These are valid control responses but really shouldn't happen in practice.
  """


class NoAuthMethods(MissingAuthInfo):
  "PROTOCOLINFO response didn't have any methods for authenticating."


class NoAuthCookie(MissingAuthInfo):
  """
  PROTOCOLINFO response supports cookie auth but doesn't have its path.

  :param bool is_safecookie: **True** if this was for SAFECOOKIE
    authentication, **False** if for COOKIE
  """

  def __init__(self, message, is_safecookie):
    super(NoAuthCookie, self).__init__(message)
    self.is_safecookie = is_safecookie

# authentication exceptions ordered as per the authenticate function's pydocs
AUTHENTICATE_EXCEPTIONS = (
  IncorrectSocketType,
  UnrecognizedAuthMethods,
  MissingPassword,
  IncorrectPassword,
  IncorrectCookieSize,
  UnreadableCookieFile,
  IncorrectCookieValue,
  AuthChallengeUnsupported,
  UnrecognizedAuthChallengeMethod,
  InvalidClientNonce,
  AuthSecurityFailure,
  OpenAuthRejected,
  MissingAuthInfo,
  AuthenticationFailure
)
