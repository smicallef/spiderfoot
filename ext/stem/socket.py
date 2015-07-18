# Copyright 2011-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Supports communication with sockets speaking the Tor control protocol. This
allows us to send messages as basic strings, and receive responses as
:class:`~stem.response.ControlMessage` instances.

**This module only consists of low level components, and is not intended for
users.** See our `tutorials <../tutorials.html>`_ and `Control Module
<control.html>`_ if you're new to Stem and looking to get started.

With that aside, these can still be used for raw socket communication with
Tor...

::

  import stem
  import stem.connection
  import stem.socket

  if __name__ == '__main__':
    try:
      control_socket = stem.socket.ControlPort(port = 9051)
      stem.connection.authenticate(control_socket)
    except stem.SocketError as exc:
      print 'Unable to connect to tor on port 9051: %s' % exc
      sys.exit(1)
    except stem.connection.AuthenticationFailure as exc:
      print 'Unable to authenticate: %s' % exc
      sys.exit(1)

    print "Issuing 'GETINFO version' query...\\n"
    control_socket.send('GETINFO version')
    print control_socket.recv()

::

  % python example.py
  Issuing 'GETINFO version' query...

  version=0.2.4.10-alpha-dev (git-8be6058d8f31e578)
  OK

**Module Overview:**

::

  ControlSocket - Socket wrapper that speaks the tor control protocol.
    |- ControlPort - Control connection via a port.
    |  |- get_address - provides the ip address of our socket
    |  +- get_port - provides the port of our socket
    |
    |- ControlSocketFile - Control connection via a local file socket.
    |  +- get_socket_path - provides the path of the socket we connect to
    |
    |- send - sends a message to the socket
    |- recv - receives a ControlMessage from the socket
    |- is_alive - reports if the socket is known to be closed
    |- is_localhost - returns if the socket is for the local system or not
    |- connect - connects a new socket
    |- close - shuts down the socket
    +- __enter__ / __exit__ - manages socket connection

  send_message - Writes a message to a control socket.
  recv_message - Reads a ControlMessage from a control socket.
  send_formatting - Performs the formatting expected from sent messages.
"""

from __future__ import absolute_import

import re
import socket
import threading
import time

import stem.prereq
import stem.response
import stem.util.str_tools

from stem.util import log


class ControlSocket(object):
  """
  Wrapper for a socket connection that speaks the Tor control protocol. To the
  better part this transparently handles the formatting for sending and
  receiving complete messages. All methods are thread safe.

  Callers should not instantiate this class directly, but rather use subclasses
  which are expected to implement the **_make_socket()** method.
  """

  def __init__(self):
    self._socket, self._socket_file = None, None
    self._is_alive = False
    self._connection_time = 0.0  # time when we last connected or disconnected

    # Tracks sending and receiving separately. This should be safe, and doing
    # so prevents deadlock where we block writes because we're waiting to read
    # a message that isn't coming.

    self._send_lock = threading.RLock()
    self._recv_lock = threading.RLock()

  def send(self, message, raw = False):
    """
    Formats and sends a message to the control socket. For more information see
    the :func:`~stem.socket.send_message` function.

    :param str message: message to be formatted and sent to the socket
    :param bool raw: leaves the message formatting untouched, passing it to the socket as-is

    :raises:
      * :class:`stem.SocketError` if a problem arises in using the socket
      * :class:`stem.SocketClosed` if the socket is known to be shut down
    """

    with self._send_lock:
      try:
        if not self.is_alive():
          raise stem.SocketClosed()

        send_message(self._socket_file, message, raw)
      except stem.SocketClosed as exc:
        # if send_message raises a SocketClosed then we should properly shut
        # everything down

        if self.is_alive():
          self.close()

        raise exc

  def recv(self):
    """
    Receives a message from the control socket, blocking until we've received
    one. For more information see the :func:`~stem.socket.recv_message` function.

    :returns: :class:`~stem.response.ControlMessage` for the message received

    :raises:
      * :class:`stem.ProtocolError` the content from the socket is malformed
      * :class:`stem.SocketClosed` if the socket closes before we receive a complete message
    """

    with self._recv_lock:
      try:
        # makes a temporary reference to the _socket_file because connect()
        # and close() may set or unset it

        socket_file = self._socket_file

        if not socket_file:
          raise stem.SocketClosed()

        return recv_message(socket_file)
      except stem.SocketClosed as exc:
        # If recv_message raises a SocketClosed then we should properly shut
        # everything down. However, there's a couple cases where this will
        # cause deadlock...
        #
        # * this socketClosed was *caused by* a close() call, which is joining
        #   on our thread
        #
        # * a send() call that's currently in flight is about to call close(),
        #   also attempting to join on us
        #
        # To resolve this we make a non-blocking call to acquire the send lock.
        # If we get it then great, we can close safely. If not then one of the
        # above are in progress and we leave the close to them.

        if self.is_alive():
          if self._send_lock.acquire(False):
            self.close()
            self._send_lock.release()

        raise exc

  def is_alive(self):
    """
    Checks if the socket is known to be closed. We won't be aware if it is
    until we either use it or have explicitily shut it down.

    In practice a socket derived from a port knows about its disconnection
    after a failed :func:`~stem.socket.ControlSocket.recv` call. Socket file
    derived connections know after either a
    :func:`~stem.socket.ControlSocket.send` or
    :func:`~stem.socket.ControlSocket.recv`.

    This means that to have reliable detection for when we're disconnected
    you need to continually pull from the socket (which is part of what the
    :class:`~stem.control.BaseController` does).

    :returns: **bool** that's **True** if our socket is connected and **False** otherwise
    """

    return self._is_alive

  def is_localhost(self):
    """
    Returns if the connection is for the local system or not.

    :returns: **bool** that's **True** if the connection is for the local host and **False** otherwise
    """

    return False

  def connection_time(self):
    """
    Provides the unix timestamp for when our socket was either connected or
    disconnected. That is to say, the time we connected if we're currently
    connected and the time we disconnected if we're not connected.

    .. versionadded:: 1.3.0

    :returns: **float** for when we last connected or disconnected, zero if
      we've never connected
    """

    return self._connection_time

  def connect(self):
    """
    Connects to a new socket, closing our previous one if we're already
    attached.

    :raises: :class:`stem.SocketError` if unable to make a socket
    """

    with self._send_lock:
      # Closes the socket if we're currently attached to one. Once we're no
      # longer alive it'll be safe to acquire the recv lock because recv()
      # calls no longer block (raising SocketClosed instead).

      if self.is_alive():
        self.close()

      with self._recv_lock:
        self._socket = self._make_socket()
        self._socket_file = self._socket.makefile(mode = 'rwb')
        self._is_alive = True
        self._connection_time = time.time()

        # It's possible for this to have a transient failure...
        # SocketError: [Errno 4] Interrupted system call
        #
        # It's safe to retry, so give it another try if it fails.

        try:
          self._connect()
        except stem.SocketError:
          self._connect()  # single retry

  def close(self):
    """
    Shuts down the socket. If it's already closed then this is a no-op.
    """

    with self._send_lock:
      # Function is idempotent with one exception: we notify _close() if this
      # is causing our is_alive() state to change.

      is_change = self.is_alive()

      if self._socket:
        # if we haven't yet established a connection then this raises an error
        # socket.error: [Errno 107] Transport endpoint is not connected

        try:
          self._socket.shutdown(socket.SHUT_RDWR)
        except socket.error:
          pass

        # Suppressing unexpected exceptions from close. For instance, if the
        # socket's file has already been closed then with python 2.7 that raises
        # with...
        # error: [Errno 32] Broken pipe

        try:
          self._socket.close()
        except:
          pass

      if self._socket_file:
        try:
          self._socket_file.close()
        except:
          pass

      self._socket = None
      self._socket_file = None
      self._is_alive = False
      self._connection_time = time.time()

      if is_change:
        self._close()

  def _get_send_lock(self):
    """
    The send lock is useful to classes that interact with us at a deep level
    because it's used to lock :func:`stem.socket.ControlSocket.connect` /
    :func:`stem.socket.ControlSocket.close`, and by extension our
    :func:`stem.socket.ControlSocket.is_alive` state changes.

    :returns: **threading.RLock** that governs sending messages to our socket
      and state changes
    """

    return self._send_lock

  def __enter__(self):
    return self

  def __exit__(self, exit_type, value, traceback):
    self.close()

  def _connect(self):
    """
    Connection callback that can be overwritten by subclasses and wrappers.
    """

    pass

  def _close(self):
    """
    Disconnection callback that can be overwritten by subclasses and wrappers.
    """

    pass

  def _make_socket(self):
    """
    Constructs and connects new socket. This is implemented by subclasses.

    :returns: **socket.socket** for our configuration

    :raises:
      * :class:`stem.SocketError` if unable to make a socket
      * **NotImplementedError** if not implemented by a subclass
    """

    raise NotImplementedError('Unsupported Operation: this should be implemented by the ControlSocket subclass')


class ControlPort(ControlSocket):
  """
  Control connection to tor. For more information see tor's ControlPort torrc
  option.
  """

  def __init__(self, address = '127.0.0.1', port = 9051, connect = True):
    """
    ControlPort constructor.

    :param str address: ip address of the controller
    :param int port: port number of the controller
    :param bool connect: connects to the socket if True, leaves it unconnected otherwise

    :raises: :class:`stem.SocketError` if connect is **True** and we're
      unable to establish a connection
    """

    super(ControlPort, self).__init__()
    self._control_addr = address
    self._control_port = port

    if connect:
      self.connect()

  def get_address(self):
    """
    Provides the ip address our socket connects to.

    :returns: str with the ip address of our socket
    """

    return self._control_addr

  def get_port(self):
    """
    Provides the port our socket connects to.

    :returns: int with the port of our socket
    """

    return self._control_port

  def is_localhost(self):
    return self._control_addr == '127.0.0.1'

  def _make_socket(self):
    try:
      control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      control_socket.connect((self._control_addr, self._control_port))
      return control_socket
    except socket.error as exc:
      raise stem.SocketError(exc)


class ControlSocketFile(ControlSocket):
  """
  Control connection to tor. For more information see tor's ControlSocket torrc
  option.
  """

  def __init__(self, path = '/var/run/tor/control', connect = True):
    """
    ControlSocketFile constructor.

    :param str socket_path: path where the control socket is located
    :param bool connect: connects to the socket if True, leaves it unconnected otherwise

    :raises: :class:`stem.SocketError` if connect is **True** and we're
      unable to establish a connection
    """

    super(ControlSocketFile, self).__init__()
    self._socket_path = path

    if connect:
      self.connect()

  def get_socket_path(self):
    """
    Provides the path our socket connects to.

    :returns: str with the path for our control socket
    """

    return self._socket_path

  def is_localhost(self):
    return True

  def _make_socket(self):
    try:
      control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
      control_socket.connect(self._socket_path)
      return control_socket
    except socket.error as exc:
      raise stem.SocketError(exc)


def send_message(control_file, message, raw = False):
  """
  Sends a message to the control socket, adding the expected formatting for
  single verses multi-line messages. Neither message type should contain an
  ending newline (if so it'll be treated as a multi-line message with a blank
  line at the end). If the message doesn't contain a newline then it's sent
  as...

  ::

    <message>\\r\\n

  and if it does contain newlines then it's split on ``\\n`` and sent as...

  ::

    +<line 1>\\r\\n
    <line 2>\\r\\n
    <line 3>\\r\\n
    .\\r\\n

  :param file control_file: file derived from the control socket (see the
    socket's makefile() method for more information)
  :param str message: message to be sent on the control socket
  :param bool raw: leaves the message formatting untouched, passing it to the
    socket as-is

  :raises:
    * :class:`stem.SocketError` if a problem arises in using the socket
    * :class:`stem.SocketClosed` if the socket is known to be shut down
  """

  if not raw:
    message = send_formatting(message)

  try:
    control_file.write(stem.util.str_tools._to_bytes(message))
    control_file.flush()

    log_message = message.replace('\r\n', '\n').rstrip()
    log.trace('Sent to tor:\n' + log_message)
  except socket.error as exc:
    log.info('Failed to send message: %s' % exc)

    # When sending there doesn't seem to be a reliable method for
    # distinguishing between failures from a disconnect verses other things.
    # Just accounting for known disconnection responses.

    if str(exc) == '[Errno 32] Broken pipe':
      raise stem.SocketClosed(exc)
    else:
      raise stem.SocketError(exc)
  except AttributeError:
    # if the control_file has been closed then flush will receive:
    # AttributeError: 'NoneType' object has no attribute 'sendall'

    log.info('Failed to send message: file has been closed')
    raise stem.SocketClosed('file has been closed')


def recv_message(control_file):
  """
  Pulls from a control socket until we either have a complete message or
  encounter a problem.

  :param file control_file: file derived from the control socket (see the
    socket's makefile() method for more information)

  :returns: :class:`~stem.response.ControlMessage` read from the socket

  :raises:
    * :class:`stem.ProtocolError` the content from the socket is malformed
    * :class:`stem.SocketClosed` if the socket closes before we receive
      a complete message
  """

  parsed_content, raw_content = [], b''
  logging_prefix = 'Error while receiving a control message (%s): '

  while True:
    try:
      # From a real socket readline() would always provide bytes, but during
      # tests we might be given a StringIO in which case it's unicode under
      # python 3.x.

      line = stem.util.str_tools._to_bytes(control_file.readline())
    except AttributeError:
      # if the control_file has been closed then we will receive:
      # AttributeError: 'NoneType' object has no attribute 'recv'

      prefix = logging_prefix % 'SocketClosed'
      log.info(prefix + 'socket file has been closed')
      raise stem.SocketClosed('socket file has been closed')
    except (socket.error, ValueError) as exc:
      # When disconnected we get...
      #
      # Python 2:
      #   socket.error: [Errno 107] Transport endpoint is not connected
      #
      # Python 3:
      #   ValueError: I/O operation on closed file.

      prefix = logging_prefix % 'SocketClosed'
      log.info(prefix + 'received exception "%s"' % exc)
      raise stem.SocketClosed(exc)

    raw_content += line

    # Parses the tor control lines. These are of the form...
    # <status code><divider><content>\r\n

    if len(line) == 0:
      # if the socket is disconnected then the readline() method will provide
      # empty content

      prefix = logging_prefix % 'SocketClosed'
      log.info(prefix + 'empty socket content')
      raise stem.SocketClosed('Received empty socket content.')
    elif len(line) < 4:
      prefix = logging_prefix % 'ProtocolError'
      log.info(prefix + 'line too short, "%s"' % log.escape(line))
      raise stem.ProtocolError('Badly formatted reply line: too short')
    elif not re.match(b'^[a-zA-Z0-9]{3}[-+ ]', line):
      prefix = logging_prefix % 'ProtocolError'
      log.info(prefix + 'malformed status code/divider, "%s"' % log.escape(line))
      raise stem.ProtocolError('Badly formatted reply line: beginning is malformed')
    elif not line.endswith(b'\r\n'):
      prefix = logging_prefix % 'ProtocolError'
      log.info(prefix + 'no CRLF linebreak, "%s"' % log.escape(line))
      raise stem.ProtocolError('All lines should end with CRLF')

    line = line[:-2]  # strips off the CRLF
    status_code, divider, content = line[:3], line[3:4], line[4:]

    if stem.prereq.is_python_3():
      status_code = stem.util.str_tools._to_unicode(status_code)
      divider = stem.util.str_tools._to_unicode(divider)

    if divider == '-':
      # mid-reply line, keep pulling for more content
      parsed_content.append((status_code, divider, content))
    elif divider == ' ':
      # end of the message, return the message
      parsed_content.append((status_code, divider, content))

      log_message = raw_content.replace(b'\r\n', b'\n').rstrip()
      log.trace('Received from tor:\n' + stem.util.str_tools._to_unicode(log_message))

      return stem.response.ControlMessage(parsed_content, raw_content)
    elif divider == '+':
      # data entry, all of the following lines belong to the content until we
      # get a line with just a period

      while True:
        try:
          line = stem.util.str_tools._to_bytes(control_file.readline())
        except socket.error as exc:
          prefix = logging_prefix % 'SocketClosed'
          log.info(prefix + 'received an exception while mid-way through a data reply (exception: "%s", read content: "%s")' % (exc, log.escape(raw_content)))
          raise stem.SocketClosed(exc)

        raw_content += line

        if not line.endswith(b'\r\n'):
          prefix = logging_prefix % 'ProtocolError'
          log.info(prefix + 'CRLF linebreaks missing from a data reply, "%s"' % log.escape(raw_content))
          raise stem.ProtocolError('All lines should end with CRLF')
        elif line == b'.\r\n':
          break  # data block termination

        line = line[:-2]  # strips off the CRLF

        # lines starting with a period are escaped by a second period (as per
        # section 2.4 of the control-spec)

        if line.startswith(b'..'):
          line = line[1:]

        # appends to previous content, using a newline rather than CRLF
        # separator (more conventional for multi-line string content outside
        # the windows world)

        content += b'\n' + line

      parsed_content.append((status_code, divider, content))
    else:
      # this should never be reached due to the prefix regex, but might as well
      # be safe...
      prefix = logging_prefix % 'ProtocolError'
      log.warn(prefix + "\"%s\" isn't a recognized divider type" % divider)
      raise stem.ProtocolError("Unrecognized divider type '%s': %s" % (divider, stem.util.str_tools._to_unicode(line)))


def send_formatting(message):
  """
  Performs the formatting expected from sent control messages. For more
  information see the :func:`~stem.socket.send_message` function.

  :param str message: message to be formatted

  :returns: **str** of the message wrapped by the formatting expected from
    controllers
  """

  # From control-spec section 2.2...
  #   Command = Keyword OptArguments CRLF / "+" Keyword OptArguments CRLF CmdData
  #   Keyword = 1*ALPHA
  #   OptArguments = [ SP *(SP / VCHAR) ]
  #
  # A command is either a single line containing a Keyword and arguments, or a
  # multiline command whose initial keyword begins with +, and whose data
  # section ends with a single "." on a line of its own.

  # if we already have \r\n entries then standardize on \n to start with
  message = message.replace('\r\n', '\n')

  if '\n' in message:
    return '+%s\r\n.\r\n' % message.replace('\n', '\r\n')
  else:
    return message + '\r\n'
