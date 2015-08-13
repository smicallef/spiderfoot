# Copyright 2014-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Handles making requests and formatting the responses.
"""

import code
import socket

import stem
import stem.control
import stem.descriptor.remote
import stem.interpreter.help
import stem.util.connection
import stem.util.str_tools
import stem.util.tor_tools

from stem.interpreter import STANDARD_OUTPUT, BOLD_OUTPUT, ERROR_OUTPUT, uses_settings, msg
from stem.util.term import format


def _get_fingerprint(arg, controller):
  """
  Resolves user input into a relay fingerprint. This accepts...

    * Fingerprints
    * Nicknames
    * IPv4 addresses, either with or without an ORPort
    * Empty input, which is resolved to ourselves if we're a relay

  :param str arg: input to be resolved to a relay fingerprint
  :param stem.control.Controller controller: tor control connection

  :returns: **str** for the relay fingerprint

  :raises: **ValueError** if we're unable to resolve the input to a relay
  """

  if not arg:
    try:
      return controller.get_info('fingerprint')
    except:
      raise ValueError("We aren't a relay, no information to provide")
  elif stem.util.tor_tools.is_valid_fingerprint(arg):
    return arg
  elif stem.util.tor_tools.is_valid_nickname(arg):
    try:
      return controller.get_network_status(arg).fingerprint
    except:
      raise ValueError("Unable to find a relay with the nickname of '%s'" % arg)
  elif ':' in arg or stem.util.connection.is_valid_ipv4_address(arg):
    if ':' in arg:
      address, port = arg.split(':', 1)

      if not stem.util.connection.is_valid_ipv4_address(address):
        raise ValueError("'%s' isn't a valid IPv4 address" % address)
      elif port and not stem.util.connection.is_valid_port(port):
        raise ValueError("'%s' isn't a valid port" % port)

      port = int(port)
    else:
      address, port = arg, None

    matches = {}

    for desc in controller.get_network_statuses():
      if desc.address == address:
        if not port or desc.or_port == port:
          matches[desc.or_port] = desc.fingerprint

    if len(matches) == 0:
      raise ValueError('No relays found at %s' % arg)
    elif len(matches) == 1:
      return list(matches.values())[0]
    else:
      response = "There's multiple relays at %s, include a port to specify which.\n\n" % arg

      for i, or_port in enumerate(matches):
        response += '  %i. %s:%s, fingerprint: %s\n' % (i + 1, address, or_port, matches[or_port])

      raise ValueError(response)
  else:
    raise ValueError("'%s' isn't a fingerprint, nickname, or IP address" % arg)


class ControlInterpretor(code.InteractiveConsole):
  """
  Handles issuing requests and providing nicely formed responses, with support
  for special irc style subcommands.
  """

  def __init__(self, controller):
    self._received_events = []

    code.InteractiveConsole.__init__(self, {
      'stem': stem,
      'stem.control': stem.control,
      'controller': controller,
      'events': self.get_events,
    })

    self._controller = controller
    self._run_python_commands = True

    # Indicates if we're processing a multiline command, such as conditional
    # block or loop.

    self.is_multiline_context = False

    # Intercept events our controller hears about at a pretty low level since
    # the user will likely be requesting them by direct 'SETEVENTS' calls.

    handle_event_real = self._controller._handle_event

    def handle_event_wrapper(event_message):
      handle_event_real(event_message)
      self._received_events.append(event_message)

    self._controller._handle_event = handle_event_wrapper

  def get_events(self, *event_types):
    events = list(self._received_events)
    event_types = list(map(str.upper, event_types))  # make filtering case insensitive

    if event_types:
      events = [e for e in events if e.type in event_types]

    return events

  def do_help(self, arg):
    """
    Performs the '/help' operation, giving usage information for the given
    argument or a general summary if there wasn't one.
    """

    return stem.interpreter.help.response(self._controller, arg)

  def do_events(self, arg):
    """
    Performs the '/events' operation, dumping the events that we've received
    belonging to the given types. If no types are specified then this provides
    all buffered events.

    If the user runs '/events clear' then this clears the list of events we've
    received.
    """

    event_types = arg.upper().split()

    if 'CLEAR' in event_types:
      del self._received_events[:]
      return format('cleared event backlog', *STANDARD_OUTPUT)

    return '\n'.join([format(str(e), *STANDARD_OUTPUT) for e in self.get_events(*event_types)])

  def do_info(self, arg):
    """
    Performs the '/info' operation, looking up a relay by fingerprint, IP
    address, or nickname and printing its descriptor and consensus entries in a
    pretty fashion.
    """

    try:
      fingerprint = _get_fingerprint(arg, self._controller)
    except ValueError as exc:
      return format(str(exc), *ERROR_OUTPUT)

    ns_desc = self._controller.get_network_status(fingerprint, None)
    server_desc = self._controller.get_server_descriptor(fingerprint, None)
    extrainfo_desc = None
    micro_desc = self._controller.get_microdescriptor(fingerprint, None)

    # We'll mostly rely on the router status entry. Either the server
    # descriptor or microdescriptor will be missing, so we'll treat them as
    # being optional.

    if not ns_desc:
      return format('Unable to find consensus information for %s' % fingerprint, *ERROR_OUTPUT)

    # More likely than not we'll have the microdescriptor but not server and
    # extrainfo descriptors. If so then fetching them.

    downloader = stem.descriptor.remote.DescriptorDownloader(timeout = 5)
    server_desc_query = downloader.get_server_descriptors(fingerprint)
    extrainfo_desc_query = downloader.get_extrainfo_descriptors(fingerprint)

    for desc in server_desc_query:
      server_desc = desc

    for desc in extrainfo_desc_query:
      extrainfo_desc = desc

    address_extrainfo = []

    try:
      address_extrainfo.append(socket.gethostbyaddr(ns_desc.address)[0])
    except:
      pass

    try:
      address_extrainfo.append(self._controller.get_info('ip-to-country/%s' % ns_desc.address))
    except:
      pass

    address_extrainfo_label = ' (%s)' % ', '.join(address_extrainfo) if address_extrainfo else ''

    if server_desc:
      exit_policy_label = str(server_desc.exit_policy)
    elif micro_desc:
      exit_policy_label = str(micro_desc.exit_policy)
    else:
      exit_policy_label = 'Unknown'

    lines = [
      '%s (%s)' % (ns_desc.nickname, fingerprint),
      format('address: ', *BOLD_OUTPUT) + '%s:%s%s' % (ns_desc.address, ns_desc.or_port, address_extrainfo_label),
    ]

    if server_desc:
      lines.append(format('tor version: ', *BOLD_OUTPUT) + str(server_desc.tor_version))

    lines.append(format('flags: ', *BOLD_OUTPUT) + ', '.join(ns_desc.flags))
    lines.append(format('exit policy: ', *BOLD_OUTPUT) + exit_policy_label)

    if server_desc and server_desc.contact:
      contact = stem.util.str_tools._to_unicode(server_desc.contact)

      # clears up some highly common obscuring

      for alias in (' at ', ' AT '):
        contact = contact.replace(alias, '@')

      for alias in (' dot ', ' DOT '):
        contact = contact.replace(alias, '.')

      lines.append(format('contact: ', *BOLD_OUTPUT) + contact)

    descriptor_section = [
      ('Server Descriptor:', server_desc),
      ('Extrainfo Descriptor:', extrainfo_desc),
      ('Microdescriptor:', micro_desc),
      ('Router Status Entry:', ns_desc),
    ]

    div = format('-' * 80, *STANDARD_OUTPUT)

    for label, desc in descriptor_section:
      if desc:
        lines += ['', div, format(label, *BOLD_OUTPUT), div, '']
        lines += [format(l, *STANDARD_OUTPUT) for l in str(desc).splitlines()]

    return '\n'.join(lines)

  def do_python(self, arg):
    """
    Performs the '/python' operation, toggling if we accept python commands or
    not.
    """

    if not arg:
      status = 'enabled' if self._run_python_commands else 'disabled'
      return format('Python support is currently %s.' % status, *STANDARD_OUTPUT)
    elif arg.lower() == 'enable':
      self._run_python_commands = True
    elif arg.lower() == 'disable':
      self._run_python_commands = False
    else:
      return format("'%s' is not recognized. Please run either '/python enable' or '/python disable'." % arg, *ERROR_OUTPUT)

    if self._run_python_commands:
      response = "Python support enabled, we'll now run non-interpreter commands as python."
    else:
      response = "Python support disabled, we'll now pass along all commands to tor."

    return format(response, *STANDARD_OUTPUT)

  @uses_settings
  def run_command(self, command, config):
    """
    Runs the given command. Requests starting with a '/' are special commands
    to the interpreter, and anything else is sent to the control port.

    :param stem.control.Controller controller: tor control connection
    :param str command: command to be processed

    :returns: **list** out output lines, each line being a list of
      (msg, format) tuples

    :raises: **stem.SocketClosed** if the control connection has been severed
    """

    if not self._controller.is_alive():
      raise stem.SocketClosed()

    # Commands fall into three categories:
    #
    # * Interpretor commands. These start with a '/'.
    #
    # * Controller commands stem knows how to handle. We use our Controller's
    #   methods for these to take advantage of caching and present nicer
    #   output.
    #
    # * Other tor commands. We pass these directly on to the control port.

    cmd, arg = command.strip(), ''

    if ' ' in cmd:
      cmd, arg = cmd.split(' ', 1)

    output = ''

    if cmd.startswith('/'):
      cmd = cmd.lower()

      if cmd == '/quit':
        raise stem.SocketClosed()
      elif cmd == '/events':
        output = self.do_events(arg)
      elif cmd == '/info':
        output = self.do_info(arg)
      elif cmd == '/python':
        output = self.do_python(arg)
      elif cmd == '/help':
        output = self.do_help(arg)
      else:
        output = format("'%s' isn't a recognized command" % command, *ERROR_OUTPUT)
    else:
      cmd = cmd.upper()  # makes commands uppercase to match the spec

      if cmd.replace('+', '') in ('LOADCONF', 'POSTDESCRIPTOR'):
        # provides a notice that multi-line controller input isn't yet implemented
        output = format(msg('msg.multiline_unimplemented_notice'), *ERROR_OUTPUT)
      elif cmd == 'QUIT':
        self._controller.msg(command)
        raise stem.SocketClosed()
      else:
        is_tor_command = cmd in config.get('help.usage', {}) and cmd.lower() != 'events'

        if self._run_python_commands and not is_tor_command:
          self.is_multiline_context = code.InteractiveConsole.push(self, command)
          return
        else:
          try:
            output = format(self._controller.msg(command).raw_content().strip(), *STANDARD_OUTPUT)
          except stem.ControllerError as exc:
            if isinstance(exc, stem.SocketClosed):
              raise exc
            else:
              output = format(str(exc), *ERROR_OUTPUT)

    output += '\n'  # give ourselves an extra line before the next prompt

    return output
