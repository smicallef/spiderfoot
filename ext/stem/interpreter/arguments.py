# Copyright 2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Commandline argument parsing for our interpreter prompt.
"""

import collections
import getopt

import stem.interpreter
import stem.util.connection

DEFAULT_ARGS = {
  'control_address': '127.0.0.1',
  'control_port': 9051,
  'user_provided_port': False,
  'control_socket': '/var/run/tor/control',
  'user_provided_socket': False,
  'disable_color': False,
  'print_help': False,
}

OPT = 'i:s:h'
OPT_EXPANDED = ['interface=', 'socket=', 'no-color', 'help']


def parse(argv):
  """
  Parses our arguments, providing a named tuple with their values.

  :param list argv: input arguments to be parsed

  :returns: a **named tuple** with our parsed arguments

  :raises: **ValueError** if we got an invalid argument
  """

  args = dict(DEFAULT_ARGS)

  try:
    recognized_args, unrecognized_args = getopt.getopt(argv, OPT, OPT_EXPANDED)

    if unrecognized_args:
      error_msg = "aren't recognized arguments" if len(unrecognized_args) > 1 else "isn't a recognized argument"
      raise getopt.GetoptError("'%s' %s" % ("', '".join(unrecognized_args), error_msg))
  except Exception as exc:
    raise ValueError('%s (for usage provide --help)' % exc)

  for opt, arg in recognized_args:
    if opt in ('-i', '--interface'):
      if ':' in arg:
        address, port = arg.split(':', 1)
      else:
        address, port = None, arg

      if address is not None:
        if not stem.util.connection.is_valid_ipv4_address(address):
          raise ValueError("'%s' isn't a valid IPv4 address" % address)

        args['control_address'] = address

      if not stem.util.connection.is_valid_port(port):
        raise ValueError("'%s' isn't a valid port number" % port)

      args['control_port'] = int(port)
      args['user_provided_port'] = True
    elif opt in ('-s', '--socket'):
      args['control_socket'] = arg
      args['user_provided_socket'] = True
    elif opt == '--no-color':
      args['disable_color'] = True
    elif opt in ('-h', '--help'):
      args['print_help'] = True

  # translates our args dict into a named tuple

  Args = collections.namedtuple('Args', args.keys())
  return Args(**args)


def get_help():
  """
  Provides our --help usage information.

  :returns: **str** with our usage information
  """

  return stem.interpreter.msg(
    'msg.help',
    address = DEFAULT_ARGS['control_address'],
    port = DEFAULT_ARGS['control_port'],
    socket = DEFAULT_ARGS['control_socket'],
  )
