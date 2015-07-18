# Copyright 2014-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Provides our /help responses.
"""

from stem.interpreter import (
  STANDARD_OUTPUT,
  BOLD_OUTPUT,
  ERROR_OUTPUT,
  msg,
  uses_settings,
)

from stem.util.term import format

try:
  # added in python 3.2
  from functools import lru_cache
except ImportError:
  from stem.util.lru_cache import lru_cache


def response(controller, arg):
  """
  Provides our /help response.

  :param stem.control.Controller controller: tor control connection
  :param str arg: controller or interpreter command to provide help output for

  :returns: **str** with our help response
  """

  # Normalizing inputs first so we can better cache responses.

  return _response(controller, _normalize(arg))


def _normalize(arg):
  arg = arg.upper()

  # If there's multiple arguments then just take the first. This is
  # particularly likely if they're trying to query a full command (for
  # instance "/help GETINFO version")

  arg = arg.split(' ')[0]

  # strip slash if someone enters an interpreter command (ex. "/help /help")

  if arg.startswith('/'):
    arg = arg[1:]

  return arg


@lru_cache()
@uses_settings
def _response(controller, arg, config):
  if not arg:
    return _general_help()

  usage_info = config.get('help.usage', {})

  if arg not in usage_info:
    return format("No help information available for '%s'..." % arg, *ERROR_OUTPUT)

  output = format(usage_info[arg] + '\n', *BOLD_OUTPUT)

  description = config.get('help.description.%s' % arg.lower(), '')

  for line in description.splitlines():
    output += format('  ' + line, *STANDARD_OUTPUT) + '\n'

  output += '\n'

  if arg == 'GETINFO':
    results = controller.get_info('info/names', None)

    if results:
      for line in results.splitlines():
        if ' -- ' in line:
          opt, summary = line.split(' -- ', 1)

          output += format('%-33s' % opt, *BOLD_OUTPUT)
          output += format(' - %s' % summary, *STANDARD_OUTPUT) + '\n'
  elif arg == 'GETCONF':
    results = controller.get_info('config/names', None)

    if results:
      options = [opt.split(' ', 1)[0] for opt in results.splitlines()]

      for i in range(0, len(options), 2):
        line = ''

        for entry in options[i:i + 2]:
          line += '%-42s' % entry

        output += format(line.rstrip(), *STANDARD_OUTPUT) + '\n'
  elif arg == 'SIGNAL':
    signal_options = config.get('help.signal.options', {})

    for signal, summary in signal_options.items():
      output += format('%-15s' % signal, *BOLD_OUTPUT)
      output += format(' - %s' % summary, *STANDARD_OUTPUT) + '\n'
  elif arg == 'SETEVENTS':
    results = controller.get_info('events/names', None)

    if results:
      entries = results.split()

      # displays four columns of 20 characters

      for i in range(0, len(entries), 4):
        line = ''

        for entry in entries[i:i + 4]:
          line += '%-20s' % entry

        output += format(line.rstrip(), *STANDARD_OUTPUT) + '\n'
  elif arg == 'USEFEATURE':
    results = controller.get_info('features/names', None)

    if results:
      output += format(results, *STANDARD_OUTPUT) + '\n'
  elif arg in ('LOADCONF', 'POSTDESCRIPTOR'):
    # gives a warning that this option isn't yet implemented
    output += format(msg('msg.multiline_unimplemented_notice'), *ERROR_OUTPUT) + '\n'

  return output.rstrip()


def _general_help():
  lines = []

  for line in msg('help.general').splitlines():
    div = line.find(' - ')

    if div != -1:
      cmd, description = line[:div], line[div:]
      lines.append(format(cmd, *BOLD_OUTPUT) + format(description, *STANDARD_OUTPUT))
    else:
      lines.append(format(line, *BOLD_OUTPUT))

  return '\n'.join(lines)
