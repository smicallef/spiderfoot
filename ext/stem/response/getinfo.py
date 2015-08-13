# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import stem.response
import stem.socket


class GetInfoResponse(stem.response.ControlMessage):
  """
  Reply for a GETINFO query.

  :var dict entries: mapping between the queried options and their bytes values
  """

  def _parse_message(self):
    # Example:
    # 250-version=0.2.3.11-alpha-dev (git-ef0bc7f8f26a917c)
    # 250+config-text=
    # ControlPort 9051
    # DataDirectory /home/atagar/.tor
    # ExitPolicy reject *:*
    # Log notice stdout
    # Nickname Unnamed
    # ORPort 9050
    # .
    # 250 OK

    self.entries = {}
    remaining_lines = [content for (code, div, content) in self.content(get_bytes = True)]

    if not self.is_ok() or not remaining_lines.pop() == b'OK':
      unrecognized_keywords = []
      for code, _, line in self.content():
        if code == '552' and line.startswith('Unrecognized key "') and line.endswith('"'):
          unrecognized_keywords.append(line[18:-1])

      if unrecognized_keywords:
        raise stem.InvalidArguments('552', 'GETINFO request contained unrecognized keywords: %s\n' % ', '.join(unrecognized_keywords), unrecognized_keywords)
      else:
        raise stem.ProtocolError("GETINFO response didn't have an OK status:\n%s" % self)

    while remaining_lines:
      try:
        key, value = remaining_lines.pop(0).split(b'=', 1)
      except ValueError:
        raise stem.ProtocolError('GETINFO replies should only contain parameter=value mappings:\n%s' % self)

      if stem.prereq.is_python_3():
        key = stem.util.str_tools._to_unicode(key)

      # if the value is a multiline value then it *must* be of the form
      # '<key>=\n<value>'

      if b'\n' in value:
        if not value.startswith(b'\n'):
          raise stem.ProtocolError("GETINFO response contained a multi-line value that didn't start with a newline:\n%s" % self)

        value = value[1:]

      self.entries[key] = value

  def _assert_matches(self, params):
    """
    Checks if we match a given set of parameters, and raise a ProtocolError if not.

    :param set params: parameters to assert that we contain

    :raises:
      * :class:`stem.ProtocolError` if parameters don't match this response
    """

    reply_params = set(self.entries.keys())

    if params != reply_params:
      requested_label = ', '.join(params)
      reply_label = ', '.join(reply_params)

      raise stem.ProtocolError("GETINFO reply doesn't match the parameters that we requested. Queried '%s' but got '%s'." % (requested_label, reply_label))
