# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import stem.response
import stem.socket


class GetConfResponse(stem.response.ControlMessage):
  """
  Reply for a GETCONF query.

  Note that configuration parameters won't match what we queried for if it's one
  of the special mapping options (ex. 'HiddenServiceOptions').

  :var dict entries: mapping between the config parameter (**str**) and their
    values (**list** of **str**)
  """

  def _parse_message(self):
    # Example:
    # 250-CookieAuthentication=0
    # 250-ControlPort=9100
    # 250-DataDirectory=/home/neena/.tor
    # 250 DirPort

    self.entries = {}
    remaining_lines = list(self)

    if self.content() == [('250', ' ', 'OK')]:
      return

    if not self.is_ok():
      unrecognized_keywords = []
      for code, _, line in self.content():
        if code == '552' and line.startswith('Unrecognized configuration key "') and line.endswith('"'):
          unrecognized_keywords.append(line[32:-1])

      if unrecognized_keywords:
        raise stem.InvalidArguments('552', 'GETCONF request contained unrecognized keywords: %s' % ', '.join(unrecognized_keywords), unrecognized_keywords)
      else:
        raise stem.ProtocolError('GETCONF response contained a non-OK status code:\n%s' % self)

    while remaining_lines:
      line = remaining_lines.pop(0)

      if line.is_next_mapping():
        key, value = line.split('=', 1)
      else:
        key, value = (line.pop(), None)

      if key not in self.entries:
        self.entries[key] = []

      if value is not None:
        self.entries[key].append(value)
