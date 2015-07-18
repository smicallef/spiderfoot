# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import stem.response
import stem.socket


class MapAddressResponse(stem.response.ControlMessage):
  """
  Reply for a MAPADDRESS query.
  Doesn't raise an exception unless no addresses were mapped successfully.

  :var dict entries: mapping between the original and replacement addresses

  :raises:
    * :class:`stem.OperationFailed` if Tor was unable to satisfy the request
    * :class:`stem.InvalidRequest` if the addresses provided were invalid
  """

  def _parse_message(self):
    # Example:
    # 250-127.192.10.10=torproject.org
    # 250 1.2.3.4=tor.freehaven.net

    if not self.is_ok():
      for code, _, message in self.content():
        if code == '512':
          raise stem.InvalidRequest(code, message)
        elif code == '451':
          raise stem.OperationFailed(code, message)
        else:
          raise stem.ProtocolError('MAPADDRESS returned unexpected response code: %s', code)

    self.entries = {}

    for code, _, message in self.content():
      if code == '250':
        try:
          key, value = message.split('=', 1)
          self.entries[key] = value
        except ValueError:
          raise stem.ProtocolError(None, "MAPADDRESS returned '%s', which isn't a mapping" % message)
