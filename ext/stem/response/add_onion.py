# Copyright 2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import stem.response


class AddOnionResponse(stem.response.ControlMessage):
  """
  ADD_ONION response.

  :var str service_id: hidden service address without the '.onion' suffix
  :var str private_key: base64 encoded hidden service private key
  :var str private_key_type: crypto used to generate the hidden service private
    key (such as RSA1024)
  """

  def _parse_message(self):
    # Example:
    #   250-ServiceID=gfzprpioee3hoppz
    #   250-PrivateKey=RSA1024:MIICXgIBAAKBgQDZvYVxv...
    #   250 OK

    self.service_id = None
    self.private_key = None
    self.private_key_type = None

    if not self.is_ok():
      raise stem.ProtocolError("ADD_ONION response didn't have an OK status: %s" % self)

    if not str(self).startswith('ServiceID='):
      raise stem.ProtocolError('ADD_ONION response should start with the service id: %s' % self)

    for line in list(self):
      if '=' in line:
        key, value = line.split('=', 1)

        if key == 'ServiceID':
          self.service_id = value
        elif key == 'PrivateKey':
          if ':' not in value:
            raise stem.ProtocolError("ADD_ONION PrivateKey lines should be of the form 'PrivateKey=[type]:[key]: %s" % self)

          self.private_key_type, self.private_key = value.split(':', 1)
