# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Checks for stem dependencies. We require python 2.6 or greater (including the
3.x series). Other requirements for complete functionality are...

* pycrypto module

  * validating descriptor signature integrity

::

  check_requirements - checks for minimum requirements for running stem

  is_python_27 - checks if python 2.7 or later is available
  is_python_3 - checks if python 3.0 or later is available

  is_crypto_available - checks if the pycrypto module is available
"""

import inspect
import sys

try:
  # added in python 3.2
  from functools import lru_cache
except ImportError:
  from stem.util.lru_cache import lru_cache

CRYPTO_UNAVAILABLE = "Unable to import the pycrypto module. Because of this we'll be unable to verify descriptor signature integrity. You can get pycrypto from: https://www.dlitz.net/software/pycrypto/"


def check_requirements():
  """
  Checks that we meet the minimum requirements to run stem. If we don't then
  this raises an ImportError with the issue.

  :raises: **ImportError** with the problem if we don't meet stem's
    requirements
  """

  major_version, minor_version = sys.version_info[0:2]

  if major_version < 2 or (major_version == 2 and minor_version < 6):
    raise ImportError('stem requires python version 2.6 or greater')


def is_python_27():
  """
  Checks if we're running python 2.7 or above (including the 3.x series).

  :returns: **True** if we meet this requirement and **False** otherwise
  """

  major_version, minor_version = sys.version_info[0:2]

  return major_version > 2 or (major_version == 2 and minor_version >= 7)


def is_python_3():
  """
  Checks if we're in the 3.0 - 3.x range.

  :returns: **True** if we meet this requirement and **False** otherwise
  """

  return sys.version_info[0] == 3


@lru_cache()
def is_crypto_available():
  """
  Checks if the pycrypto functions we use are available. This is used for
  verifying relay descriptor signatures.

  :returns: **True** if we can use pycrypto and **False** otherwise
  """

  from stem.util import log

  try:
    from Crypto.PublicKey import RSA
    from Crypto.Util import asn1
    from Crypto.Util.number import long_to_bytes
    return True
  except ImportError:
    log.log_once('stem.prereq.is_crypto_available', log.INFO, CRYPTO_UNAVAILABLE)
    return False


@lru_cache()
def is_mock_available():
  """
  Checks if the mock module is available. In python 3.3 and up it is a builtin
  unittest module, but before this it needed to be `installed separately
  <https://pypi.python.org/pypi/mock/>`_. Imports should be as follows....

  ::

    try:
      # added in python 3.3
      from unittest.mock import Mock
    except ImportError:
      from mock import Mock

  :returns: **True** if the mock module is available and **False** otherwise
  """

  try:
    # checks for python 3.3 version
    import unittest.mock
    return True
  except ImportError:
    pass

  try:
    import mock

    # check for mock's patch.dict() which was introduced in version 0.7.0

    if not hasattr(mock.patch, 'dict'):
      raise ImportError()

    # check for mock's new_callable argument for patch() which was introduced in version 0.8.0

    if 'new_callable' not in inspect.getargspec(mock.patch).args:
      raise ImportError()

    return True
  except ImportError:
    return False
