# Copyright (C) 2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""Hashing backwards compatibility wrapper"""

import sys

_hashes = None

def _need_later_python(alg):
    def func(*args, **kwargs):
        raise NotImplementedError("TSIG algorithm " + alg +
                                  " requires Python 2.5.2 or later")
    return func

def _setup():
    global _hashes
    _hashes = {}
    try:
        import hashlib
        _hashes['MD5'] = hashlib.md5
        _hashes['SHA1'] = hashlib.sha1
        _hashes['SHA224'] = hashlib.sha224
        _hashes['SHA256'] = hashlib.sha256
        if sys.hexversion >= 0x02050200:
            _hashes['SHA384'] = hashlib.sha384
            _hashes['SHA512'] = hashlib.sha512
        else:
            _hashes['SHA384'] = _need_later_python('SHA384')
            _hashes['SHA512'] = _need_later_python('SHA512')

        if sys.hexversion < 0x02050000:
            # hashlib doesn't conform to PEP 247: API for
            # Cryptographic Hash Functions, which hmac before python
            # 2.5 requires, so add the necessary items.
            class HashlibWrapper:
                def __init__(self, basehash):
                    self.basehash = basehash
                    self.digest_size = self.basehash().digest_size

                def new(self, *args, **kwargs):
                    return self.basehash(*args, **kwargs)

            for name in _hashes:
                _hashes[name] = HashlibWrapper(_hashes[name])

    except ImportError:
        import md5, sha
        _hashes['MD5'] =  md5
        _hashes['SHA1'] = sha

def get(algorithm):
    if _hashes is None:
        _setup()
    return _hashes[algorithm.upper()]
