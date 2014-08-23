# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
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

"""Tokenize DNS master file format"""

import cStringIO
import sys

import dns.exception
import dns.name
import dns.ttl

_DELIMITERS = {
    ' ' : True,
    '\t' : True,
    '\n' : True,
    ';' : True,
    '(' : True,
    ')' : True,
    '"' : True }

_QUOTING_DELIMITERS = { '"' : True }

EOF = 0
EOL = 1
WHITESPACE = 2
IDENTIFIER = 3
QUOTED_STRING = 4
COMMENT = 5
DELIMITER = 6

class UngetBufferFull(dns.exception.DNSException):
    """Raised when an attempt is made to unget a token when the unget
    buffer is full."""
    pass

class Token(object):
    """A DNS master file format token.

    @ivar ttype: The token type
    @type ttype: int
    @ivar value: The token value
    @type value: string
    @ivar has_escape: Does the token value contain escapes?
    @type has_escape: bool
    """

    def __init__(self, ttype, value='', has_escape=False):
        """Initialize a token instance.

        @param ttype: The token type
        @type ttype: int
        @param value: The token value
        @type value: string
        @param has_escape: Does the token value contain escapes?
        @type has_escape: bool
        """
        self.ttype = ttype
        self.value = value
        self.has_escape = has_escape

    def is_eof(self):
        return self.ttype == EOF

    def is_eol(self):
        return self.ttype == EOL

    def is_whitespace(self):
        return self.ttype == WHITESPACE

    def is_identifier(self):
        return self.ttype == IDENTIFIER

    def is_quoted_string(self):
        return self.ttype == QUOTED_STRING

    def is_comment(self):
        return self.ttype == COMMENT

    def is_delimiter(self):
        return self.ttype == DELIMITER

    def is_eol_or_eof(self):
        return (self.ttype == EOL or self.ttype == EOF)

    def __eq__(self, other):
        if not isinstance(other, Token):
            return False
        return (self.ttype == other.ttype and
                self.value == other.value)

    def __ne__(self, other):
        if not isinstance(other, Token):
            return True
        return (self.ttype != other.ttype or
                self.value != other.value)

    def __str__(self):
        return '%d "%s"' % (self.ttype, self.value)

    def unescape(self):
        if not self.has_escape:
            return self
        unescaped = ''
        l = len(self.value)
        i = 0
        while i < l:
            c = self.value[i]
            i += 1
            if c == '\\':
                if i >= l:
                    raise dns.exception.UnexpectedEnd
                c = self.value[i]
                i += 1
                if c.isdigit():
                    if i >= l:
                        raise dns.exception.UnexpectedEnd
                    c2 = self.value[i]
                    i += 1
                    if i >= l:
                        raise dns.exception.UnexpectedEnd
                    c3 = self.value[i]
                    i += 1
                    if not (c2.isdigit() and c3.isdigit()):
                        raise dns.exception.SyntaxError
                    c = chr(int(c) * 100 + int(c2) * 10 + int(c3))
            unescaped += c
        return Token(self.ttype, unescaped)

    # compatibility for old-style tuple tokens

    def __len__(self):
        return 2

    def __iter__(self):
        return iter((self.ttype, self.value))

    def __getitem__(self, i):
        if i == 0:
            return self.ttype
        elif i == 1:
            return self.value
        else:
            raise IndexError

class Tokenizer(object):
    """A DNS master file format tokenizer.

    A token is a (type, value) tuple, where I{type} is an int, and
    I{value} is a string.  The valid types are EOF, EOL, WHITESPACE,
    IDENTIFIER, QUOTED_STRING, COMMENT, and DELIMITER.

    @ivar file: The file to tokenize
    @type file: file
    @ivar ungotten_char: The most recently ungotten character, or None.
    @type ungotten_char: string
    @ivar ungotten_token: The most recently ungotten token, or None.
    @type ungotten_token: (int, string) token tuple
    @ivar multiline: The current multiline level.  This value is increased
    by one every time a '(' delimiter is read, and decreased by one every time
    a ')' delimiter is read.
    @type multiline: int
    @ivar quoting: This variable is true if the tokenizer is currently
    reading a quoted string.
    @type quoting: bool
    @ivar eof: This variable is true if the tokenizer has encountered EOF.
    @type eof: bool
    @ivar delimiters: The current delimiter dictionary.
    @type delimiters: dict
    @ivar line_number: The current line number
    @type line_number: int
    @ivar filename: A filename that will be returned by the L{where} method.
    @type filename: string
    """

    def __init__(self, f=sys.stdin, filename=None):
        """Initialize a tokenizer instance.

        @param f: The file to tokenize.  The default is sys.stdin.
        This parameter may also be a string, in which case the tokenizer
        will take its input from the contents of the string.
        @type f: file or string
        @param filename: the name of the filename that the L{where} method
        will return.
        @type filename: string
        """

        if isinstance(f, str):
            f = cStringIO.StringIO(f)
            if filename is None:
                filename = '<string>'
        else:
            if filename is None:
                if f is sys.stdin:
                    filename = '<stdin>'
                else:
                    filename = '<file>'
        self.file = f
        self.ungotten_char = None
        self.ungotten_token = None
        self.multiline = 0
        self.quoting = False
        self.eof = False
        self.delimiters = _DELIMITERS
        self.line_number = 1
        self.filename = filename

    def _get_char(self):
        """Read a character from input.
        @rtype: string
        """

        if self.ungotten_char is None:
            if self.eof:
                c = ''
            else:
                c = self.file.read(1)
                if c == '':
                    self.eof = True
                elif c == '\n':
                    self.line_number += 1
        else:
            c = self.ungotten_char
            self.ungotten_char = None
        return c

    def where(self):
        """Return the current location in the input.

        @rtype: (string, int) tuple.  The first item is the filename of
        the input, the second is the current line number.
        """

        return (self.filename, self.line_number)

    def _unget_char(self, c):
        """Unget a character.

        The unget buffer for characters is only one character large; it is
        an error to try to unget a character when the unget buffer is not
        empty.

        @param c: the character to unget
        @type c: string
        @raises UngetBufferFull: there is already an ungotten char
        """

        if not self.ungotten_char is None:
            raise UngetBufferFull
        self.ungotten_char = c

    def skip_whitespace(self):
        """Consume input until a non-whitespace character is encountered.

        The non-whitespace character is then ungotten, and the number of
        whitespace characters consumed is returned.

        If the tokenizer is in multiline mode, then newlines are whitespace.

        @rtype: int
        """

        skipped = 0
        while True:
            c = self._get_char()
            if c != ' ' and c != '\t':
                if (c != '\n') or not self.multiline:
                    self._unget_char(c)
                    return skipped
            skipped += 1

    def get(self, want_leading = False, want_comment = False):
        """Get the next token.

        @param want_leading: If True, return a WHITESPACE token if the
        first character read is whitespace.  The default is False.
        @type want_leading: bool
        @param want_comment: If True, return a COMMENT token if the
        first token read is a comment.  The default is False.
        @type want_comment: bool
        @rtype: Token object
        @raises dns.exception.UnexpectedEnd: input ended prematurely
        @raises dns.exception.SyntaxError: input was badly formed
        """

        if not self.ungotten_token is None:
            token = self.ungotten_token
            self.ungotten_token = None
            if token.is_whitespace():
                if want_leading:
                    return token
            elif token.is_comment():
                if want_comment:
                    return token
            else:
                return token
        skipped = self.skip_whitespace()
        if want_leading and skipped > 0:
            return Token(WHITESPACE, ' ')
        token = ''
        ttype = IDENTIFIER
        has_escape = False
        while True:
            c = self._get_char()
            if c == '' or c in self.delimiters:
                if c == '' and self.quoting:
                    raise dns.exception.UnexpectedEnd
                if token == '' and ttype != QUOTED_STRING:
                    if c == '(':
                        self.multiline += 1
                        self.skip_whitespace()
                        continue
                    elif c == ')':
                        if not self.multiline > 0:
                            raise dns.exception.SyntaxError
                        self.multiline -= 1
                        self.skip_whitespace()
                        continue
                    elif c == '"':
                        if not self.quoting:
                            self.quoting = True
                            self.delimiters = _QUOTING_DELIMITERS
                            ttype = QUOTED_STRING
                            continue
                        else:
                            self.quoting = False
                            self.delimiters = _DELIMITERS
                            self.skip_whitespace()
                            continue
                    elif c == '\n':
                        return Token(EOL, '\n')
                    elif c == ';':
                        while 1:
                            c = self._get_char()
                            if c == '\n' or c == '':
                                break
                            token += c
                        if want_comment:
                            self._unget_char(c)
                            return Token(COMMENT, token)
                        elif c == '':
                            if self.multiline:
                                raise dns.exception.SyntaxError('unbalanced parentheses')
                            return Token(EOF)
                        elif self.multiline:
                            self.skip_whitespace()
                            token = ''
                            continue
                        else:
                            return Token(EOL, '\n')
                    else:
                        # This code exists in case we ever want a
                        # delimiter to be returned.  It never produces
                        # a token currently.
                        token = c
                        ttype = DELIMITER
                else:
                    self._unget_char(c)
                break
            elif self.quoting:
                if c == '\\':
                    c = self._get_char()
                    if c == '':
                        raise dns.exception.UnexpectedEnd
                    if c.isdigit():
                        c2 = self._get_char()
                        if c2 == '':
                            raise dns.exception.UnexpectedEnd
                        c3 = self._get_char()
                        if c == '':
                            raise dns.exception.UnexpectedEnd
                        if not (c2.isdigit() and c3.isdigit()):
                            raise dns.exception.SyntaxError
                        c = chr(int(c) * 100 + int(c2) * 10 + int(c3))
                elif c == '\n':
                    raise dns.exception.SyntaxError('newline in quoted string')
            elif c == '\\':
                #
                # It's an escape.  Put it and the next character into
                # the token; it will be checked later for goodness.
                #
                token += c
                has_escape = True
                c = self._get_char()
                if c == '' or c == '\n':
                    raise dns.exception.UnexpectedEnd
            token += c
        if token == '' and ttype != QUOTED_STRING:
            if self.multiline:
                raise dns.exception.SyntaxError('unbalanced parentheses')
            ttype = EOF
        return Token(ttype, token, has_escape)

    def unget(self, token):
        """Unget a token.

        The unget buffer for tokens is only one token large; it is
        an error to try to unget a token when the unget buffer is not
        empty.

        @param token: the token to unget
        @type token: Token object
        @raises UngetBufferFull: there is already an ungotten token
        """

        if not self.ungotten_token is None:
            raise UngetBufferFull
        self.ungotten_token = token

    def next(self):
        """Return the next item in an iteration.
        @rtype: (int, string)
        """

        token = self.get()
        if token.is_eof():
            raise StopIteration
        return token

    def __iter__(self):
        return self

    # Helpers

    def get_int(self):
        """Read the next token and interpret it as an integer.

        @raises dns.exception.SyntaxError:
        @rtype: int
        """

        token = self.get().unescape()
        if not token.is_identifier():
            raise dns.exception.SyntaxError('expecting an identifier')
        if not token.value.isdigit():
            raise dns.exception.SyntaxError('expecting an integer')
        return int(token.value)

    def get_uint8(self):
        """Read the next token and interpret it as an 8-bit unsigned
        integer.

        @raises dns.exception.SyntaxError:
        @rtype: int
        """

        value = self.get_int()
        if value < 0 or value > 255:
            raise dns.exception.SyntaxError('%d is not an unsigned 8-bit integer' % value)
        return value

    def get_uint16(self):
        """Read the next token and interpret it as a 16-bit unsigned
        integer.

        @raises dns.exception.SyntaxError:
        @rtype: int
        """

        value = self.get_int()
        if value < 0 or value > 65535:
            raise dns.exception.SyntaxError('%d is not an unsigned 16-bit integer' % value)
        return value

    def get_uint32(self):
        """Read the next token and interpret it as a 32-bit unsigned
        integer.

        @raises dns.exception.SyntaxError:
        @rtype: int
        """

        token = self.get().unescape()
        if not token.is_identifier():
            raise dns.exception.SyntaxError('expecting an identifier')
        if not token.value.isdigit():
            raise dns.exception.SyntaxError('expecting an integer')
        value = long(token.value)
        if value < 0 or value > 4294967296L:
            raise dns.exception.SyntaxError('%d is not an unsigned 32-bit integer' % value)
        return value

    def get_string(self, origin=None):
        """Read the next token and interpret it as a string.

        @raises dns.exception.SyntaxError:
        @rtype: string
        """

        token = self.get().unescape()
        if not (token.is_identifier() or token.is_quoted_string()):
            raise dns.exception.SyntaxError('expecting a string')
        return token.value

    def get_identifier(self, origin=None):
        """Read the next token and raise an exception if it is not an identifier.

        @raises dns.exception.SyntaxError:
        @rtype: string
        """

        token = self.get().unescape()
        if not token.is_identifier():
            raise dns.exception.SyntaxError('expecting an identifier')
        return token.value

    def get_name(self, origin=None):
        """Read the next token and interpret it as a DNS name.

        @raises dns.exception.SyntaxError:
        @rtype: dns.name.Name object"""

        token = self.get()
        if not token.is_identifier():
            raise dns.exception.SyntaxError('expecting an identifier')
        return dns.name.from_text(token.value, origin)

    def get_eol(self):
        """Read the next token and raise an exception if it isn't EOL or
        EOF.

        @raises dns.exception.SyntaxError:
        @rtype: string
        """

        token = self.get()
        if not token.is_eol_or_eof():
            raise dns.exception.SyntaxError('expected EOL or EOF, got %d "%s"' % (token.ttype, token.value))
        return token.value

    def get_ttl(self):
        token = self.get().unescape()
        if not token.is_identifier():
            raise dns.exception.SyntaxError('expecting an identifier')
        return dns.ttl.from_text(token.value)
