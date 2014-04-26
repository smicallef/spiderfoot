#! python
# -*- coding: utf-8 -*-
# $Id: shell.py 61 2009-12-18 10:53:19Z gilles.lenfant $
"""Command line tool"""

import os
import optparse
import time
import codecs
import locale
import types
import openxmllib

DEFAULT_CHARSET = locale.getpreferredencoding()
USAGE = """%%prog [options] command file
Version: %s
%s
Commands:
* `metadata' shows the file's metadata.
* `words' shows all words from file."""
VERSION = openxmllib.version


class Application(object):
    """Command line utility showing openxml document informations."""

    def __init__(self):

        def check_charset_option(option, opt_str, value, parser):
            """Value must be a valid charset"""
            try:
                dummy = codecs.lookup(value)
            except LookupError, e:
                raise optparse.OptionValueError(
                    "Charset '%s' in unknown or not supported by your sytem."
                    % value)
            setattr(parser.values, option.dest, value)
            return

        parser = optparse.OptionParser(
            usage=USAGE % (VERSION, self.__class__.__doc__),
            version=VERSION)
        parser.add_option(
            '-c', '--charset', dest='charset', default=DEFAULT_CHARSET,
            type='string', action='callback', callback=check_charset_option,
            help="Converts output to this charset (default %s)" % DEFAULT_CHARSET
            )
        parser.add_option(
            '-v', '--verbosity', dest='verbosity', default=0, action='count',
            help="Adds verbosity for each '-v'")
        self.options, self.args = parser.parse_args()
        if (len(self.args) < 2
            or self.args[0] not in self.commands.keys()):
            parser.error("Invalid arguments")
        self.filenames = self.args[1:]
        return

    def run(self):
        self.commands[self.args[0]](self)
        return

    def metadataCmd(self):
        self.log(1, "Showing metadata of %s.", ", ".join(self.filenames))
        for filename in self.filenames:
            self.showMetadata(filename)
        return

    def wordsCmd(self):
        self.log(1, "Showing words of %s.", ", ".join(self.filenames))
        for filename in self.filenames:
            self.showWords(filename)
        return

    commands = {
        'metadata': metadataCmd,
        'words': wordsCmd
        }

    def showMetadata(self, filename):
        if not self.checkfile(filename):
            return
        self.log(1, "Processing %s...", filename)
        doc = openxmllib.openXmlDocument(path=filename)
        self.log(2, "Core properties:")
        for k, v in doc.coreProperties.items():
            print "%s: %s" % (self.recode(k), self.recode(v))
        self.log(2, "Extended properties:")
        for k, v in doc.extendedProperties.items():
            print "%s: %s" % (self.recode(k), self.recode(v))
        self.log(2, "Custom properties:")
        for k, v in doc.customProperties.items():
            print "%s: %s" % (self.recode(k), self.recode(v))
        return

    def showWords(self, filename):
        if not self.checkfile(filename):
            return
        self.log(1, "Processing %s...", filename)
        start_time = time.time()
        doc = openxmllib.openXmlDocument(path=filename)
        text = doc.indexableText(include_properties=False)
        duration = time.time() - start_time
        print self.recode(text)
        self.log(1, "Words extracted in %s second(s)", duration)
        return

    def checkfile(self, filename):
        if not os.path.isfile(filename):
            self.log(0, "'%s' is not a file, skipped", filename)
            return False
        return True

    def log(self, required_verbosity, message, *args):
        if self.options.verbosity >= required_verbosity:
            print message % args
        return

    def recode(self, utext):
        if type(utext) is types.UnicodeType:
            return utext.encode(self.options.charset, 'replace')
        return utext

def openxmlinfo():
    Application().run()
    return
