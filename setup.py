# -*- coding: utf-8 -*-

from __future__ import absolute_import
from distutils.core import setup
import py2exe

setup(
    console=['sf.py'],
    options={
        "py2exe": {
            "packages": ["modules", "ext.dns", "sflib", "sfwebui", "sfdb", "mako",
                         "cherrypy", "M2Crypto", "netaddr", "ext.socks", "ext.pyPdf",
                         "ext.metapdf", "ext.openxmllib"],
            "bundle_files": 1,
            "compressed": True,
            "includes": ['lxml._elementpath']
        }
    },
    zipfile=None
)
