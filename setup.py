# -*- coding: utf-8 -*-
from distutils.core import setup
import py2exe

setup(
    console=['sf.py'],
    options={
        "py2exe": {
            "packages": ["modules", "ext.dns", "sflib", "sfwebui", "sfdb", "mako",
                         "cherrypy", "M2Crypto", "netaddr", "ext.socks", "ext.PyPDF2",
                         "ext.openxmllib", "ext.stem", "ext.whois",
                         "phonenumbers", "ext.gexf", "bs4", "requests" ],
            "bundle_files": 1,
            "compressed": True,
            "includes": ['lxml._elementpath'],
            "dll_excludes": [ "w9xpopen.exe", "mswsock.dll", "powrprof.dll", "crypt32.dll", "mpr.dll" ]
        }
    },
    zipfile=None
)
