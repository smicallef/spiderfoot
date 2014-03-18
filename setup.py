from distutils.core import setup
import py2exe

setup(
    console=['sf.py'],
    options={
        "py2exe": {
            "packages": ["modules", "ext.dns", "sflib", "sfwebui", "sfdb", "mako", 
                "cherrypy", "M2Crypto", "netaddr", "ext.socks"],
            "bundle_files": 1,
            "compressed": True
        }
    },
    zipfile = None
)
