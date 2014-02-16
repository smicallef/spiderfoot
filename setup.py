from distutils.core import setup
import py2exe

setup(
    console=['sf.py'],
    options={
        "py2exe": {
            "packages": ["modules", "dns", "sflib", "sfwebui", "sfdb", "mako", 
                "cherrypy", "M2Crypto", "netaddr", "socks"],
            "bundle_files": 1,
            "compressed": True
        }
    },
    zipfile = None
)
