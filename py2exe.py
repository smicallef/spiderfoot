from distutils.core import setup
import py2exe

setup(
    console=['sf.py'],
    options={
    "py2exe": {
        "packages": ["modules", "sflib", "sfwebui", "sfdb", "mako", "cherrypy"],
        "bundle_files": 1,
                "compressed": True
    }
    },
    zipfile = None
)
