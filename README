ABOUT
======

SpiderFoot is an open source footprinting tool, created by Steve Micallef <steve@binarypool.com>. It is designed to be easy to use, fast and extensible.

Visit the project website at http://www.spiderfoot.net.


DOWNLOADING
============

To get the packaged and tested SpiderFoot releases for your platform:
https://sourceforge.net/projects/spiderfoot/files

To get the latest source and tinker around with it yourself:
https://github.com/smicallef/spiderfoot


INSTALLING AND RUNNING ON *NIX
===============================

SpiderFoot is written in Python (2.7), so to run on Linux/Solaris/etc. you need Python 2.7 installed, in addition to the CherryPy and Mako modules.

To install the dependencies using PIP (https://pypi.python.org/pypi/pip), do the following:

$ pip install cherrypy
$ pip install mako

All other module dependencies, such as SQLite3, are included with Python, so nothing further should be needed.

To run SpiderFoot, simply execute sf.py from the directory you extracted SpiderFoot into:

$ python ./sf.py

Once executed, a web-server will be started, which by default will listen on 127.0.0.1:5001. You can then use the web-browser of your choice by browsing to http://127.0.0.1:5001. 

If you wish to make SpiderFoot accessible from another system, for example running it on a server and controlling it remotely, then you can specify an external IP for SpiderFoot to bind to, or use 0.0.0.0 so that it binds to all addresses, including 127.0.0.1:

$ python ./sf.py 0.0.0.0:5001

If port 5001 is used by another application on your system, you can change the port:

$ python ./sf.py 127.0.0.1:9999

** A word of caution **: SpiderFoot does not authenticate users connecting to it's user-interface (feature coming soon..), so avoid running it on a server/workstation that can be accessed from untrusted devices, as they will be able to control SpiderFoot remotely and initiate scans from your devices.


INSTALLING AND RUNNING ON WINDOWS
==================================

SpiderFoot for Windows comes as a pre-packaged executable, with no need to install any dependencies. 

For now, there is no installer wizard, so all that's needed is to unzip the package into a directory (e.g. C:\SpiderFoot) and run sf.exe:

C:\SpiderFoot>sf.exe


REPORTING BUGS
===============

All bugs are tracked in github, please visit: https://github.com/smicallef/spiderfoot/issues


REQUESTING FEATURES
====================

A UserVoice instance has been set up for capturing feature requests, please visit: http://spiderfoot.uservoice.com to request new features or vote on other people's requests.


GETTING HELP
=============

A user manual is currently work-in-progress, but effort has been made to make the user-interface as simple and self-explanatory as possible. 

If you are really stuck, just e-mail support@spiderfoot.net.

