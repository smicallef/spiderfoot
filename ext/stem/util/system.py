# Copyright 2011-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Helper functions for working with the underlying system. These are mostly os
dependent, only working on linux, osx, and bsd. In almost all cases they're
best-effort, providing **None** if the lookup fails.

.. versionchanged:: 1.3.0
   Dropped the get_* prefix from several function names. The old names still
   work, but are deprecated aliases.

**Module Overview:**

::

  is_windows - checks if we're running on windows
  is_mac - checks if we're running on a mac
  is_gentoo - checks if we're running on gentoo
  is_bsd - checks if we're running on the bsd family of operating systems

  is_available - determines if a command is available on this system
  is_running - determines if a given process is running
  call - runs the given system command and provides back the results

  name_by_pid - gets the name for a process by the given pid
  pid_by_name - gets the pid for a process by the given name
  pid_by_port - gets the pid for a process listening to a given port
  pid_by_open_file - gets the pid for the process with an open file
  cwd - provides the current working directory for a given process
  user - provides the user a process is running under
  start_time - provides the unix timestamp when the process started
  tail - provides lines from the end of a file
  bsd_jail_id - provides the BSD jail id a given process is running within
  bsd_jail_path - provides the path of the given BSD jail

  is_tarfile - checks if the given path is a tarball
  expand_path - expands relative paths and ~ entries
  files_with_suffix - provides files with the given suffix

  get_process_name - provides our process' name
  set_process_name - changes our process' name
"""

import ctypes
import ctypes.util
import distutils.spawn
import mimetypes
import os
import platform
import re
import subprocess
import tarfile
import time

import stem.util.proc
import stem.util.str_tools

from stem import UNDEFINED, str_type
from stem.util import log

# Mapping of commands to if they're available or not.

CMD_AVAILABLE_CACHE = {}

# An incomplete listing of commands provided by the shell. Expand this as
# needed. Some noteworthy things about shell commands...
#
# * They're not in the path so is_available() will fail.
# * subprocess.Popen() without the 'shell = True' argument will fail with...
#   OSError: [Errno 2] No such file or directory

SHELL_COMMANDS = ['ulimit']

IS_RUNNING_PS_LINUX = 'ps -A co command'
IS_RUNNING_PS_BSD = 'ps -ao ucomm='
GET_NAME_BY_PID_PS = 'ps -p %s -o comm'
GET_PID_BY_NAME_PGREP = 'pgrep -x %s'
GET_PID_BY_NAME_PIDOF = 'pidof %s'
GET_PID_BY_NAME_PS_LINUX = 'ps -o pid -C %s'
GET_PID_BY_NAME_PS_BSD = 'ps axc'
GET_PID_BY_NAME_LSOF = 'lsof -tc %s'
GET_PID_BY_PORT_NETSTAT = 'netstat -npltu'
GET_PID_BY_PORT_SOCKSTAT = 'sockstat -4l -P tcp -p %s'
GET_PID_BY_PORT_LSOF = 'lsof -wnP -iTCP -sTCP:LISTEN'
GET_PID_BY_FILE_LSOF = 'lsof -tw %s'
GET_CWD_PWDX = 'pwdx %s'
GET_CWD_LSOF = 'lsof -a -p %s -d cwd -Fn'
GET_BSD_JAIL_ID_PS = 'ps -p %s -o jid'
GET_BSD_JAIL_PATH = 'jls -j %s'

BLOCK_SIZE = 1024

# flag for setting the process name, found in '/usr/include/linux/prctl.h'

PR_SET_NAME = 15

argc_t = ctypes.POINTER(ctypes.c_char_p)

# The following can fail with pypy...
# AttributeError: No symbol Py_GetArgcArgv found in library <None>

try:
  Py_GetArgcArgv = ctypes.pythonapi.Py_GetArgcArgv
  Py_GetArgcArgv.restype = None
  Py_GetArgcArgv.argtypes = [
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(argc_t),
  ]
except:
  Py_GetArgcArgv = None

# This is both a cache for get_process_name() and tracks what we've changed our
# process name to.

_PROCESS_NAME = None

# Length of our original process name.
#
# The original author our process renaming is based on did a memset for 256,
# while Jake did it for the original process name length (capped at 1608). I'm
# not sure of the reasons for either of these limits, but setting it to
# anything higher than our original name length should be pointless, so opting
# for Jake's limit.

_MAX_NAME_LENGTH = -1


def is_windows():
  """
  Checks if we are running on Windows.

  :returns: **bool** to indicate if we're on Windows
  """

  return platform.system() == 'Windows'


def is_mac():
  """
  Checks if we are running on Mac OSX.

  :returns: **bool** to indicate if we're on a Mac
  """

  return platform.system() == 'Darwin'


def is_gentoo():
  """
  Checks if we're running on Gentoo.

  :returns: **bool** to indicate if we're on Gentoo
  """

  return os.path.exists('/etc/gentoo-release')


def is_bsd():
  """
  Checks if we are within the BSD family of operating systems. This currently
  recognizes Macs, FreeBSD, and OpenBSD but may be expanded later.

  :returns: **bool** to indicate if we're on a BSD OS
  """

  return platform.system() in ('Darwin', 'FreeBSD', 'OpenBSD')


def is_available(command, cached=True):
  """
  Checks the current PATH to see if a command is available or not. If more
  than one command is present (for instance "ls -a | grep foo") then this
  just checks the first.

  Note that shell (like cd and ulimit) aren't in the PATH so this lookup will
  try to assume that it's available. This only happends for recognized shell
  commands (those in SHELL_COMMANDS).

  :param str command: command to search for
  :param bool cached: makes use of available cached results if **True**

  :returns: **True** if an executable we can use by that name exists in the
    PATH, **False** otherwise
  """

  if ' ' in command:
    command = command.split(' ')[0]

  if command in SHELL_COMMANDS:
    # we can't actually look it up, so hope the shell really provides it...

    return True
  elif cached and command in CMD_AVAILABLE_CACHE:
    return CMD_AVAILABLE_CACHE[command]
  else:
    cmd_exists = distutils.spawn.find_executable(command) is not None
    CMD_AVAILABLE_CACHE[command] = cmd_exists
    return cmd_exists


def is_running(command):
  """
  Checks for if a process with a given name is running or not.

  :param str command: process name to be checked

  :returns: **True** if the process is running, **False** if it's not among ps
    results, and **None** if ps can't be queried
  """

  # Linux and the BSD families have different variants of ps. Guess based on
  # the is_bsd() check which to try first, then fall back to the other.
  #
  # Linux
  #   -A          - Select all processes.
  #   -co command - Shows just the base command.
  #
  # Mac / BSD
  #   -a        - Display information about other users' processes as well as
  #               our own.
  #   -o ucomm= - Shows just the ucomm attribute ("name to be used for
  #               accounting")

  if is_available('ps'):
    if is_bsd():
      primary_resolver = IS_RUNNING_PS_BSD
      secondary_resolver = IS_RUNNING_PS_LINUX
    else:
      primary_resolver = IS_RUNNING_PS_LINUX
      secondary_resolver = IS_RUNNING_PS_BSD

    command_listing = call(primary_resolver, None)

    if not command_listing:
      command_listing = call(secondary_resolver, None)

    if command_listing:
      command_listing = map(str_type.strip, command_listing)
      return command in command_listing

  return None


def name_by_pid(pid):
  """
  Attempts to determine the name a given process is running under (not
  including arguments). This uses...

  ::

    1. Information from /proc
    2. ps -p <pid> -o command

  :param int pid: process id of the process to be queried

  :returns: **str** with the process name, **None** if it can't be determined
  """

  process_name = None

  if stem.util.proc.is_available():
    try:
      process_name = stem.util.proc.stats(pid, stem.util.proc.Stat.COMMAND)[0]
    except IOError:
      pass

  # attempts to resolve using ps, failing if:
  # - system's ps variant doesn't handle these flags (none known at the moment)
  #
  # example output:
  #   atagar@morrigan:~$ ps -p 5767 -o comm
  #   COMMAND
  #   vim

  if not process_name:
    try:
      results = call(GET_NAME_BY_PID_PS % pid)
    except OSError:
      results = None

    if results and len(results) == 2 and results[0] == 'COMMAND':
      process_name = results[1].strip()

  return process_name


def pid_by_name(process_name, multiple = False):
  """
  Attempts to determine the process id for a running process, using...

  ::

    1. pgrep -x <name>
    2. pidof <name>
    3. ps -o pid -C <name> (linux)
       ps axc | egrep " <name>$" (bsd)
    4. lsof -tc <name>
    5. tasklist | str <name>.exe

  :param str process_name: process name for which to fetch the pid
  :param bool multiple: provides a list of all pids if **True**, otherwise
    results with multiple processes are discarded

  :returns:
    Response depends upon the 'multiple' argument as follows...

    * if **False** then this provides an **int** with the process id or **None** if it can't be determined
    * if **True** then this provides a **list** of all **int** process ids, and an empty list if it can't be determined
  """

  # attempts to resolve using pgrep, failing if:
  # - we're running on bsd (command unavailable)
  #
  # example output:
  #   atagar@morrigan:~$ pgrep -x vim
  #   3283
  #   3392

  if is_available('pgrep'):
    results = call(GET_PID_BY_NAME_PGREP % process_name, None)

    if results:
      try:
        pids = list(map(int, results))

        if multiple:
          return pids
        elif len(pids) == 1:
          return pids[0]
      except ValueError:
        pass

  # attempts to resolve using pidof, failing if:
  # - we're running on bsd (command unavailable)
  #
  # example output:
  #   atagar@morrigan:~$ pidof vim
  #   3392 3283

  if is_available('pidof'):
    results = call(GET_PID_BY_NAME_PIDOF % process_name, None)

    if results and len(results) == 1:
      try:
        pids = list(map(int, results[0].split()))

        if multiple:
          return pids
        elif len(pids) == 1:
          return pids[0]
      except ValueError:
        pass

  # attempts to resolve using ps, failing if:
  # - system's ps variant doesn't handle these flags (none known at the moment)
  #
  # example output:
  #   atagar@morrigan:~/Desktop/stem$ ps -o pid -C vim
  #     PID
  #    3283
  #    3392
  #
  #   atagar$ ps axc
  #     PID   TT  STAT      TIME COMMAND
  #       1   ??  Ss     9:00.22 launchd
  #      10   ??  Ss     0:09.97 kextd
  #      11   ??  Ss     5:47.36 DirectoryService
  #      12   ??  Ss     3:01.44 notifyd

  if is_available('ps'):
    if not is_bsd():
      # linux variant of ps
      results = call(GET_PID_BY_NAME_PS_LINUX % process_name, None)

      if results:
        try:
          pids = list(map(int, results[1:]))

          if multiple:
            return pids
          elif len(pids) == 1:
            return pids[0]
        except ValueError:
          pass

    if is_bsd():
      # bsd variant of ps
      results = call(GET_PID_BY_NAME_PS_BSD, None)

      if results:
        # filters results to those with our process name
        results = [r.split()[0] for r in results if r.endswith(' %s' % process_name)]

        try:
          pids = list(map(int, results))

          if multiple:
            return pids
          elif len(pids) == 1:
            return pids[0]
        except ValueError:
          pass

  # resolves using lsof which works on both Linux and BSD, only failing if:
  # - lsof is unavailable (not included by default on OpenBSD)
  # - the process being run as a different user due to permissions
  # - the process doesn't have any open files to be reported by lsof?
  #
  # flags:
  #   t - only show pids
  #   c - restrict results to that command
  #
  # example output:
  #   atagar@morrigan:~$ lsof -t -c vim
  #   2470
  #   2561

  if is_available('lsof'):
    results = call(GET_PID_BY_NAME_LSOF % process_name, None)

    if results:
      try:
        pids = list(map(int, results))

        if multiple:
          return pids
        elif len(pids) == 1:
          return pids[0]
      except ValueError:
        pass

  if is_available('tasklist') and is_windows():
    if not process_name.endswith('.exe'):
      process_name = process_name + '.exe'

    process_ids = []

    results = stem.util.system.call('tasklist', None)

    if results:
      tasklist_regex = re.compile('^\s*%s\s+(?P<pid>[0-9]*)' % process_name)

      for line in results:
        match = tasklist_regex.search(line)

        if match:
          process_ids.append(int(match.group('pid')))

      if multiple:
        return process_ids
      elif len(process_ids) > 0:
        return process_ids[0]

  log.debug("failed to resolve a pid for '%s'" % process_name)
  return [] if multiple else None


def pid_by_port(port):
  """
  Attempts to determine the process id for a process with the given port,
  using...

  ::

    1. netstat -npltu | grep 127.0.0.1:<port>
    2. sockstat -4l -P tcp -p <port>
    3. lsof -wnP -iTCP -sTCP:LISTEN | grep ":<port>"

  Most queries limit results to listening TCP connections. This function likely
  won't work on Mac OSX.

  :param int port: port where the process we're looking for is listening

  :returns: **int** with the process id, **None** if it can't be determined
  """

  # attempts to resolve using netstat, failing if:
  # - netstat doesn't accept these flags (Linux only)
  # - the process being run as a different user due to permissions
  #
  # flags:
  #   n - numeric (disables hostname lookups)
  #   p - program (include pids)
  #   l - listening (include listening sockets)
  #   tu - show tcp and udp sockets, and nothing else
  #
  # example output:
  #   atagar@morrigan:~$ netstat -npltu
  #   Active Internet connections (only servers)
  #   Proto Recv-Q Send-Q Local Address           Foreign Address   State    PID/Program name
  #   tcp        0      0 127.0.0.1:631           0.0.0.0:*         LISTEN   -
  #   tcp        0      0 127.0.0.1:9051          0.0.0.0:*         LISTEN   1641/tor
  #   tcp6       0      0 ::1:631                 :::*              LISTEN   -
  #   udp        0      0 0.0.0.0:5353            0.0.0.0:*                  -
  #   udp6       0      0 fe80::7ae4:ff:fe2f::123 :::*                       -

  if is_available('netstat'):
    results = call(GET_PID_BY_PORT_NETSTAT, None)

    if results:
      # filters to results with our port
      results = [r for r in results if '127.0.0.1:%s' % port in r]

      if len(results) == 1 and len(results[0].split()) == 7:
        results = results[0].split()[6]  # process field (ex. "7184/tor")
        pid = results[:results.find('/')]

        if pid.isdigit():
          return int(pid)

  # attempts to resolve using sockstat, failing if:
  # - sockstat doesn't accept the -4 flag (BSD only)
  # - sockstat isn't available (encountered with OSX 10.5.8)
  # - there are multiple instances using the same port on different addresses
  #
  # flags:
  #   4 - only show IPv4 sockets
  #   l - listening sockets
  #   P tcp - only show tcp connections
  #   p - only includes results if the local or foreign port match this
  #
  # example output:
  #   # sockstat -4 | grep tor
  #   _tor     tor        4397  7  tcp4   51.64.7.84:9050    *:*
  #   _tor     tor        4397  8  udp4   51.64.7.84:53      *:*
  #   _tor     tor        4397  12 tcp4   51.64.7.84:54011   80.3.121.7:9001
  #   _tor     tor        4397  15 tcp4   51.64.7.84:59374   7.42.1.102:9001
  #   _tor     tor        4397  20 tcp4   51.64.7.84:51946   32.83.7.104:443

  if is_available('sockstat'):
    results = call(GET_PID_BY_PORT_SOCKSTAT % port, None)

    if results:
      # filters to results where this is the local port
      results = [r for r in results if (len(r.split()) == 7 and (':%s' % port) in r.split()[5])]

      if len(results) == 1:
        pid = results[0].split()[2]

        if pid.isdigit():
          return int(pid)

  # resolves using lsof which works on both Linux and BSD, only failing if:
  # - lsof is unavailable (not included by default on OpenBSD)
  # - lsof doesn't provide the port ip/port, nor accept the -i and -s args
  #   (encountered with OSX 10.5.8)
  # - the process being run as a different user due to permissions
  # - there are multiple instances using the same port on different addresses
  #
  # flags:
  #   w - disables warning messages
  #   n - numeric addresses (disables hostname lookups)
  #   P - numeric ports (disables replacement of ports with their protocol)
  #   iTCP - only show tcp connections
  #   sTCP:LISTEN - listening sockets
  #
  # example output:
  #   atagar@morrigan:~$ lsof -wnP -iTCP -sTCP:LISTEN
  #   COMMAND  PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
  #   tor     1745 atagar    6u  IPv4  14229      0t0  TCP 127.0.0.1:9051 (LISTEN)

  if is_available('lsof'):
    results = call(GET_PID_BY_PORT_LSOF, None)

    if results:
      # filters to results with our port
      results = [r for r in results if (len(r.split()) == 10 and (':%s' % port) in r.split()[8])]

      if len(results) == 1:
        pid = results[0].split()[1]

        if pid.isdigit():
          return int(pid)

  return None  # all queries failed


def pid_by_open_file(path):
  """
  Attempts to determine the process id for a process with the given open file,
  using...

  ::

    lsof -w <path>

  :param str path: location of the socket file to query against

  :returns: **int** with the process id, **None** if it can't be determined
  """

  # resolves using lsof which works on both Linux and BSD, only failing if:
  # - lsof is unavailable (not included by default on OpenBSD)
  # - the file can't be read due to permissions
  #
  # flags:
  #   t - only show pids
  #   w - disables warning messages
  #
  # example output:
  #   atagar@morrigan:~$ lsof -tw /tmp/foo
  #   4762

  if is_available('lsof'):
    results = call(GET_PID_BY_FILE_LSOF % path, [])

    if len(results) == 1:
      pid = results[0].strip()

      if pid.isdigit():
        return int(pid)

  return None  # all queries failed


def cwd(pid):
  """
  Provides the working directory of the given process.

  :param int pid: process id of the process to be queried

  :returns: **str** with the absolute path for the process' present working
    directory, **None** if it can't be determined
  """

  # try fetching via the proc contents if it's available
  if stem.util.proc.is_available():
    try:
      return stem.util.proc.cwd(pid)
    except IOError:
      pass

  # Fall back to a pwdx query. This isn't available on BSD.
  logging_prefix = 'cwd(%s):' % pid

  if is_available('pwdx'):
    # pwdx results are of the form:
    # 3799: /home/atagar
    # 5839: No such process

    results = call(GET_CWD_PWDX % pid, None)

    if not results:
      log.debug("%s pwdx didn't return any results" % logging_prefix)
    elif results[0].endswith('No such process'):
      log.debug('%s pwdx processes reported for this pid' % logging_prefix)
    elif len(results) != 1 or results[0].count(' ') != 1 or not results[0].startswith('%s: ' % pid):
      log.debug('%s we got unexpected output from pwdx: %s' % (logging_prefix, results))
    else:
      return results[0].split(' ', 1)[1].strip()

  # Use lsof as the final fallback. This is available on both Linux and is the
  # only lookup method here that works for BSD...
  # https://trac.torproject.org/projects/tor/ticket/4236
  #
  # flags:
  #   a - presents the intersection of the following arguments
  #   p - limits results to this pid
  #   d cwd - limits results to just the cwd rather than all open files
  #   Fn - short listing in a single column, with just the pid and cwd
  #
  # example output:
  #   ~$ lsof -a -p 75717 -d cwd -Fn
  #   p75717
  #   n/Users/atagar/tor/src/or

  if is_available('lsof'):
    results = call(GET_CWD_LSOF % pid, [])

    if len(results) == 2 and results[1].startswith('n/'):
      lsof_result = results[1][1:].strip()

      # If we lack read permissions for the cwd then it returns...
      # p2683
      # n/proc/2683/cwd (readlink: Permission denied)

      if ' ' not in lsof_result:
        return lsof_result
    else:
      log.debug('%s we got unexpected output from lsof: %s' % (logging_prefix, results))

  return None  # all queries failed


def user(pid):
  """
  Provides the user a process is running under.

  :param int pid: process id of the process to be queried

  :returns: **str** with the username a process is running under, **None** if
    it can't be determined
  """

  if not isinstance(pid, int) or pid < 0:
    return None

  if stem.util.proc.is_available():
    try:
      import pwd  # only available on unix platforms

      uid = stem.util.proc.uid(pid)

      if uid and uid.isdigit():
        return pwd.getpwuid(int(uid)).pw_name
    except:
      pass

  if is_available('ps'):
    results = call('ps -o user %s' % pid, [])

    if len(results) >= 2:
      return results[1].strip()

  return None


def start_time(pid):
  """
  Provides the unix timestamp when the given process started.

  :param int pid: process id of the process to be queried

  :returns: **float** for the unix timestamp when the process began, **None**
    if it can't be determined
  """

  if not isinstance(pid, int) or pid < 0:
    return None

  if stem.util.proc.is_available():
    try:
      return float(stem.util.proc.stats(pid, stem.util.proc.Stat.START_TIME)[0])
    except IOError:
      pass

  try:
    ps_results = call('ps -p %s -o etime' % pid, [])

    if len(ps_results) >= 2:
      etime = ps_results[1].strip()
      return time.time() - stem.util.str_tools.parse_short_time_label(etime)
  except:
    pass

  return None


def tail(target, lines = None):
  """
  Provides lines of a file starting with the end. For instance,
  'tail -n 50 /tmp/my_log' could be done with...

  ::

    reversed(list(tail('/tmp/my_log', 50)))

  :param str,file target: path or file object to read from
  :param int lines: number of lines to read

  :returns: **generator** that reads lines, starting with the end

  :raises: **IOError** if unable to read the file
  """

  if isinstance(target, str):
    with open(target) as target_file:
      for line in tail(target_file, lines):
        yield line

      return

  # based on snippet from...
  # https://stackoverflow.com/questions/136168/get-last-n-lines-of-a-file-with-python-similar-to-tail

  target.seek(0, 2)  # go to the end of the file
  block_end_byte = target.tell()
  block_number = -1
  content = ''

  while (lines is None or lines > 0) and block_end_byte > 0:
    if (block_end_byte - BLOCK_SIZE > 0):
      # read the last block we haven't yet read
      target.seek(block_number * BLOCK_SIZE, 2)
      content, completed_lines = (target.read(BLOCK_SIZE) + content).split('\n', 1)
    else:
      # reached the start of the file, just read what's left
      target.seek(0, 0)
      completed_lines = target.read(block_end_byte) + content

    for line in reversed(completed_lines.splitlines()):
      if lines is None or lines > 0:
        if lines is not None:
          lines -= 1

        yield line

    block_end_byte -= BLOCK_SIZE
    block_number -= 1


def bsd_jail_id(pid):
  """
  Gets the jail id for a process. These seem to only exist for FreeBSD (this
  style for jails does not exist on Linux, OSX, or OpenBSD).

  :param int pid: process id of the jail id to be queried

  :returns: **int** for the jail id, zero if this can't be determined
  """

  # Output when called from a FreeBSD jail or when Tor isn't jailed:
  #   JID
  #    0
  #
  # Otherwise it's something like:
  #   JID
  #    1

  ps_output = call(GET_BSD_JAIL_ID_PS % pid, [])

  if len(ps_output) == 2 and len(ps_output[1].split()) == 1:
    jid = ps_output[1].strip()

    if jid.isdigit():
      return int(jid)

  os_name = platform.system()
  if os_name == 'FreeBSD':
    log.warn('Unable to get the jail id for process %s.' % pid)
  else:
    log.debug('bsd_jail_id(%s): jail ids do not exist on %s' % (pid, os_name))

  return 0


def bsd_jail_path(jid):
  """
  Provides the path of the given FreeBSD jail.

  :param int jid: jail id to be queried

  :returns: **str** of the path prefix, **None** if this can't be determined
  """

  if jid != 0:
    # Output should be something like:
    #    JID  IP Address      Hostname      Path
    #      1  10.0.0.2        tor-jail      /usr/jails/tor-jail

    jls_output = call(GET_BSD_JAIL_PATH % jid, [])

    if len(jls_output) == 2 and len(jls_output[1].split()) == 4:
      return jls_output[1].split()[3]

  return None


def is_tarfile(path):
  """
  Returns if the path belongs to a tarfile or not.

  .. versionadded:: 1.2.0

  :param str path: path to be checked

  :returns: **True** if the path belongs to a tarball, **False** otherwise
  """

  # Checking if it's a tar file may fail due to permissions so failing back
  # to the mime type...
  #
  #   IOError: [Errno 13] Permission denied: '/vmlinuz.old'
  #
  # With python 3 insuffient permissions raises an AttributeError instead...
  #
  #   http://bugs.python.org/issue17059

  try:
    return tarfile.is_tarfile(path)
  except (IOError, AttributeError):
    return mimetypes.guess_type(path)[0] == 'application/x-tar'


def expand_path(path, cwd = None):
  """
  Provides an absolute path, expanding tildes with the user's home and
  appending a current working directory if the path was relative.

  :param str path: path to be expanded
  :param str cwd: current working directory to expand relative paths with, our
    process' if this is **None**

  :returns: **str** of the path expanded to be an absolute path, never with an
    ending slash
  """

  if is_windows():
    relative_path = path.replace('/', '\\').rstrip('\\')
  else:
    relative_path = path.rstrip('/')

  if not relative_path or os.path.isabs(relative_path):
    # empty or already absolute - nothing to do
    pass
  elif relative_path.startswith('~'):
    # prefixed with a ~ or ~user entry
    relative_path = os.path.expanduser(relative_path)
  else:
    # relative path, expand with the cwd

    if not cwd:
      cwd = os.getcwd()

    # we'll be dealing with both "my/path/" and "./my/path" entries, so
    # cropping the later
    if relative_path.startswith('./') or relative_path.startswith('.\\'):
      relative_path = relative_path[2:]
    elif relative_path == '.':
      relative_path = ''

    if relative_path == '':
      relative_path = cwd
    else:
      relative_path = os.path.join(cwd, relative_path)

  return relative_path


def files_with_suffix(base_path, suffix):
  """
  Iterates over files in a given directory, providing filenames with a certain
  suffix.

  .. versionadded:: 1.2.0

  :param str base_path: directory to be iterated over
  :param str suffix: filename suffix to look for

  :returns: iterator that yields the absolute path for files with the given suffix
  """

  if os.path.isfile(base_path):
    if base_path.endswith(suffix):
      yield base_path
  else:
    for root, _, files in os.walk(base_path):
      for filename in files:
        if filename.endswith(suffix):
          yield os.path.join(root, filename)


def call(command, default = UNDEFINED, ignore_exit_status = False):
  """
  Issues a command in a subprocess, blocking until completion and returning the
  results. This is not actually ran in a shell so pipes and other shell syntax
  are not permitted.

  :param str,list command: command to be issued
  :param object default: response if the query fails
  :param bool ignore_exit_status: reports failure if our command's exit status
    was non-zero

  :returns: **list** with the lines of output from the command

  :raises: **OSError** if this fails and no default was provided
  """

  if isinstance(command, str):
    command_list = command.split(' ')
  else:
    command_list = command

  try:
    is_shell_command = command_list[0] in SHELL_COMMANDS

    start_time = time.time()
    process = subprocess.Popen(command_list, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = is_shell_command)

    stdout, stderr = process.communicate()
    stdout, stderr = stdout.strip(), stderr.strip()
    runtime = time.time() - start_time

    log.debug('System call: %s (runtime: %0.2f)' % (command, runtime))
    trace_prefix = 'Received from system (%s)' % command

    if stdout and stderr:
      log.trace(trace_prefix + ', stdout:\n%s\nstderr:\n%s' % (stdout, stderr))
    elif stdout:
      log.trace(trace_prefix + ', stdout:\n%s' % stdout)
    elif stderr:
      log.trace(trace_prefix + ', stderr:\n%s' % stderr)

    exit_code = process.poll()

    if not ignore_exit_status and exit_code != 0:
      raise OSError('%s returned exit status %i' % (command, exit_code))

    if stdout:
      return stdout.decode('utf-8', 'replace').splitlines()
    else:
      return []
  except OSError as exc:
    log.debug('System call (failed): %s (error: %s)' % (command, exc))

    if default != UNDEFINED:
      return default
    else:
      raise exc


def get_process_name():
  """
  Provides the present name of our process.

  :returns: **str** with the present name of our process
  """

  global _PROCESS_NAME, _MAX_NAME_LENGTH

  if _PROCESS_NAME is None:
    # Example output...
    #
    #   COMMAND
    #   python run_tests.py --unit

    ps_output = call('ps -p %i -o args' % os.getpid(), [])

    if len(ps_output) == 2 and ps_output[0] in ('COMMAND', 'ARGS'):
      _PROCESS_NAME = ps_output[1]
    else:
      # Falling back on using ctypes to get our argv. Unfortunately the simple
      # method for getting this...
      #
      #   ' '.join(['python'] + sys.argv)
      #
      # ... doesn't do the trick since this will miss interpreter arguments.
      #
      #   python -W ignore::DeprecationWarning my_script.py

      args, argc = [], argc_t()

      for i in range(100):
        # The ending index can be either None or raise a ValueError when
        # accessed...
        #
        # ValueError: NULL pointer access

        try:
          if argc[i] is None:
            break
        except ValueError:
          break

        args.append(str(argc[i]))

      _PROCESS_NAME = ' '.join(args)

    _MAX_NAME_LENGTH = len(_PROCESS_NAME)

  return _PROCESS_NAME


def set_process_name(process_name):
  """
  Renames our current process from "python <args>" to a custom name. This is
  best-effort, not necessarily working on all platforms.

  **Note:** This might have issues on FreeBSD (:trac:`9804`).

  :param str process_name: new name for our process
  """

  # This is mostly based on...
  #
  # http://www.rhinocerus.net/forum/lang-python/569677-setting-program-name-like-0-perl.html#post2272369
  #
  # ... and an adaptation by Jake...
  #
  # https://github.com/ioerror/chameleon
  #
  # A cleaner implementation is available at...
  #
  # https://github.com/cream/libs/blob/b38970e2a6f6d2620724c828808235be0445b799/cream/util/procname.py
  #
  # but I'm not quite clear on their implementation, and it only does targeted
  # argument replacement (ie, replace argv[0], argv[1], etc but with a string
  # the same size).

  _set_argv(process_name)

  if platform.system() == 'Linux':
    _set_prctl_name(process_name)
  elif platform.system() in ('Darwin', 'FreeBSD', 'OpenBSD'):
    _set_proc_title(process_name)


def _set_argv(process_name):
  """
  Overwrites our argv in a similar fashion to how it's done in C with:
  strcpy(argv[0], 'new_name');
  """

  if Py_GetArgcArgv is None:
    return

  global _PROCESS_NAME

  # both gets the current process name and initializes _MAX_NAME_LENGTH

  current_name = get_process_name()

  argv, argc = ctypes.c_int(0), argc_t()
  Py_GetArgcArgv(argv, ctypes.pointer(argc))

  if len(process_name) > _MAX_NAME_LENGTH:
    raise IOError("Can't rename process to something longer than our initial name (this would overwrite memory used for the env)")

  # space we need to clear
  zero_size = max(len(current_name), len(process_name))

  ctypes.memset(argc.contents, 0, zero_size + 1)  # null terminate the string's end
  process_name_encoded = process_name.encode('utf8')
  ctypes.memmove(argc.contents, process_name_encoded, len(process_name))
  _PROCESS_NAME = process_name


def _set_prctl_name(process_name):
  """
  Sets the prctl name, which is used by top and killall. This appears to be
  Linux specific and has the max of 15 characters.

  This is from...
  http://stackoverflow.com/questions/564695/is-there-a-way-to-change-effective-process-name-in-python/923034#923034
  """

  libc = ctypes.CDLL(ctypes.util.find_library('c'))
  name_buffer = ctypes.create_string_buffer(len(process_name) + 1)
  name_buffer.value = stem.util.str_tools._to_bytes(process_name)
  libc.prctl(PR_SET_NAME, ctypes.byref(name_buffer), 0, 0, 0)


def _set_proc_title(process_name):
  """
  BSD specific calls (should be compataible with both FreeBSD and OpenBSD:
  http://fxr.watson.org/fxr/source/gen/setproctitle.c?v=FREEBSD-LIBC
  http://www.rootr.net/man/man/setproctitle/3
  """

  libc = ctypes.CDLL(ctypes.util.find_library('c'))
  name_buffer = ctypes.create_string_buffer(len(process_name) + 1)
  name_buffer.value = process_name

  try:
    libc.setproctitle(ctypes.byref(name_buffer))
  except AttributeError:
    # Possible issue (seen on OSX):
    # AttributeError: dlsym(0x7fff6a41d1e0, setproctitle): symbol not found

    pass


# TODO: drop with stem 2.x
# We renamed our methods to drop a redundant 'get_*' prefix, so alias the old
# names for backward compatability.

get_name_by_pid = name_by_pid
get_pid_by_name = pid_by_name
get_pid_by_port = pid_by_port
get_pid_by_open_file = pid_by_open_file
get_cwd = cwd
get_user = user
get_start_time = start_time
get_bsd_jail_id = bsd_jail_id
get_bsd_jail_path = bsd_jail_path
