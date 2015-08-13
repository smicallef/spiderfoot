# Copyright 2011-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Helper functions for querying process and system information from the /proc
contents. Fetching information this way provides huge performance benefits
over lookups via system utilities (ps, netstat, etc). For instance, resolving
connections this way cuts the runtime by around 90% verses the alternatives.
These functions may not work on all platforms (only Linux?).

The method for reading these files (and a little code) are borrowed from
`psutil <https://code.google.com/p/psutil/>`_, which was written by Jay Loden,
Dave Daeschler, Giampaolo Rodola' and is under the BSD license.

**These functions are not being vended to stem users. They may change in the
future, use them at your own risk.**

.. versionchanged:: 1.3.0
   Dropped the get_* prefix from several function names. The old names still
   work, but are deprecated aliases.

**Module Overview:**

::

  is_available - checks if proc utilities can be used on this system
  system_start_time - unix timestamp for when the system started
  physical_memory - memory available on this system
  cwd - provides the current working directory for a process
  uid - provides the user id a process is running under
  memory_usage - provides the memory usage of a process
  stats - queries statistics about a process
  file_descriptors_used - number of file descriptors used by a process
  connections - provides the connections made by a process

.. data:: Stat (enum)

  Types of data available via the :func:`~stem.util.proc.stats` function.

  ============== ===========
  Stat           Description
  ============== ===========
  **COMMAND**    command name under which the process is running
  **CPU_UTIME**  total user time spent on the process
  **CPU_STIME**  total system time spent on the process
  **START_TIME** when this process began, in unix time
  ============== ===========
"""

import base64
import os
import platform
import socket
import sys
import time

import stem.util.enum

from stem.util import log

try:
  # added in python 3.2
  from functools import lru_cache
except ImportError:
  from stem.util.lru_cache import lru_cache

# os.sysconf is only defined on unix
try:
  CLOCK_TICKS = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
except AttributeError:
  CLOCK_TICKS = None

Stat = stem.util.enum.Enum(
  ('COMMAND', 'command'), ('CPU_UTIME', 'utime'),
  ('CPU_STIME', 'stime'), ('START_TIME', 'start time')
)


@lru_cache()
def is_available():
  """
  Checks if proc information is available on this platform.

  :returns: **True** if proc contents exist on this platform, **False** otherwise
  """

  if platform.system() != 'Linux':
    return False
  else:
    # list of process independent proc paths we use
    proc_paths = ('/proc/stat', '/proc/meminfo', '/proc/net/tcp', '/proc/net/udp')

    for path in proc_paths:
      if not os.path.exists(path):
        return False

    return True


@lru_cache()
def system_start_time():
  """
  Provides the unix time (seconds since epoch) when the system started.

  :returns: **float** for the unix time of when the system started

  :raises: **IOError** if it can't be determined
  """

  start_time, parameter = time.time(), 'system start time'
  btime_line = _get_line('/proc/stat', 'btime', parameter)

  try:
    result = float(btime_line.strip().split()[1])
    _log_runtime(parameter, '/proc/stat[btime]', start_time)
    return result
  except:
    exc = IOError('unable to parse the /proc/stat btime entry: %s' % btime_line)
    _log_failure(parameter, exc)
    raise exc


@lru_cache()
def physical_memory():
  """
  Provides the total physical memory on the system in bytes.

  :returns: **int** for the bytes of physical memory this system has

  :raises: **IOError** if it can't be determined
  """

  start_time, parameter = time.time(), 'system physical memory'
  mem_total_line = _get_line('/proc/meminfo', 'MemTotal:', parameter)

  try:
    result = int(mem_total_line.split()[1]) * 1024
    _log_runtime(parameter, '/proc/meminfo[MemTotal]', start_time)
    return result
  except:
    exc = IOError('unable to parse the /proc/meminfo MemTotal entry: %s' % mem_total_line)
    _log_failure(parameter, exc)
    raise exc


def cwd(pid):
  """
  Provides the current working directory for the given process.

  :param int pid: process id of the process to be queried

  :returns: **str** with the path of the working directory for the process

  :raises: **IOError** if it can't be determined
  """

  start_time, parameter = time.time(), 'cwd'
  proc_cwd_link = '/proc/%s/cwd' % pid

  if pid == 0:
    cwd = ''
  else:
    try:
      cwd = os.readlink(proc_cwd_link)
    except OSError:
      exc = IOError('unable to read %s' % proc_cwd_link)
      _log_failure(parameter, exc)
      raise exc

  _log_runtime(parameter, proc_cwd_link, start_time)
  return cwd


def uid(pid):
  """
  Provides the user ID the given process is running under.

  :param int pid: process id of the process to be queried

  :returns: **int** with the user id for the owner of the process

  :raises: **IOError** if it can't be determined
  """

  start_time, parameter = time.time(), 'uid'
  status_path = '/proc/%s/status' % pid
  uid_line = _get_line(status_path, 'Uid:', parameter)

  try:
    result = int(uid_line.split()[1])
    _log_runtime(parameter, '%s[Uid]' % status_path, start_time)
    return result
  except:
    exc = IOError('unable to parse the %s Uid entry: %s' % (status_path, uid_line))
    _log_failure(parameter, exc)
    raise exc


def memory_usage(pid):
  """
  Provides the memory usage in bytes for the given process.

  :param int pid: process id of the process to be queried

  :returns: **tuple** of two ints with the memory usage of the process, of the
    form **(resident_size, virtual_size)**

  :raises: **IOError** if it can't be determined
  """

  # checks if this is the kernel process

  if pid == 0:
    return (0, 0)

  start_time, parameter = time.time(), 'memory usage'
  status_path = '/proc/%s/status' % pid
  mem_lines = _get_lines(status_path, ('VmRSS:', 'VmSize:'), parameter)

  try:
    residentSize = int(mem_lines['VmRSS:'].split()[1]) * 1024
    virtualSize = int(mem_lines['VmSize:'].split()[1]) * 1024

    _log_runtime(parameter, '%s[VmRSS|VmSize]' % status_path, start_time)
    return (residentSize, virtualSize)
  except:
    exc = IOError('unable to parse the %s VmRSS and VmSize entries: %s' % (status_path, ', '.join(mem_lines)))
    _log_failure(parameter, exc)
    raise exc


def stats(pid, *stat_types):
  """
  Provides process specific information. See the :data:`~stem.util.proc.Stat`
  enum for valid options.

  :param int pid: process id of the process to be queried
  :param Stat stat_types: information to be provided back

  :returns: **tuple** with all of the requested statistics as strings

  :raises: **IOError** if it can't be determined
  """

  if CLOCK_TICKS is None:
    raise IOError('Unable to look up SC_CLK_TCK')

  start_time, parameter = time.time(), 'process %s' % ', '.join(stat_types)

  # the stat file contains a single line, of the form...
  # 8438 (tor) S 8407 8438 8407 34818 8438 4202496...
  stat_path = '/proc/%s/stat' % pid
  stat_line = _get_line(stat_path, str(pid), parameter)

  # breaks line into component values
  stat_comp = []
  cmd_start, cmd_end = stat_line.find('('), stat_line.find(')')

  if cmd_start != -1 and cmd_end != -1:
    stat_comp.append(stat_line[:cmd_start])
    stat_comp.append(stat_line[cmd_start + 1:cmd_end])
    stat_comp += stat_line[cmd_end + 1:].split()

  if len(stat_comp) < 44 and _is_float(stat_comp[13], stat_comp[14], stat_comp[21]):
    exc = IOError('stat file had an unexpected format: %s' % stat_path)
    _log_failure(parameter, exc)
    raise exc

  results = []
  for stat_type in stat_types:
    if stat_type == Stat.COMMAND:
      if pid == 0:
        results.append('sched')
      else:
        results.append(stat_comp[1])
    elif stat_type == Stat.CPU_UTIME:
      if pid == 0:
        results.append('0')
      else:
        results.append(str(float(stat_comp[13]) / CLOCK_TICKS))
    elif stat_type == Stat.CPU_STIME:
      if pid == 0:
        results.append('0')
      else:
        results.append(str(float(stat_comp[14]) / CLOCK_TICKS))
    elif stat_type == Stat.START_TIME:
      if pid == 0:
        return system_start_time()
      else:
        # According to documentation, starttime is in field 21 and the unit is
        # jiffies (clock ticks). We divide it for clock ticks, then add the
        # uptime to get the seconds since the epoch.
        p_start_time = float(stat_comp[21]) / CLOCK_TICKS
        results.append(str(p_start_time + system_start_time()))

  _log_runtime(parameter, stat_path, start_time)
  return tuple(results)


def file_descriptors_used(pid):
  """
  Provides the number of file descriptors currently being used by a process.

  .. versionadded:: 1.3.0

  :param int pid: process id of the process to be queried

  :returns: **int** of the number of file descriptors used

  :raises: **IOError** if it can't be determined
  """

  try:
    pid = int(pid)

    if pid < 0:
      raise IOError("Process pids can't be negative: %s" % pid)
  except (ValueError, TypeError):
    raise IOError('Process pid was non-numeric: %s' % pid)

  try:
    return len(os.listdir('/proc/%i/fd' % pid))
  except Exception as exc:
    raise IOError('Unable to check number of file descriptors used: %s' % exc)


def connections(pid):
  """
  Queries connection related information from the proc contents. This provides
  similar results to netstat, lsof, sockstat, and other connection resolution
  utilities (though the lookup is far quicker).

  :param int pid: process id of the process to be queried

  :returns: A listing of connection tuples of the form **[(local_ipAddr1,
    local_port1, foreign_ipAddr1, foreign_port1, protocol), ...]** (addresses
    and protocols are strings and ports are ints)

  :raises: **IOError** if it can't be determined
  """

  try:
    pid = int(pid)

    if pid < 0:
      raise IOError("Process pids can't be negative: %s" % pid)
  except (ValueError, TypeError):
    raise IOError('Process pid was non-numeric: %s' % pid)

  if pid == 0:
    return []

  # fetches the inode numbers for socket file descriptors

  start_time, parameter = time.time(), 'process connections'
  inodes = []

  for fd in os.listdir('/proc/%s/fd' % pid):
    fd_path = '/proc/%s/fd/%s' % (pid, fd)

    try:
      # File descriptor link, such as 'socket:[30899]'

      fd_name = os.readlink(fd_path)

      if fd_name.startswith('socket:['):
        inodes.append(fd_name[8:-1])
    except OSError as exc:
      if not os.path.exists(fd_path):
        continue  # descriptors may shift while we're in the middle of iterating over them

      # most likely couldn't be read due to permissions
      exc = IOError('unable to determine file descriptor destination (%s): %s' % (exc, fd_path))
      _log_failure(parameter, exc)
      raise exc

  if not inodes:
    # unable to fetch any connections for this process
    return []

  # check for the connection information from the /proc/net contents

  conn = []

  for proc_file_path in ('/proc/net/tcp', '/proc/net/udp'):
    try:
      proc_file = open(proc_file_path)
      proc_file.readline()  # skip the first line

      for line in proc_file:
        _, l_addr, f_addr, status, _, _, _, _, _, inode = line.split()[:10]

        if inode in inodes:
          # if a tcp connection, skip if it isn't yet established
          if proc_file_path.endswith('/tcp') and status != '01':
            continue

          local_ip, local_port = _decode_proc_address_encoding(l_addr)
          foreign_ip, foreign_port = _decode_proc_address_encoding(f_addr)
          protocol = proc_file_path[10:]
          conn.append((local_ip, local_port, foreign_ip, foreign_port, protocol))

      proc_file.close()
    except IOError as exc:
      exc = IOError("unable to read '%s': %s" % (proc_file_path, exc))
      _log_failure(parameter, exc)
      raise exc
    except Exception as exc:
      exc = IOError("unable to parse '%s': %s" % (proc_file_path, exc))
      _log_failure(parameter, exc)
      raise exc

  _log_runtime(parameter, '/proc/net/[tcp|udp]', start_time)
  return conn


def _decode_proc_address_encoding(addr):
  """
  Translates an address entry in the /proc/net/* contents to a human readable
  form (`reference <http://linuxdevcenter.com/pub/a/linux/2000/11/16/LinuxAdmin.html>`_,
  for instance:

  ::

    "0500000A:0016" -> ("10.0.0.5", 22)

  :param str addr: proc address entry to be decoded

  :returns: **tuple** of the form **(addr, port)**, with addr as a string and port an int
  """

  ip, port = addr.split(':')

  # the port is represented as a two-byte hexadecimal number
  port = int(port, 16)

  if sys.version_info >= (3,):
    ip = ip.encode('ascii')

  # The IPv4 address portion is a little-endian four-byte hexadecimal number.
  # That is, the least significant byte is listed first, so we need to reverse
  # the order of the bytes to convert it to an IP address.
  #
  # This needs to account for the endian ordering as per...
  # http://code.google.com/p/psutil/issues/detail?id=201
  # https://trac.torproject.org/projects/tor/ticket/4777

  if sys.byteorder == 'little':
    ip = socket.inet_ntop(socket.AF_INET, base64.b16decode(ip)[::-1])
  else:
    ip = socket.inet_ntop(socket.AF_INET, base64.b16decode(ip))

  return (ip, port)


def _is_float(*value):
  try:
    for v in value:
      float(v)

    return True
  except ValueError:
    return False


def _get_line(file_path, line_prefix, parameter):
  return _get_lines(file_path, (line_prefix, ), parameter)[line_prefix]


def _get_lines(file_path, line_prefixes, parameter):
  """
  Fetches lines with the given prefixes from a file. This only provides back
  the first instance of each prefix.

  :param str file_path: path of the file to read
  :param tuple line_prefixes: string prefixes of the lines to return
  :param str parameter: description of the proc attribute being fetch

  :returns: mapping of prefixes to the matching line

  :raises: **IOError** if unable to read the file or can't find all of the prefixes
  """

  try:
    remaining_prefixes = list(line_prefixes)
    proc_file, results = open(file_path), {}

    for line in proc_file:
      if not remaining_prefixes:
        break  # found everything we're looking for

      for prefix in remaining_prefixes:
        if line.startswith(prefix):
          results[prefix] = line
          remaining_prefixes.remove(prefix)
          break

    proc_file.close()

    if remaining_prefixes:
      if len(remaining_prefixes) == 1:
        msg = '%s did not contain a %s entry' % (file_path, remaining_prefixes[0])
      else:
        msg = '%s did not contain %s entries' % (file_path, ', '.join(remaining_prefixes))

      raise IOError(msg)
    else:
      return results
  except IOError as exc:
    _log_failure(parameter, exc)
    raise exc


def _log_runtime(parameter, proc_location, start_time):
  """
  Logs a message indicating a successful proc query.

  :param str parameter: description of the proc attribute being fetch
  :param str proc_location: proc files we were querying
  :param int start_time: unix time for when this query was started
  """

  runtime = time.time() - start_time
  log.debug('proc call (%s): %s (runtime: %0.4f)' % (parameter, proc_location, runtime))


def _log_failure(parameter, exc):
  """
  Logs a message indicating that the proc query failed.

  :param str parameter: description of the proc attribute being fetch
  :param Exception exc: exception that we're raising
  """

  log.debug('proc call failed (%s): %s' % (parameter, exc))

# TODO: drop with stem 2.x
# We renamed our methods to drop a redundant 'get_*' prefix, so alias the old
# names for backward compatability.

get_system_start_time = system_start_time
get_physical_memory = physical_memory
get_cwd = cwd
get_uid = uid
get_memory_usage = memory_usage
get_stats = stats
get_connections = connections
