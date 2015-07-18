# Copyright 2011-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Handlers for text configuration files. Configurations are simple string to
string mappings, with the configuration files using the following rules...

* the key/value is separated by a space
* anything after a '#' is ignored as a comment
* excess whitespace is trimmed
* empty lines are ignored
* multi-line values can be defined by following the key with lines starting
  with a '|'

For instance...

::

  # This is my sample config
  user.name Galen
  user.password yabba1234 # here's an inline comment
  user.notes takes a fancy to pepperjack cheese
  blankEntry.example

  msg.greeting
  |Multi-line message exclaiming of the
  |wonder and awe that is pepperjack!

... would be loaded as...

::

  config = {
    'user.name': 'Galen',
    'user.password': 'yabba1234',
    'user.notes': 'takes a fancy to pepperjack cheese',
    'blankEntry.example': '',
    'msg.greeting': 'Multi-line message exclaiming of the\\nwonder and awe that is pepperjack!',
  }

Configurations are managed via the :class:`~stem.util.conf.Config` class. The
:class:`~stem.util.conf.Config` can be be used directly with its
:func:`~stem.util.conf.Config.get` and :func:`~stem.util.conf.Config.set`
methods, but usually modules will want a local dictionary with just the
configurations that it cares about.

To do this use the :func:`~stem.util.conf.config_dict` function. For example...

::

  import getpass
  from stem.util import conf, connection

  def config_validator(key, value):
    if key == 'timeout':
      # require at least a one second timeout
      return max(1, value)
    elif key == 'endpoint':
      if not connection.is_valid_ipv4_address(value):
        raise ValueError("'%s' isn't a valid IPv4 address" % value)
    elif key == 'port':
      if not connection.is_valid_port(value):
        raise ValueError("'%s' isn't a valid port" % value)
    elif key == 'retries':
      # negative retries really don't make sense
      return max(0, value)

  CONFIG = conf.config_dict('ssh_login', {
    'username': getpass.getuser(),
    'password': '',
    'timeout': 10,
    'endpoint': '263.12.8.0',
    'port': 22,
    'reconnect': False,
    'retries': 3,
  }, config_validator)

There's several things going on here so lets take it step by step...

* The :func:`~stem.util.conf.config_dict` provides a dictionary that's bound
  to a given configuration. If the "ssh_proxy_config" configuration changes
  then so will the contents of CONFIG.

* The dictionary we're passing to :func:`~stem.util.conf.config_dict` provides
  two important pieces of information: default values and their types. See the
  Config's :func:`~stem.util.conf.Config.get` method for how these type
  inferences work.

* The config_validator is a hook we're adding to make sure CONFIG only gets
  values we think are valid. In this case it ensures that our timeout value
  is at least one second, and rejects endpoints or ports that are invalid.

Now lets say our user has the following configuration file...

::

  username waddle_doo
  password jabberwocky
  timeout -15
  port 9000000
  retries lots
  reconnect true
  logging debug

... and we load it as follows...

::

  >>> from stem.util import conf
  >>> our_config = conf.get_config('ssh_login')
  >>> our_config.load('/home/atagar/user_config')
  >>> print CONFIG  # doctest: +SKIP
  {
    "username": "waddle_doo",
    "password": "jabberwocky",
    "timeout": 1,
    "endpoint": "263.12.8.0",
    "port": 22,
    "reconnect": True,
    "retries": 3,
  }

Here's an expanation of what happened...

* the username, password, and reconnect attributes took the values in the
  configuration file

* the 'config_validator' we added earlier allows for a minimum timeout of one
  and rejected the invalid port (with a log message)

* we weren't able to convert the retries' "lots" value to an integer so it kept
  its default value and logged a warning

* the user didn't supply an endpoint so that remained unchanged

* our CONFIG didn't have a 'logging' attribute so it was ignored

**Module Overview:**

::

  config_dict - provides a dictionary that's kept in sync with our config
  get_config - singleton for getting configurations
  uses_settings - provides an annotation for functions that use configurations
  parse_enum_csv - helper funcion for parsing confguration entries for enums

  Config - Custom configuration
    |- load - reads a configuration file
    |- save - writes the current configuration to a file
    |- clear - empties our loaded configuration contents
    |- add_listener - notifies the given listener when an update occurs
    |- clear_listeners - removes any attached listeners
    |- keys - provides keys in the loaded configuration
    |- set - sets the given key/value pair
    |- unused_keys - provides keys that have never been requested
    |- get - provides the value for a given key, with type inference
    +- get_value - provides the value for a given key as a string
"""

import inspect
import os
import threading

from stem.util import log

try:
  # added in python 2.7
  from collections import OrderedDict
except ImportError:
  from stem.util.ordereddict import OrderedDict

CONFS = {}  # mapping of identifier to singleton instances of configs


class _SyncListener(object):
  def __init__(self, config_dict, interceptor):
    self.config_dict = config_dict
    self.interceptor = interceptor

  def update(self, config, key):
    if key in self.config_dict:
      new_value = config.get(key, self.config_dict[key])

      if new_value == self.config_dict[key]:
        return  # no change

      if self.interceptor:
        interceptor_value = self.interceptor(key, new_value)

        if interceptor_value:
          new_value = interceptor_value

      self.config_dict[key] = new_value


def config_dict(handle, conf_mappings, handler = None):
  """
  Makes a dictionary that stays synchronized with a configuration.

  This takes a dictionary of 'config_key => default_value' mappings and
  changes the values to reflect our current configuration. This will leave
  the previous values alone if...

  * we don't have a value for that config_key
  * we can't convert our value to be the same type as the default_value

  If a handler is provided then this is called just prior to assigning new
  values to the config_dict. The handler function is expected to accept the
  (key, value) for the new values and return what we should actually insert
  into the dictionary. If this returns None then the value is updated as
  normal.

  For more information about how we convert types see our
  :func:`~stem.util.conf.Config.get` method.

  **The dictionary you get from this is manged by the
  :class:`~stem.util.conf.Config` class and should be treated as being
  read-only.**

  :param str handle: unique identifier for a config instance
  :param dict conf_mappings: config key/value mappings used as our defaults
  :param functor handler: function referred to prior to assigning values
  """

  selected_config = get_config(handle)
  selected_config.add_listener(_SyncListener(conf_mappings, handler).update)
  return conf_mappings


def get_config(handle):
  """
  Singleton constructor for configuration file instances. If a configuration
  already exists for the handle then it's returned. Otherwise a fresh instance
  is constructed.

  :param str handle: unique identifier used to access this config instance
  """

  if handle not in CONFS:
    CONFS[handle] = Config()

  return CONFS[handle]


def uses_settings(handle, path, lazy_load = True):
  """
  Provides a function that can be used as a decorator for other functions that
  require settings to be loaded. Functions with this decorator will be provided
  with the configuration as its 'config' keyword argument.

  .. versionchanged:: 1.3.0
     Omits the 'config' argument if the funcion we're decorating doesn't accept
     it.

  ::

    uses_settings = stem.util.conf.uses_settings('my_app', '/path/to/settings.cfg')

    @uses_settings
    def my_function(config):
      print 'hello %s!' % config.get('username', '')

  :param str handle: hande for the configuration
  :param str path: path where the configuration should be loaded from
  :param bool lazy_load: loads the configuration file when the decorator is
    used if true, otherwise it's loaded right away

  :returns: **function** that can be used as a decorator to provide the
    configuration

  :raises: **IOError** if we fail to read the configuration file, if
    **lazy_load** is true then this arises when we use the decorator
  """

  config = get_config(handle)

  if not lazy_load and not config.get('settings_loaded', False):
    config.load(path)
    config.set('settings_loaded', 'true')

  def decorator(func):
    def wrapped(*args, **kwargs):
      if lazy_load and not config.get('settings_loaded', False):
        config.load(path)
        config.set('settings_loaded', 'true')

      if 'config' in inspect.getargspec(func).args:
        return func(*args, config = config, **kwargs)
      else:
        return func(*args, **kwargs)

    return wrapped

  return decorator


def parse_enum(key, value, enumeration):
  """
  Provides the enumeration value for a given key. This is a case insensitive
  lookup and raises an exception if the enum key doesn't exist.

  :param str key: configuration key being looked up
  :param str value: value to be parsed
  :param stem.util.enum.Enum enumeration: enumeration the values should be in

  :returns: enumeration value

  :raises: **ValueError** if the **value** isn't among the enumeration keys
  """

  return parse_enum_csv(key, value, enumeration, 1)[0]


def parse_enum_csv(key, value, enumeration, count = None):
  """
  Parses a given value as being a comma separated listing of enumeration keys,
  returning the corresponding enumeration values. This is intended to be a
  helper for config handlers. The checks this does are case insensitive.

  The **count** attribute can be used to make assertions based on the number of
  values. This can be...

  * None to indicate that there's no restrictions.
  * An int to indicate that we should have this many values.
  * An (int, int) tuple to indicate the range that values can be in. This range
    is inclusive and either can be None to indicate the lack of a lower or
    upper bound.

  :param str key: configuration key being looked up
  :param str value: value to be parsed
  :param stem.util.enum.Enum enumeration: enumeration the values should be in
  :param int,tuple count: validates that we have this many items

  :returns: list with the enumeration values

  :raises: **ValueError** if the count assertion fails or the **value** entries
    don't match the enumeration keys
  """

  values = [val.upper().strip() for val in value.split(',')]

  if values == ['']:
    return []

  if count is None:
    pass  # no count validateion checks to do
  elif isinstance(count, int):
    if len(values) != count:
      raise ValueError("Config entry '%s' is expected to be %i comma separated values, got '%s'" % (key, count, value))
  elif isinstance(count, tuple) and len(count) == 2:
    minimum, maximum = count

    if minimum is not None and len(values) < minimum:
      raise ValueError("Config entry '%s' must have at least %i comma separated values, got '%s'" % (key, minimum, value))

    if maximum is not None and len(values) > maximum:
      raise ValueError("Config entry '%s' can have at most %i comma separated values, got '%s'" % (key, maximum, value))
  else:
    raise ValueError("The count must be None, an int, or two value tuple. Got '%s' (%s)'" % (count, type(count)))

  result = []
  enum_keys = [k.upper() for k in list(enumeration.keys())]
  enum_values = list(enumeration)

  for val in values:
    if val in enum_keys:
      result.append(enum_values[enum_keys.index(val)])
    else:
      raise ValueError("The '%s' entry of config entry '%s' wasn't in the enumeration (expected %s)" % (val, key, ', '.join(enum_keys)))

  return result


class Config(object):
  """
  Handler for easily working with custom configurations, providing persistence
  to and from files. All operations are thread safe.

  **Example usage:**

  User has a file at '/home/atagar/myConfig' with...

  ::

    destination.ip 1.2.3.4
    destination.port blarg

    startup.run export PATH=$PATH:~/bin
    startup.run alias l=ls

  And they have a script with...

  ::

    from stem.util import conf

    # Configuration values we'll use in this file. These are mappings of
    # configuration keys to the default values we'll use if the user doesn't
    # have something different in their config file (or it doesn't match this
    # type).

    ssh_config = conf.config_dict('ssh_login', {
      'login.user': 'atagar',
      'login.password': 'pepperjack_is_awesome!',
      'destination.ip': '127.0.0.1',
      'destination.port': 22,
      'startup.run': [],
    })

    # Makes an empty config instance with the handle of 'ssh_login'. This is
    # a singleton so other classes can fetch this same configuration from
    # this handle.

    user_config = conf.get_config('ssh_login')

    # Loads the user's configuration file, warning if this fails.

    try:
      user_config.load("/home/atagar/myConfig")
    except IOError as exc:
      print "Unable to load the user's config: %s" % exc

    # This replace the contents of ssh_config with the values from the user's
    # config file if...
    #
    # * the key is present in the config file
    # * we're able to convert the configuration file's value to the same type
    #   as what's in the mapping (see the Config.get() method for how these
    #   type inferences work)
    #
    # For instance in this case...
    #
    # * the login values are left alone because they aren't in the user's
    #   config file
    #
    # * the 'destination.port' is also left with the value of 22 because we
    #   can't turn "blarg" into an integer
    #
    # The other values are replaced, so ssh_config now becomes...
    #
    # {'login.user': 'atagar',
    #  'login.password': 'pepperjack_is_awesome!',
    #  'destination.ip': '1.2.3.4',
    #  'destination.port': 22,
    #  'startup.run': ['export PATH=$PATH:~/bin', 'alias l=ls']}
    #
    # Information for what values fail to load and why are reported to
    # 'stem.util.log'.
  """

  def __init__(self):
    self._path = None        # location we last loaded from or saved to
    self._contents = {}      # configuration key/value pairs
    self._listeners = []     # functors to be notified of config changes

    # used for accessing _contents
    self._contents_lock = threading.RLock()

    # keys that have been requested (used to provide unused config contents)
    self._requested_keys = set()

  def load(self, path = None):
    """
    Reads in the contents of the given path, adding its configuration values
    to our current contents. If the path is a directory then this loads each
    of the files, recursively.

    .. versionchanged:: 1.3.0
       Added support for directories.

    :param str path: file or directory path to be loaded, this uses the last
      loaded path if not provided

    :raises:
      * **IOError** if we fail to read the file (it doesn't exist, insufficient
        permissions, etc)
      * **ValueError** if no path was provided and we've never been provided one
    """

    if path:
      self._path = path
    elif not self._path:
      raise ValueError('Unable to load configuration: no path provided')

    if os.path.isdir(self._path):
      for root, dirnames, filenames in os.walk(self._path):
        for filename in filenames:
          self.load(os.path.join(root, filename))

      return

    with open(self._path, 'r') as config_file:
      read_contents = config_file.readlines()

    with self._contents_lock:
      while read_contents:
        line = read_contents.pop(0)

        # strips any commenting or excess whitespace
        comment_start = line.find('#')

        if comment_start != -1:
          line = line[:comment_start]

        line = line.strip()

        # parse the key/value pair
        if line:
          try:
            key, value = line.split(' ', 1)
            value = value.strip()
          except ValueError:
            log.debug("Config entry '%s' is expected to be of the format 'Key Value', defaulting to '%s' -> ''" % (line, line))
            key, value = line, ''

          if not value:
            # this might be a multi-line entry, try processing it as such
            multiline_buffer = []

            while read_contents and read_contents[0].lstrip().startswith('|'):
              content = read_contents.pop(0).lstrip()[1:]  # removes '\s+|' prefix
              content = content.rstrip('\n')  # trailing newline
              multiline_buffer.append(content)

            if multiline_buffer:
              self.set(key, '\n'.join(multiline_buffer), False)
              continue

          self.set(key, value, False)

  def save(self, path = None):
    """
    Saves configuration contents to disk. If a path is provided then it
    replaces the configuration location that we track.

    :param str path: location to be saved to

    :raises: **ValueError** if no path was provided and we've never been provided one
    """

    if path:
      self._path = path
    elif not self._path:
      raise ValueError('Unable to save configuration: no path provided')

    with self._contents_lock:
      with open(self._path, 'w') as output_file:
        for entry_key in sorted(self.keys()):
          for entry_value in self.get_value(entry_key, multiple = True):
            # check for multi line entries
            if '\n' in entry_value:
              entry_value = '\n|' + entry_value.replace('\n', '\n|')

            output_file.write('%s %s\n' % (entry_key, entry_value))

  def clear(self):
    """
    Drops the configuration contents and reverts back to a blank, unloaded
    state.
    """

    with self._contents_lock:
      self._contents.clear()
      self._requested_keys = set()

  def add_listener(self, listener, backfill = True):
    """
    Registers the function to be notified of configuration updates. Listeners
    are expected to be functors which accept (config, key).

    :param functor listener: function to be notified when our configuration is changed
    :param bool backfill: calls the function with our current values if **True**
    """

    with self._contents_lock:
      self._listeners.append(listener)

      if backfill:
        for key in self.keys():
          listener(self, key)

  def clear_listeners(self):
    """
    Removes all attached listeners.
    """

    self._listeners = []

  def keys(self):
    """
    Provides all keys in the currently loaded configuration.

    :returns: **list** if strings for the configuration keys we've loaded
    """

    return list(self._contents.keys())

  def unused_keys(self):
    """
    Provides the configuration keys that have never been provided to a caller
    via :func:`~stem.util.conf.config_dict` or the
    :func:`~stem.util.conf.Config.get` and
    :func:`~stem.util.conf.Config.get_value` methods.

    :returns: **set** of configuration keys we've loaded but have never been requested
    """

    return set(self.keys()).difference(self._requested_keys)

  def set(self, key, value, overwrite = True):
    """
    Appends the given key/value configuration mapping, behaving the same as if
    we'd loaded this from a configuration file.

    :param str key: key for the configuration mapping
    :param str,list value: value we're setting the mapping to
    :param bool overwrite: replaces the previous value if **True**, otherwise
      the values are appended
    """

    with self._contents_lock:
      if isinstance(value, str):
        if not overwrite and key in self._contents:
          self._contents[key].append(value)
        else:
          self._contents[key] = [value]

        for listener in self._listeners:
          listener(self, key)
      elif isinstance(value, (list, tuple)):
        if not overwrite and key in self._contents:
          self._contents[key] += value
        else:
          self._contents[key] = value

        for listener in self._listeners:
          listener(self, key)
      else:
        raise ValueError("Config.set() only accepts str, list, or tuple. Provided value was a '%s'" % type(value))

  def get(self, key, default = None):
    """
    Fetches the given configuration, using the key and default value to
    determine the type it should be. Recognized inferences are:

    * **default is a boolean => boolean**

      * values are case insensitive
      * provides the default if the value isn't "true" or "false"

    * **default is an integer => int**

      * provides the default if the value can't be converted to an int

    * **default is a float => float**

      * provides the default if the value can't be converted to a float

    * **default is a list => list**

      * string contents for all configuration values with this key

    * **default is a tuple => tuple**

      * string contents for all configuration values with this key

    * **default is a dictionary => dict**

      * values without "=>" in them are ignored
      * values are split into key/value pairs on "=>" with extra whitespace
        stripped

    :param str key: config setting to be fetched
    :param default object: value provided if no such key exists or fails to be converted

    :returns: given configuration value with its type inferred with the above rules
    """

    is_multivalue = isinstance(default, (list, tuple, dict))
    val = self.get_value(key, default, is_multivalue)

    if val == default:
      return val  # don't try to infer undefined values

    if isinstance(default, bool):
      if val.lower() == 'true':
        val = True
      elif val.lower() == 'false':
        val = False
      else:
        log.debug("Config entry '%s' is expected to be a boolean, defaulting to '%s'" % (key, str(default)))
        val = default
    elif isinstance(default, int):
      try:
        val = int(val)
      except ValueError:
        log.debug("Config entry '%s' is expected to be an integer, defaulting to '%i'" % (key, default))
        val = default
    elif isinstance(default, float):
      try:
        val = float(val)
      except ValueError:
        log.debug("Config entry '%s' is expected to be a float, defaulting to '%f'" % (key, default))
        val = default
    elif isinstance(default, list):
      val = list(val)  # make a shallow copy
    elif isinstance(default, tuple):
      val = tuple(val)
    elif isinstance(default, dict):
      val_map = OrderedDict()
      for entry in val:
        if '=>' in entry:
          entry_key, entry_val = entry.split('=>', 1)
          val_map[entry_key.strip()] = entry_val.strip()
        else:
          log.debug('Ignoring invalid %s config entry (expected a mapping, but "%s" was missing "=>")' % (key, entry))
      val = val_map

    return val

  def get_value(self, key, default = None, multiple = False):
    """
    This provides the current value associated with a given key.

    :param str key: config setting to be fetched
    :param object default: value provided if no such key exists
    :param bool multiple: provides back a list of all values if **True**,
      otherwise this returns the last loaded configuration value

    :returns: **str** or **list** of string configuration values associated
      with the given key, providing the default if no such key exists
    """

    with self._contents_lock:
      if key in self._contents:
        self._requested_keys.add(key)

        if multiple:
          return self._contents[key]
        else:
          return self._contents[key][-1]
      else:
        message_id = 'stem.util.conf.missing_config_key_%s' % key
        log.log_once(message_id, log.TRACE, "config entry '%s' not found, defaulting to '%s'" % (key, default))
        return default
