# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Utilities for reading descriptors from local directories and archives. This is
mostly done through the :class:`~stem.descriptor.reader.DescriptorReader`
class, which is an iterator for the descriptor data in a series of
destinations. For example...

::

  my_descriptors = [
    '/tmp/server-descriptors-2012-03.tar.bz2',
    '/tmp/archived_descriptors/',
  ]

  # prints the contents of all the descriptor files
  with DescriptorReader(my_descriptors) as reader:
    for descriptor in reader:
      print descriptor

This ignores files that cannot be processed due to read errors or unparsable
content. To be notified of skipped files you can register a listener with
:func:`~stem.descriptor.reader.DescriptorReader.register_skip_listener`.

The :class:`~stem.descriptor.reader.DescriptorReader` keeps track of the last
modified timestamps for descriptor files that it has read so it can skip
unchanged files if run again. This listing of processed files can also be
persisted and applied to other
:class:`~stem.descriptor.reader.DescriptorReader` instances. For example, the
following prints descriptors as they're changed over the course of a minute,
and picks up where it left off if run again...

::

  reader = DescriptorReader(['/tmp/descriptor_data'])

  try:
    processed_files = load_processed_files('/tmp/used_descriptors')
    reader.set_processed_files(processed_files)
  except: pass # could not load, maybe this is the first run

  start_time = time.time()

  while (time.time() - start_time) < 60:
    # prints any descriptors that have changed since last checked
    with reader:
      for descriptor in reader:
        print descriptor

    time.sleep(1)

  save_processed_files('/tmp/used_descriptors', reader.get_processed_files())

**Module Overview:**

::

  load_processed_files - Loads a listing of processed files
  save_processed_files - Saves a listing of processed files

  DescriptorReader - Iterator for descriptor data on the local file system
    |- get_processed_files - provides the listing of files that we've processed
    |- set_processed_files - sets our tracking of the files we have processed
    |- register_read_listener - adds a listener for when files are read
    |- register_skip_listener - adds a listener that's notified of skipped files
    |- start - begins reading descriptor data
    |- stop - stops reading descriptor data
    |- __enter__ / __exit__ - manages the descriptor reader thread in the context
    +- __iter__ - iterates over descriptor data in unread files

  FileSkipped - Base exception for a file that was skipped
    |- AlreadyRead - We've already read a file with this last modified timestamp
    |- ParsingFailure - Contents can't be parsed as descriptor data
    |- UnrecognizedType - File extension indicates non-descriptor data
    +- ReadFailed - Wraps an error that was raised while reading the file
       +- FileMissing - File does not exist
"""

import mimetypes
import os
import tarfile
import threading

try:
  import queue
except ImportError:
  import Queue as queue

import stem.descriptor
import stem.prereq
import stem.util.system

from stem import str_type

# flag to indicate when the reader thread is out of descriptor files to read
FINISHED = 'DONE'


class FileSkipped(Exception):
  "Base error when we can't provide descriptor data from a file."


class AlreadyRead(FileSkipped):
  """
  Already read a file with this 'last modified' timestamp or later.

  :param int last_modified: unix timestamp for when the file was last modified
  :param int last_modified_when_read: unix timestamp for the modification time
    when we last read this file
  """

  def __init__(self, last_modified, last_modified_when_read):
    super(AlreadyRead, self).__init__('File has already been read since it was last modified. modification time: %s, last read: %s' % (last_modified, last_modified_when_read))
    self.last_modified = last_modified
    self.last_modified_when_read = last_modified_when_read


class ParsingFailure(FileSkipped):
  """
  File contents could not be parsed as descriptor data.

  :param ValueError exception: issue that arose when parsing
  """

  def __init__(self, parsing_exception):
    super(ParsingFailure, self).__init__(parsing_exception)
    self.exception = parsing_exception


class UnrecognizedType(FileSkipped):
  """
  File doesn't contain descriptor data. This could either be due to its file
  type or because it doesn't conform to a recognizable descriptor type.

  :param tuple mime_type: the (type, encoding) tuple provided by mimetypes.guess_type()
  """

  def __init__(self, mime_type):
    super(UnrecognizedType, self).__init__('Unrecognized mime type: %s (%s)' % mime_type)
    self.mime_type = mime_type


class ReadFailed(FileSkipped):
  """
  An IOError occurred while trying to read the file.

  :param IOError exception: issue that arose when reading the file, **None** if
    this arose due to the file not being present
  """

  def __init__(self, read_exception):
    super(ReadFailed, self).__init__(read_exception)
    self.exception = read_exception


class FileMissing(ReadFailed):
  'File does not exist.'

  def __init__(self):
    super(FileMissing, self).__init__('File does not exist')


def load_processed_files(path):
  """
  Loads a dictionary of 'path => last modified timestamp' mappings, as
  persisted by :func:`~stem.descriptor.reader.save_processed_files`, from a
  file.

  :param str path: location to load the processed files dictionary from

  :returns: **dict** of 'path (**str**) => last modified unix timestamp
    (**int**)' mappings

  :raises:
    * **IOError** if unable to read the file
    * **TypeError** if unable to parse the file's contents
  """

  processed_files = {}

  with open(path) as input_file:
    for line in input_file.readlines():
      line = line.strip()

      if not line:
        continue  # skip blank lines

      if ' ' not in line:
        raise TypeError('Malformed line: %s' % line)

      path, timestamp = line.rsplit(' ', 1)

      if not os.path.isabs(path):
        raise TypeError("'%s' is not an absolute path" % path)
      elif not timestamp.isdigit():
        raise TypeError("'%s' is not an integer timestamp" % timestamp)

      processed_files[path] = int(timestamp)

  return processed_files


def save_processed_files(path, processed_files):
  """
  Persists a dictionary of 'path => last modified timestamp' mappings (as
  provided by the DescriptorReader's
  :func:`~stem.descriptor.reader.DescriptorReader.get_processed_files` method)
  so that they can be loaded later and applied to another
  :class:`~stem.descriptor.reader.DescriptorReader`.

  :param str path: location to save the processed files dictionary to
  :param dict processed_files: 'path => last modified' mappings

  :raises:
    * **IOError** if unable to write to the file
    * **TypeError** if processed_files is of the wrong type
  """

  # makes the parent directory if it doesn't already exist
  try:
    path_dir = os.path.dirname(path)

    if not os.path.exists(path_dir):
      os.makedirs(path_dir)
  except OSError as exc:
    raise IOError(exc)

  with open(path, 'w') as output_file:
    for path, timestamp in list(processed_files.items()):
      if not os.path.isabs(path):
        raise TypeError('Only absolute paths are acceptable: %s' % path)

      output_file.write('%s %i\n' % (path, timestamp))


class DescriptorReader(object):
  """
  Iterator for the descriptor data on the local file system. This can process
  text files, tarball archives (gzip or bzip2), or recurse directories.

  By default this limits the number of descriptors that we'll read ahead before
  waiting for our caller to fetch some of them. This is included to avoid
  unbounded memory usage.

  Our persistence_path argument is a convenient method to persist the listing
  of files we have processed between runs, however it doesn't allow for error
  handling. If you want that then use the
  :func:`~stem.descriptor.reader.load_processed_files` and
  :func:`~stem.descriptor.reader.save_processed_files` functions instead.

  :param str,list target: path or list of paths for files or directories to be read from
  :param bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :param bool follow_links: determines if we'll follow symlinks when traversing
    directories (requires python 2.6)
  :param int buffer_size: descriptors we'll buffer before waiting for some to
    be read, this is unbounded if zero
  :param str persistence_path: if set we will load and save processed file
    listings from this path, errors are ignored
  :param stem.descriptor.__init__.DocumentHandler document_handler: method in
    which to parse :class:`~stem.descriptor.networkstatus.NetworkStatusDocument`
  :param dict kwargs: additional arguments for the descriptor constructor
  """

  def __init__(self, target, validate = False, follow_links = False, buffer_size = 100, persistence_path = None, document_handler = stem.descriptor.DocumentHandler.ENTRIES, **kwargs):
    if isinstance(target, (bytes, str_type)):
      self._targets = [target]
    else:
      self._targets = target

    # expand any relative paths we got

    self._targets = list(map(os.path.abspath, self._targets))

    self._validate = validate
    self._follow_links = follow_links
    self._persistence_path = persistence_path
    self._document_handler = document_handler
    self._kwargs = kwargs
    self._read_listeners = []
    self._skip_listeners = []
    self._processed_files = {}

    self._reader_thread = None
    self._reader_thread_lock = threading.RLock()

    self._iter_lock = threading.RLock()
    self._iter_notice = threading.Event()

    self._is_stopped = threading.Event()
    self._is_stopped.set()

    # Descriptors that we have read but not yet provided to the caller. A
    # FINISHED entry is used by the reading thread to indicate the end.

    self._unreturned_descriptors = queue.Queue(buffer_size)

    if self._persistence_path:
      try:
        processed_files = load_processed_files(self._persistence_path)
        self.set_processed_files(processed_files)
      except:
        pass

  def get_processed_files(self):
    """
    For each file that we have read descriptor data from this provides a
    mapping of the form...

    ::

      absolute path (str) => last modified unix timestamp (int)

    This includes entries set through the
    :func:`~stem.descriptor.reader.DescriptorReader.set_processed_files`
    method. Each run resets this to only the files that were present during
    that run.

    :returns: **dict** with the absolute paths and unix timestamp for the last
      modified times of the files we have processed
    """

    # make sure that we only provide back absolute paths
    return dict((os.path.abspath(k), v) for (k, v) in list(self._processed_files.items()))

  def set_processed_files(self, processed_files):
    """
    Sets the listing of the files we have processed. Most often this is used
    with a newly created :class:`~stem.descriptor.reader.DescriptorReader` to
    pre-populate the listing of descriptor files that we have seen.

    :param dict processed_files: mapping of absolute paths (**str**) to unix
      timestamps for the last modified time (**int**)
    """

    self._processed_files = dict(processed_files)

  def register_read_listener(self, listener):
    """
    Registers a listener for when files are read. This is executed prior to
    processing files. Listeners are expected to be of the form...

    ::

      my_listener(path)

    :param functor listener: functor to be notified when files are read
    """

    self._read_listeners.append(listener)

  def register_skip_listener(self, listener):
    """
    Registers a listener for files that are skipped. This listener is expected
    to be a functor of the form...

    ::

      my_listener(path, exception)

    :param functor listener: functor to be notified of files that are skipped
      to read errors or because they couldn't be parsed as valid descriptor data
    """

    self._skip_listeners.append(listener)

  def get_buffered_descriptor_count(self):
    """
    Provides the number of descriptors that are waiting to be iterated over.
    This is limited to the buffer_size that we were constructed with.

    :returns: **int** for the estimated number of currently enqueued
      descriptors, this is not entirely reliable
    """

    return self._unreturned_descriptors.qsize()

  def start(self):
    """
    Starts reading our descriptor files.

    :raises: **ValueError** if we're already reading the descriptor files
    """

    with self._reader_thread_lock:
      if self._reader_thread:
        raise ValueError('Already running, you need to call stop() first')
      else:
        self._is_stopped.clear()
        self._reader_thread = threading.Thread(target = self._read_descriptor_files, name='Descriptor Reader')
        self._reader_thread.setDaemon(True)
        self._reader_thread.start()

  def stop(self):
    """
    Stops further reading of descriptor files.
    """

    with self._reader_thread_lock:
      self._is_stopped.set()
      self._iter_notice.set()

      # clears our queue to unblock enqueue calls

      try:
        while True:
          self._unreturned_descriptors.get_nowait()
      except queue.Empty:
        pass

      self._reader_thread.join()
      self._reader_thread = None

      if self._persistence_path:
        try:
          processed_files = self.get_processed_files()
          save_processed_files(self._persistence_path, processed_files)
        except:
          pass

  def _read_descriptor_files(self):
    new_processed_files = {}
    remaining_files = list(self._targets)

    while remaining_files and not self._is_stopped.is_set():
      target = remaining_files.pop(0)

      if not os.path.exists(target):
        self._notify_skip_listeners(target, FileMissing())
        continue

      if os.path.isdir(target):
        walker = os.walk(target, followlinks = self._follow_links)
        self._handle_walker(walker, new_processed_files)
      else:
        self._handle_file(target, new_processed_files)

    self._processed_files = new_processed_files

    if not self._is_stopped.is_set():
      self._unreturned_descriptors.put(FINISHED)

    self._iter_notice.set()

  def __iter__(self):
    with self._iter_lock:
      while not self._is_stopped.is_set():
        try:
          descriptor = self._unreturned_descriptors.get_nowait()

          if descriptor == FINISHED:
            break
          else:
            yield descriptor
        except queue.Empty:
          self._iter_notice.wait()
          self._iter_notice.clear()

  def _handle_walker(self, walker, new_processed_files):
    for root, _, files in walker:
      for filename in files:
        self._handle_file(os.path.join(root, filename), new_processed_files)

        # this can take a while if, say, we're including the root directory
        if self._is_stopped.is_set():
          return

  def _handle_file(self, target, new_processed_files):
    # This is a file. Register its last modified timestamp and check if
    # it's a file that we should skip.

    try:
      last_modified = int(os.stat(target).st_mtime)
      last_used = self._processed_files.get(target)
      new_processed_files[target] = last_modified
    except OSError as exc:
      self._notify_skip_listeners(target, ReadFailed(exc))
      return

    if last_used and last_used >= last_modified:
      self._notify_skip_listeners(target, AlreadyRead(last_modified, last_used))
      return

    # Block devices and such are never descriptors, and can cause us to block
    # for quite a while so skipping anything that isn't a regular file.

    if not os.path.isfile(target):
      return

    # The mimetypes module only checks the file extension. To actually
    # check the content (like the 'file' command) we'd need something like
    # pymagic (https://github.com/cloudburst/pymagic).

    target_type = mimetypes.guess_type(target)

    if target_type[0] in (None, 'text/plain'):
      # either '.txt' or an unknown type
      self._handle_descriptor_file(target, target_type)
    elif stem.util.system.is_tarfile(target):
      # handles gzip, bz2, and decompressed tarballs among others
      self._handle_archive(target)
    else:
      self._notify_skip_listeners(target, UnrecognizedType(target_type))

  def _handle_descriptor_file(self, target, mime_type):
    try:
      self._notify_read_listeners(target)

      with open(target, 'rb') as target_file:
        for desc in stem.descriptor.parse_file(target_file, validate = self._validate, document_handler = self._document_handler, **self._kwargs):
          if self._is_stopped.is_set():
            return

          self._unreturned_descriptors.put(desc)
          self._iter_notice.set()
    except TypeError as exc:
      self._notify_skip_listeners(target, UnrecognizedType(mime_type))
    except ValueError as exc:
      self._notify_skip_listeners(target, ParsingFailure(exc))
    except IOError as exc:
      self._notify_skip_listeners(target, ReadFailed(exc))

  def _handle_archive(self, target):
    # TODO: When dropping python 2.6 support go back to using 'with' for
    # tarfiles...
    #
    #   http://bugs.python.org/issue7232

    tar_file = None

    try:
      self._notify_read_listeners(target)
      tar_file = tarfile.open(target)

      for tar_entry in tar_file:
        if tar_entry.isfile():
          entry = tar_file.extractfile(tar_entry)

          try:
            for desc in stem.descriptor.parse_file(entry, validate = self._validate, document_handler = self._document_handler, **self._kwargs):
              if self._is_stopped.is_set():
                return

              desc._set_path(os.path.abspath(target))
              desc._set_archive_path(tar_entry.name)
              self._unreturned_descriptors.put(desc)
              self._iter_notice.set()
          except TypeError as exc:
            self._notify_skip_listeners(target, ParsingFailure(exc))
          except ValueError as exc:
            self._notify_skip_listeners(target, ParsingFailure(exc))
          finally:
            entry.close()
    except IOError as exc:
      self._notify_skip_listeners(target, ReadFailed(exc))
    finally:
      if tar_file:
        tar_file.close()

  def _notify_read_listeners(self, path):
    for listener in self._read_listeners:
      listener(path)

  def _notify_skip_listeners(self, path, exception):
    for listener in self._skip_listeners:
      listener(path, exception)

  def __enter__(self):
    self.start()
    return self

  def __exit__(self, exit_type, value, traceback):
    self.stop()
