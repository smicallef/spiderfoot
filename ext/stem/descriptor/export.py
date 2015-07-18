# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Toolkit for exporting descriptors to other formats.

**Module Overview:**

::

  export_csv - Exports descriptors to a CSV
  export_csv_file - Writes exported CSV output to a file
"""

import csv

try:
  from cStringIO import StringIO
except ImportError:
  from io import StringIO

import stem.descriptor
import stem.prereq


class _ExportDialect(csv.excel):
  lineterminator = '\n'


def export_csv(descriptors, included_fields = (), excluded_fields = (), header = True):
  """
  Provides a newline separated CSV for one or more descriptors. If simply
  provided with descriptors then the CSV contains all of its attributes,
  labeled with a header row. Either 'included_fields' or 'excluded_fields' can
  be used for more granular control over its attributes and the order.

  :param Descriptor,list descriptors: either a
    :class:`~stem.descriptor.Descriptor` or list of descriptors to be exported
  :param list included_fields: attributes to include in the csv
  :param list excluded_fields: attributes to exclude from the csv
  :param bool header: if **True** then the first line will be a comma separated
    list of the attribute names (**only supported in python 2.7 and higher**)

  :returns: **str** of the CSV for the descriptors, one per line
  :raises: **ValueError** if descriptors contain more than one descriptor type
  """

  output_buffer = StringIO()
  export_csv_file(output_buffer, descriptors, included_fields, excluded_fields, header)
  return output_buffer.getvalue()


def export_csv_file(output_file, descriptors, included_fields = (), excluded_fields = (), header = True):
  """
  Similar to :func:`stem.descriptor.export.export_csv`, except that the CSV is
  written directly to a file.

  :param file output_file: file to be written to
  :param Descriptor,list descriptors: either a
    :class:`~stem.descriptor.Descriptor` or list of descriptors to be exported
  :param list included_fields: attributes to include in the csv
  :param list excluded_fields: attributes to exclude from the csv
  :param bool header: if **True** then the first line will be a comma separated
    list of the attribute names (**only supported in python 2.7 and higher**)

  :returns: **str** of the CSV for the descriptors, one per line
  :raises: **ValueError** if descriptors contain more than one descriptor type
  """

  if isinstance(descriptors, stem.descriptor.Descriptor):
    descriptors = (descriptors,)

  if not descriptors:
    return

  descriptor_type = type(descriptors[0])
  descriptor_type_label = descriptor_type.__name__
  included_fields = list(included_fields)

  # If the user didn't specify the fields to include then export everything,
  # ordered alphabetically. If they did specify fields then make sure that
  # they exist.

  desc_attr = sorted(vars(descriptors[0]).keys())

  if included_fields:
    for field in included_fields:
      if field not in desc_attr:
        raise ValueError("%s does not have a '%s' attribute, valid fields are: %s" % (descriptor_type_label, field, ', '.join(desc_attr)))
  else:
    included_fields = [attr for attr in desc_attr if not attr.startswith('_')]

  for field in excluded_fields:
    try:
      included_fields.remove(field)
    except ValueError:
      pass

  writer = csv.DictWriter(output_file, included_fields, dialect = _ExportDialect(), extrasaction='ignore')

  if header and stem.prereq.is_python_27():
    writer.writeheader()

  for desc in descriptors:
    if not isinstance(desc, stem.descriptor.Descriptor):
      raise ValueError('Unable to export a descriptor CSV since %s is not a descriptor.' % type(desc).__name__)
    elif descriptor_type != type(desc):
      raise ValueError('To export a descriptor CSV all of the descriptors must be of the same type. First descriptor was a %s but we later got a %s.' % (descriptor_type_label, type(desc)))

    writer.writerow(vars(desc))
