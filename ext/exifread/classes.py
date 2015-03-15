import struct
import re

from .exif_log import get_logger
from .utils import s2n_motorola, s2n_intel, Ratio
from .tags import *

logger = get_logger()


class IfdTag:
    """
    Eases dealing with tags.
    """

    def __init__(self, printable, tag, field_type, values, field_offset,
                 field_length):
        # printable version of data
        self.printable = printable
        # tag ID number
        self.tag = tag
        # field type as index into FIELD_TYPES
        self.field_type = field_type
        # offset of start of field in bytes from beginning of IFD
        self.field_offset = field_offset
        # length of data field in bytes
        self.field_length = field_length
        # either a string or array of data items
        self.values = values

    def __str__(self):
        return self.printable

    def __repr__(self):
        try:
            s = '(0x%04X) %s=%s @ %d' % (self.tag,
                                         FIELD_TYPES[self.field_type][2],
                                         self.printable,
                                         self.field_offset)
        except:
            s = '(%s) %s=%s @ %s' % (str(self.tag),
                                     FIELD_TYPES[self.field_type][2],
                                     self.printable,
                                     str(self.field_offset))
        return s


class ExifHeader:
    """
    Handle an EXIF header.
    """

    def __init__(self, file, endian, offset, fake_exif, strict,
                 debug=False, detailed=True):
        self.file = file
        self.endian = endian
        self.offset = offset
        self.fake_exif = fake_exif
        self.strict = strict
        self.debug = debug
        self.detailed = detailed
        self.tags = {}

    def s2n(self, offset, length, signed=0):
        """
        Convert slice to integer, based on sign and endian flags.

        Usually this offset is assumed to be relative to the beginning of the
        start of the EXIF information.
        For some cameras that use relative tags, this offset may be relative
        to some other starting point.
        """
        self.file.seek(self.offset + offset)
        sliced = self.file.read(length)
        if self.endian == 'I':
            val = s2n_intel(sliced)
        else:
            val = s2n_motorola(sliced)
            # Sign extension?
        if signed:
            msb = 1 << (8 * length - 1)
            if val & msb:
                val -= (msb << 1)
        return val

    def n2s(self, offset, length):
        """Convert offset to string."""
        s = ''
        for dummy in range(length):
            if self.endian == 'I':
                s += chr(offset & 0xFF)
            else:
                s = chr(offset & 0xFF) + s
            offset = offset >> 8
        return s

    def _first_ifd(self):
        """Return first IFD."""
        return self.s2n(4, 4)

    def _next_ifd(self, ifd):
        """Return the pointer to next IFD."""
        entries = self.s2n(ifd, 2)
        next_ifd = self.s2n(ifd + 2 + 12 * entries, 4)
        if next_ifd == ifd:
            return 0
        else:
            return next_ifd

    def list_ifd(self):
        """Return the list of IFDs in the header."""
        i = self._first_ifd()
        ifds = []
        while i:
            ifds.append(i)
            i = self._next_ifd(i)
        return ifds

    def dump_ifd(self, ifd, ifd_name, tag_dict=EXIF_TAGS, relative=0, stop_tag=DEFAULT_STOP_TAG):
        """
        Return a list of entries in the given IFD.
        """
        # make sure we can process the entries
        try:
            entries = self.s2n(ifd, 2)
        except TypeError:
            logger.warning("Possibly corrupted IFD: %s" % ifd)
            return

        for i in range(entries):
            # entry is index of start of this IFD in the file
            entry = ifd + 2 + 12 * i
            tag = self.s2n(entry, 2)

            # get tag name early to avoid errors, help debug
            tag_entry = tag_dict.get(tag)
            if tag_entry:
                tag_name = tag_entry[0]
            else:
                tag_name = 'Tag 0x%04X' % tag

            # ignore certain tags for faster processing
            if not (not self.detailed and tag in IGNORE_TAGS):
                field_type = self.s2n(entry + 2, 2)

                # unknown field type
                if not 0 < field_type < len(FIELD_TYPES):
                    if not self.strict:
                        continue
                    else:
                        raise ValueError('Unknown type %d in tag 0x%04X' % (field_type, tag))

                type_length = FIELD_TYPES[field_type][0]
                count = self.s2n(entry + 4, 4)
                # Adjust for tag id/type/count (2+2+4 bytes)
                # Now we point at either the data or the 2nd level offset
                offset = entry + 8

                # If the value fits in 4 bytes, it is inlined, else we
                # need to jump ahead again.
                if count * type_length > 4:
                    # offset is not the value; it's a pointer to the value
                    # if relative we set things up so s2n will seek to the right
                    # place when it adds self.offset.  Note that this 'relative'
                    # is for the Nikon type 3 makernote.  Other cameras may use
                    # other relative offsets, which would have to be computed here
                    # slightly differently.
                    if relative:
                        tmp_offset = self.s2n(offset, 4)
                        offset = tmp_offset + ifd - 8
                        if self.fake_exif:
                            offset += 18
                    else:
                        offset = self.s2n(offset, 4)

                field_offset = offset
                values = None
                if field_type == 2:
                    # special case: null-terminated ASCII string
                    # XXX investigate
                    # sometimes gets too big to fit in int value
                    if count != 0:  # and count < (2**31):  # 2E31 is hardware dependant. --gd
                        try:
                            self.file.seek(self.offset + offset)
                            values = self.file.read(count)
                            #print values
                            # Drop any garbage after a null.
                            values = values.split(b'\x00', 1)[0]
                            if isinstance(values, bytes):
                                try:
                                    values = values.decode("utf-8")
                                except UnicodeDecodeError:
                                    logger.warning("Possibly corrupted field %s in %s IFD", tag_name, ifd_name)
                        except OverflowError:
                            values = ''
                else:
                    values = []
                    signed = (field_type in [6, 8, 9, 10])

                    # XXX investigate
                    # some entries get too big to handle could be malformed
                    # file or problem with self.s2n
                    if count < 1000:
                        for dummy in range(count):
                            if field_type in (5, 10):
                                # a ratio
                                value = Ratio(self.s2n(offset, 4, signed),
                                              self.s2n(offset + 4, 4, signed))
                            else:
                                value = self.s2n(offset, type_length, signed)
                            values.append(value)
                            offset = offset + type_length
                    # The test above causes problems with tags that are
                    # supposed to have long values! Fix up one important case.
                    elif tag_name in ('MakerNote', makernote.canon.CAMERA_INFO_TAG_NAME):
                        for dummy in range(count):
                            value = self.s2n(offset, type_length, signed)
                            values.append(value)
                            offset = offset + type_length

                # now 'values' is either a string or an array
                if count == 1 and field_type != 2:
                    printable = str(values[0])
                elif count > 50 and len(values) > 20:
                    printable = str(values[0:20])[0:-1] + ", ... ]"
                else:
                    try:
                        printable = str(values)
                    # fix for python2's handling of unicode values
                    except UnicodeEncodeError:
                        printable = unicode(values)

                # compute printable version of values
                if tag_entry:
                    # optional 2nd tag element is present
                    if len(tag_entry) != 1:
                        if callable(tag_entry[1]):
                            # call mapping function
                            printable = tag_entry[1](values)
                        elif type(tag_entry[1]) is tuple:
                            ifd_info = tag_entry[1]
                            try:
                                logger.debug('%s SubIFD at offset %d:', ifd_info[0], values[0])
                                self.dump_ifd(values[0], ifd_info[0], tag_dict=ifd_info[1], stop_tag=stop_tag)
                            except IndexError:
                                logger.warn('No values found for %s SubIFD', ifd_info[0])
                        else:
                            printable = ''
                            for i in values:
                                # use lookup table for this tag
                                printable += tag_entry[1].get(i, repr(i))

                self.tags[ifd_name + ' ' + tag_name] = IfdTag(printable, tag,
                                                              field_type,
                                                              values, field_offset,
                                                              count * type_length)
                try:
                    tag_value = repr(self.tags[ifd_name + ' ' + tag_name])
                # fix for python2's handling of unicode values
                except UnicodeEncodeError:
                    tag_value = unicode(self.tags[ifd_name + ' ' + tag_name])
                logger.debug(' %s: %s', tag_name, tag_value)

            if tag_name == stop_tag:
                break

    def extract_tiff_thumbnail(self, thumb_ifd):
        """
        Extract uncompressed TIFF thumbnail.

        Take advantage of the pre-existing layout in the thumbnail IFD as
        much as possible
        """
        thumb = self.tags.get('Thumbnail Compression')
        if not thumb or thumb.printable != 'Uncompressed TIFF':
            return

        entries = self.s2n(thumb_ifd, 2)
        # this is header plus offset to IFD ...
        if self.endian == 'M':
            tiff = 'MM\x00*\x00\x00\x00\x08'
        else:
            tiff = 'II*\x00\x08\x00\x00\x00'
            # ... plus thumbnail IFD data plus a null "next IFD" pointer
        self.file.seek(self.offset + thumb_ifd)
        tiff += self.file.read(entries * 12 + 2) + '\x00\x00\x00\x00'

        # fix up large value offset pointers into data area
        for i in range(entries):
            entry = thumb_ifd + 2 + 12 * i
            tag = self.s2n(entry, 2)
            field_type = self.s2n(entry + 2, 2)
            type_length = FIELD_TYPES[field_type][0]
            count = self.s2n(entry + 4, 4)
            old_offset = self.s2n(entry + 8, 4)
            # start of the 4-byte pointer area in entry
            ptr = i * 12 + 18
            # remember strip offsets location
            if tag == 0x0111:
                strip_off = ptr
                strip_len = count * type_length
                # is it in the data area?
            if count * type_length > 4:
                # update offset pointer (nasty "strings are immutable" crap)
                # should be able to say "tiff[ptr:ptr+4]=newoff"
                newoff = len(tiff)
                tiff = tiff[:ptr] + self.n2s(newoff, 4) + tiff[ptr + 4:]
                # remember strip offsets location
                if tag == 0x0111:
                    strip_off = newoff
                    strip_len = 4
                # get original data and store it
                self.file.seek(self.offset + old_offset)
                tiff += self.file.read(count * type_length)

        # add pixel strips and update strip offset info
        old_offsets = self.tags['Thumbnail StripOffsets'].values
        old_counts = self.tags['Thumbnail StripByteCounts'].values
        for i in range(len(old_offsets)):
            # update offset pointer (more nasty "strings are immutable" crap)
            offset = self.n2s(len(tiff), strip_len)
            tiff = tiff[:strip_off] + offset + tiff[strip_off + strip_len:]
            strip_off += strip_len
            # add pixel strip to end
            self.file.seek(self.offset + old_offsets[i])
            tiff += self.file.read(old_counts[i])

        self.tags['TIFFThumbnail'] = tiff

    def extract_jpeg_thumbnail(self):
        """
        Extract JPEG thumbnail.

        (Thankfully the JPEG data is stored as a unit.)
        """
        thumb_offset = self.tags.get('Thumbnail JPEGInterchangeFormat')
        if thumb_offset:
            self.file.seek(self.offset + thumb_offset.values[0])
            size = self.tags['Thumbnail JPEGInterchangeFormatLength'].values[0]
            self.tags['JPEGThumbnail'] = self.file.read(size)

        # Sometimes in a TIFF file, a JPEG thumbnail is hidden in the MakerNote
        # since it's not allowed in a uncompressed TIFF IFD
        if 'JPEGThumbnail' not in self.tags:
            thumb_offset = self.tags.get('MakerNote JPEGThumbnail')
            if thumb_offset:
                self.file.seek(self.offset + thumb_offset.values[0])
                self.tags['JPEGThumbnail'] = self.file.read(thumb_offset.field_length)

    def decode_maker_note(self):
        """
        Decode all the camera-specific MakerNote formats

        Note is the data that comprises this MakerNote.
        The MakerNote will likely have pointers in it that point to other
        parts of the file. We'll use self.offset as the starting point for
        most of those pointers, since they are relative to the beginning
        of the file.
        If the MakerNote is in a newer format, it may use relative addressing
        within the MakerNote. In that case we'll use relative addresses for
        the pointers.
        As an aside: it's not just to be annoying that the manufacturers use
        relative offsets.  It's so that if the makernote has to be moved by the
        picture software all of the offsets don't have to be adjusted.  Overall,
        this is probably the right strategy for makernotes, though the spec is
        ambiguous.
        The spec does not appear to imagine that makernotes would
        follow EXIF format internally.  Once they did, it's ambiguous whether
        the offsets should be from the header at the start of all the EXIF info,
        or from the header at the start of the makernote.
        """
        note = self.tags['EXIF MakerNote']

        # Some apps use MakerNote tags but do not use a format for which we
        # have a description, so just do a raw dump for these.
        make = self.tags['Image Make'].printable

        # Nikon
        # The maker note usually starts with the word Nikon, followed by the
        # type of the makernote (1 or 2, as a short).  If the word Nikon is
        # not at the start of the makernote, it's probably type 2, since some
        # cameras work that way.
        if 'NIKON' in make:
            if note.values[0:7] == [78, 105, 107, 111, 110, 0, 1]:
                logger.debug("Looks like a type 1 Nikon MakerNote.")
                self.dump_ifd(note.field_offset + 8, 'MakerNote',
                              tag_dict=makernote.NIKON_OLD)
            elif note.values[0:7] == [78, 105, 107, 111, 110, 0, 2]:
                if self.debug:
                    logger.debug("Looks like a labeled type 2 Nikon MakerNote")
                if note.values[12:14] != [0, 42] and note.values[12:14] != [42, 0]:
                    raise ValueError("Missing marker tag '42' in MakerNote.")
                    # skip the Makernote label and the TIFF header
                self.dump_ifd(note.field_offset + 10 + 8, 'MakerNote',
                              tag_dict=makernote.NIKON_NEW, relative=1)
            else:
                # E99x or D1
                logger.debug("Looks like an unlabeled type 2 Nikon MakerNote")
                self.dump_ifd(note.field_offset, 'MakerNote',
                              tag_dict=makernote.NIKON_NEW)
            return

        # Olympus
        if make.startswith('OLYMPUS'):
            self.dump_ifd(note.field_offset + 8, 'MakerNote',
                          tag_dict=makernote.OLYMPUS)
            # TODO
            #for i in (('MakerNote Tag 0x2020', makernote.OLYMPUS_TAG_0x2020),):
            #    self.decode_olympus_tag(self.tags[i[0]].values, i[1])
            #return

        # Casio
        if 'CASIO' in make or 'Casio' in make:
            self.dump_ifd(note.field_offset, 'MakerNote',
                          tag_dict=makernote.CASIO)
            return

        # Fujifilm
        if make == 'FUJIFILM':
            # bug: everything else is "Motorola" endian, but the MakerNote
            # is "Intel" endian
            endian = self.endian
            self.endian = 'I'
            # bug: IFD offsets are from beginning of MakerNote, not
            # beginning of file header
            offset = self.offset
            self.offset += note.field_offset
            # process note with bogus values (note is actually at offset 12)
            self.dump_ifd(12, 'MakerNote', tag_dict=makernote.FUJIFILM)
            # reset to correct values
            self.endian = endian
            self.offset = offset
            return

        # Canon
        if make == 'Canon':
            self.dump_ifd(note.field_offset, 'MakerNote',
                          tag_dict=makernote.canon.TAGS)
            for i in (('MakerNote Tag 0x0001', makernote.canon.CAMERA_SETTINGS),
                      ('MakerNote Tag 0x0002', makernote.canon.FOCAL_LENGTH),
                      ('MakerNote Tag 0x0004', makernote.canon.SHOT_INFO),
                      ('MakerNote Tag 0x0026', makernote.canon.AF_INFO_2),
                      ('MakerNote Tag 0x0093', makernote.canon.FILE_INFO)):
                if i[0] in self.tags:
                    logger.debug('Canon ' + i[0])
                    self._canon_decode_tag(self.tags[i[0]].values, i[1])
                    del self.tags[i[0]]
            if makernote.canon.CAMERA_INFO_TAG_NAME in self.tags:
                tag = self.tags[makernote.canon.CAMERA_INFO_TAG_NAME]
                logger.debug('Canon CameraInfo')
                self._canon_decode_camera_info(tag)
                del self.tags[makernote.canon.CAMERA_INFO_TAG_NAME]
            return

    def _olympus_decode_tag(self, value, mn_tags):
        """ TODO Decode Olympus MakerNote tag based on offset within tag."""
        pass

    def _canon_decode_tag(self, value, mn_tags):
        """
        Decode Canon MakerNote tag based on offset within tag.

        See http://www.burren.cx/david/canon.html by David Burren
        """
        for i in range(1, len(value)):
            tag = mn_tags.get(i, ('Unknown', ))
            name = tag[0]
            if len(tag) > 1:
                val = tag[1].get(value[i], 'Unknown')
            else:
                val = value[i]
            try:
                logger.debug(" %s %s %s", i, name, hex(value[i]))
            except TypeError:
                logger.debug(" %s %s %s", i, name, value[i])

            # it's not a real IFD Tag but we fake one to make everybody
            # happy. this will have a "proprietary" type
            self.tags['MakerNote ' + name] = IfdTag(str(val), None, 0, None,
                                                    None, None)

    def _canon_decode_camera_info(self, camera_info_tag):
        """
        Decode the variable length encoded camera info section.
        """
        model = self.tags.get('Image Model', None)
        if not model:
            return
        model = str(model.values)

        camera_info_tags = None
        for (model_name_re, tag_desc) in makernote.canon.CAMERA_INFO_MODEL_MAP.items():
            if re.search(model_name_re, model):
                camera_info_tags = tag_desc
                break
        else:
            return

        # We are assuming here that these are all unsigned bytes (Byte or
        # Unknown)
        if camera_info_tag.field_type not in (1, 7):
            return
        camera_info = struct.pack('<%dB' % len(camera_info_tag.values),
                                  *camera_info_tag.values)

        # Look for each data value and decode it appropriately.
        for offset, tag in camera_info_tags.items():
            tag_format = tag[1]
            tag_size = struct.calcsize(tag_format)
            if len(camera_info) < offset + tag_size:
                continue
            packed_tag_value = camera_info[offset:offset + tag_size]
            tag_value = struct.unpack(tag_format, packed_tag_value)[0]

            tag_name = tag[0]
            if len(tag) > 2:
                if callable(tag[2]):
                    tag_value = tag[2](tag_value)
                else:
                    tag_value = tag[2].get(tag_value, tag_value)
            logger.debug(" %s %s", tag_name, tag_value)

            self.tags['MakerNote ' + tag_name] = IfdTag(str(tag_value), None,
                                                        0, None, None, None)

    def parse_xmp(self, xmp_string):
        import xml.dom.minidom

        logger.debug('XMP cleaning data')

        xml = xml.dom.minidom.parseString(xmp_string)
        pretty = xml.toprettyxml()
        cleaned = []
        for line in pretty.splitlines():
            if line.strip():
                cleaned.append(line)
        self.tags['Image ApplicationNotes'] = IfdTag('\n'.join(cleaned), None,
                                                     1, None, None, None)