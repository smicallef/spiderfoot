"""
Read Exif metadata from tiff and jpeg files.
"""

from .exif_log import get_logger
from .classes import *
from .tags import *
from .utils import ord_

__version__ = '2.0.1'

logger = get_logger()


def increment_base(data, base):
    return ord_(data[base + 2]) * 256 + ord_(data[base + 3]) + 2


def process_file(f, stop_tag=DEFAULT_STOP_TAG, details=True, strict=False, debug=False):
    """
    Process an image file (expects an open file object).

    This is the function that has to deal with all the arbitrary nasty bits
    of the EXIF standard.
    """

    # by default do not fake an EXIF beginning
    fake_exif = 0

    # determine whether it's a JPEG or TIFF
    data = f.read(12)
    if data[0:4] in [b'II*\x00', b'MM\x00*']:
        # it's a TIFF file
        logger.debug("TIFF format recognized in data[0:4]")
        f.seek(0)
        endian = f.read(1)
        f.read(1)
        offset = 0
    elif data[0:2] == b'\xFF\xD8':
        # it's a JPEG file
        logger.debug("JPEG format recognized data[0:2]=0x%X%X", ord_(data[0]), ord_(data[1]))
        base = 2
        logger.debug("data[2]=0x%X data[3]=0x%X data[6:10]=%s",
                     ord_(data[2]), ord_(data[3]), data[6:10])
        while ord_(data[2]) == 0xFF and data[6:10] in (b'JFIF', b'JFXX', b'OLYM', b'Phot'):
            length = ord_(data[4]) * 256 + ord_(data[5])
            logger.debug(" Length offset is %s", length)
            f.read(length - 8)
            # fake an EXIF beginning of file
            # I don't think this is used. --gd
            data = b'\xFF\x00' + f.read(10)
            fake_exif = 1
            if base > 2:
                logger.debug(" Added to base")
                base = base + length + 4 - 2
            else:
                logger.debug(" Added to zero")
                base = length + 4
            logger.debug(" Set segment base to 0x%X", base)

        # Big ugly patch to deal with APP2 (or other) data coming before APP1
        f.seek(0)
        # in theory, this could be insufficient since 64K is the maximum size--gd
        data = f.read(base + 4000)
        # base = 2
        while 1:
            logger.debug(" Segment base 0x%X", base)
            if data[base:base + 2] == b'\xFF\xE1':
                # APP1
                logger.debug("  APP1 at base 0x%X", base)
                logger.debug("  Length: 0x%X 0x%X", ord_(data[base + 2]),
                             ord_(data[base + 3]))
                logger.debug("  Code: %s", data[base + 4:base + 8])
                if data[base + 4:base + 8] == b"Exif":
                    logger.debug("  Decrement base by 2 to get to pre-segment header (for compatibility with later code)")
                    base -= 2
                    break
                increment = increment_base(data, base)
                logger.debug(" Increment base by %s", increment)
                base += increment
            elif data[base:base + 2] == b'\xFF\xE0':
                # APP0
                logger.debug("  APP0 at base 0x%X", base)
                logger.debug("  Length: 0x%X 0x%X", ord_(data[base + 2]),
                             ord_(data[base + 3]))
                logger.debug("  Code: %s", data[base + 4:base + 8])
                increment = increment_base(data, base)
                logger.debug(" Increment base by %s", increment)
                base += increment
            elif data[base:base + 2] == b'\xFF\xE2':
                # APP2
                logger.debug("  APP2 at base 0x%X", base)
                logger.debug("  Length: 0x%X 0x%X", ord_(data[base + 2]),
                             ord_(data[base + 3]))
                logger.debug(" Code: %s", data[base + 4:base + 8])
                increment = increment_base(data, base)
                logger.debug(" Increment base by %s", increment)
                base += increment
            elif data[base:base + 2] == b'\xFF\xEE':
                # APP14
                logger.debug("  APP14 Adobe segment at base 0x%X", base)
                logger.debug("  Length: 0x%X 0x%X", ord_(data[base + 2]),
                             ord_(data[base + 3]))
                logger.debug("  Code: %s", data[base + 4:base + 8])
                increment = increment_base(data, base)
                logger.debug(" Increment base by %s", increment)
                base += increment
                logger.debug("  There is useful EXIF-like data here, but we have no parser for it.")
            elif data[base:base + 2] == b'\xFF\xDB':
                logger.debug("  JPEG image data at base 0x%X No more segments are expected.",
                             base)
                break
            elif data[base:base + 2] == b'\xFF\xD8':
                # APP12
                logger.debug("  FFD8 segment at base 0x%X", base)
                logger.debug("  Got 0x%X 0x%X and %s instead",
                             ord_(data[base]),
                             ord_(data[base + 1]),
                             data[4 + base:10 + base])
                logger.debug("  Length: 0x%X 0x%X", ord_(data[base + 2]),
                             ord_(data[base + 3]))
                logger.debug("  Code: %s", data[base + 4:base + 8])
                increment = increment_base(data, base)
                logger.debug("  Increment base by %s", increment)
                base += increment
            elif data[base:base + 2] == b'\xFF\xEC':
                # APP12
                logger.debug("  APP12 XMP (Ducky) or Pictureinfo segment at base 0x%X",
                             base)
                logger.debug("  Got 0x%X and 0x%X instead", ord_(data[base]),
                             ord_(data[base + 1]))
                logger.debug("  Length: 0x%X 0x%X",
                             ord_(data[base + 2]),
                             ord_(data[base + 3]))
                logger.debug("Code: %s", data[base + 4:base + 8])
                increment = increment_base(data, base)
                logger.debug("  Increment base by %s", increment)
                base += increment
                logger.debug(
                    "  There is useful EXIF-like data here (quality, comment, copyright), but we have no parser for it.")
            else:
                try:
                    increment = increment_base(data, base)
                    logger.debug("  Got 0x%X and 0x%X instead",
                                 ord_(data[base]),
                                 ord_(data[base + 1]))
                except IndexError:
                    logger.debug("  Unexpected/unhandled segment type or file content.")
                    return {}
                else:
                    logger.debug("  Increment base by %s", increment)
                    base += increment
        f.seek(base + 12)
        if ord_(data[2 + base]) == 0xFF and data[6 + base:10 + base] == b'Exif':
            # detected EXIF header
            offset = f.tell()
            endian = f.read(1)
            #HACK TEST:  endian = 'M'
        elif ord_(data[2 + base]) == 0xFF and data[6 + base:10 + base + 1] == b'Ducky':
            # detected Ducky header.
            logger.debug("EXIF-like header (normally 0xFF and code): 0x%X and %s",
                         ord_(data[2 + base]), data[6 + base:10 + base + 1])
            offset = f.tell()
            endian = f.read(1)
        elif ord_(data[2 + base]) == 0xFF and data[6 + base:10 + base + 1] == b'Adobe':
            # detected APP14 (Adobe)
            logger.debug("EXIF-like header (normally 0xFF and code): 0x%X and %s",
                         ord_(data[2 + base]), data[6 + base:10 + base + 1])
            offset = f.tell()
            endian = f.read(1)
        else:
            # no EXIF information
            logger.debug("No EXIF header expected data[2+base]==0xFF and data[6+base:10+base]===Exif (or Duck)")
            logger.debug("Did get 0x%X and %s",
                         ord_(data[2 + base]), data[6 + base:10 + base + 1])
            return {}
    else:
        # file format not recognized
        logger.debug("File format not recognized.")
        return {}

    endian = chr(ord_(endian[0]))
    # deal with the EXIF info we found
    logger.debug("Endian format is %s (%s)", endian, {
        'I': 'Intel',
        'M': 'Motorola',
        '\x01': 'Adobe Ducky',
        'd': 'XMP/Adobe unknown'
    }[endian])

    hdr = ExifHeader(f, endian, offset, fake_exif, strict, debug, details)
    ifd_list = hdr.list_ifd()
    thumb_ifd = False
    ctr = 0
    for ifd in ifd_list:
        if ctr == 0:
            ifd_name = 'Image'
        elif ctr == 1:
            ifd_name = 'Thumbnail'
            thumb_ifd = ifd
        else:
            ifd_name = 'IFD %d' % ctr
        logger.debug('IFD %d (%s) at offset %s:', ctr, ifd_name, ifd)
        hdr.dump_ifd(ifd, ifd_name, stop_tag=stop_tag)
        ctr += 1
    # EXIF IFD
    exif_off = hdr.tags.get('Image ExifOffset')
    if exif_off:
        logger.debug('Exif SubIFD at offset %s:', exif_off.values[0])
        hdr.dump_ifd(exif_off.values[0], 'EXIF', stop_tag=stop_tag)

    # deal with MakerNote contained in EXIF IFD
    # (Some apps use MakerNote tags but do not use a format for which we
    # have a description, do not process these).
    if details and 'EXIF MakerNote' in hdr.tags and 'Image Make' in hdr.tags:
        hdr.decode_maker_note()

    # extract thumbnails
    if details and thumb_ifd:
        hdr.extract_tiff_thumbnail(thumb_ifd)
        hdr.extract_jpeg_thumbnail()

    # parse XMP tags (experimental)
    if debug and details:
        xmp_string = b''
        # Easy we already have them
        if 'Image ApplicationNotes' in hdr.tags:
            logger.debug('XMP present in Exif')
            xmp_string = make_string(hdr.tags['Image ApplicationNotes'].values)
        # We need to look in the entire file for the XML
        else:
            logger.debug('XMP not in Exif, searching file for XMP info ...')
            xml_started = False
            xml_finished = False
            for line in f:
                open_tag = line.find(b'<x:xmpmeta')
                close_tag = line.find(b'</x:xmpmeta>')

                if open_tag != -1:
                    xml_started = True
                    line = line[open_tag:]
                    logger.debug('XMP found opening tag at line position %s' % open_tag)

                if close_tag != -1:
                    logger.debug('XMP found closing tag at line position %s' % close_tag)
                    line_offset = 0
                    if open_tag != -1:
                        line_offset = open_tag
                    line = line[:(close_tag - line_offset) + 12]
                    xml_finished = True

                if xml_started:
                    xmp_string += line

                if xml_finished:
                    break

            logger.debug('XMP Finished searching for info')
        if xmp_string:
            hdr.parse_xmp(xmp_string)

    return hdr.tags
