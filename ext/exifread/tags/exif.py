"""
Standard tag definitions.
"""

from exifread.utils import make_string, make_string_uc

# Interoperability tags
INTEROP_TAGS = {
    0x0001: ('InteroperabilityIndex', ),
    0x0002: ('InteroperabilityVersion', ),
    0x1000: ('RelatedImageFileFormat', ),
    0x1001: ('RelatedImageWidth', ),
    0x1002: ('RelatedImageLength', ),
}
INTEROP_INFO = (
    'Interoperability',
    INTEROP_TAGS
)

# GPS tags
GPS_TAGS = {
    0x0000: ('GPSVersionID', ),
    0x0001: ('GPSLatitudeRef', ),
    0x0002: ('GPSLatitude', ),
    0x0003: ('GPSLongitudeRef', ),
    0x0004: ('GPSLongitude', ),
    0x0005: ('GPSAltitudeRef', ),
    0x0006: ('GPSAltitude', ),
    0x0007: ('GPSTimeStamp', ),
    0x0008: ('GPSSatellites', ),
    0x0009: ('GPSStatus', ),
    0x000A: ('GPSMeasureMode', ),
    0x000B: ('GPSDOP', ),
    0x000C: ('GPSSpeedRef', ),
    0x000D: ('GPSSpeed', ),
    0x000E: ('GPSTrackRef', ),
    0x000F: ('GPSTrack', ),
    0x0010: ('GPSImgDirectionRef', ),
    0x0011: ('GPSImgDirection', ),
    0x0012: ('GPSMapDatum', ),
    0x0013: ('GPSDestLatitudeRef', ),
    0x0014: ('GPSDestLatitude', ),
    0x0015: ('GPSDestLongitudeRef', ),
    0x0016: ('GPSDestLongitude', ),
    0x0017: ('GPSDestBearingRef', ),
    0x0018: ('GPSDestBearing', ),
    0x0019: ('GPSDestDistanceRef', ),
    0x001A: ('GPSDestDistance', ),
    0x001B: ('GPSProcessingMethod', ),
    0x001C: ('GPSAreaInformation', ),
    0x001D: ('GPSDate', ),
    0x001E: ('GPSDifferential', ),
}
GPS_INFO = (
    'GPS',
    GPS_TAGS
)

# Main Exif tag names
EXIF_TAGS = {
    0x00FE: ('SubfileType', {
        0x0: 'Full-resolution Image',
        0x1: 'Reduced-resolution image',
        0x2: 'Single page of multi-page image',
        0x3: 'Single page of multi-page reduced-resolution image',
        0x4: 'Transparency mask',
        0x5: 'Transparency mask of reduced-resolution image',
        0x6: 'Transparency mask of multi-page image',
        0x7: 'Transparency mask of reduced-resolution multi-page image',
        0x10001: 'Alternate reduced-resolution image',
        0xffffffff: 'invalid ',
    }),
    0x00FF: ('OldSubfileType', {
        1: 'Full-resolution image',
        2: 'Reduced-resolution image',
        3: 'Single page of multi-page image',
    }),
    0x0100: ('ImageWidth', ),
    0x0101: ('ImageLength', ),
    0x0102: ('BitsPerSample', ),
    0x0103: ('Compression', {
        1: 'Uncompressed',
        2: 'CCITT 1D',
        3: 'T4/Group 3 Fax',
        4: 'T6/Group 4 Fax',
        5: 'LZW',
        6: 'JPEG (old-style)',
        7: 'JPEG',
        8: 'Adobe Deflate',
        9: 'JBIG B&W',
        10: 'JBIG Color',
        32766: 'Next',
        32769: 'Epson ERF Compressed',
        32771: 'CCIRLEW',
        32773: 'PackBits',
        32809: 'Thunderscan',
        32895: 'IT8CTPAD',
        32896: 'IT8LW',
        32897: 'IT8MP',
        32898: 'IT8BL',
        32908: 'PixarFilm',
        32909: 'PixarLog',
        32946: 'Deflate',
        32947: 'DCS',
        34661: 'JBIG',
        34676: 'SGILog',
        34677: 'SGILog24',
        34712: 'JPEG 2000',
        34713: 'Nikon NEF Compressed',
        65000: 'Kodak DCR Compressed',
        65535: 'Pentax PEF Compressed'
    }),
    0x0106: ('PhotometricInterpretation', ),
    0x0107: ('Thresholding', ),
    0x0108: ('CellWidth', ),
    0x0109: ('CellLength', ),
    0x010A: ('FillOrder', ),
    0x010D: ('DocumentName', ),
    0x010E: ('ImageDescription', ),
    0x010F: ('Make', ),
    0x0110: ('Model', ),
    0x0111: ('StripOffsets', ),
    0x0112: ('Orientation', {
        1: 'Horizontal (normal)',
        2: 'Mirrored horizontal',
        3: 'Rotated 180',
        4: 'Mirrored vertical',
        5: 'Mirrored horizontal then rotated 90 CCW',
        6: 'Rotated 90 CCW',
        7: 'Mirrored horizontal then rotated 90 CW',
        8: 'Rotated 90 CW'
    }),
    0x0115: ('SamplesPerPixel', ),
    0x0116: ('RowsPerStrip', ),
    0x0117: ('StripByteCounts', ),
    0x0118: ('MinSampleValue', ),
    0x0119: ('MaxSampleValue', ),
    0x011A: ('XResolution', ),
    0x011B: ('YResolution', ),
    0x011C: ('PlanarConfiguration', ),
    0x011D: ('PageName', make_string),
    0x011E: ('XPosition', ),
    0x011F: ('YPosition', ),
    0x0122: ('GrayResponseUnit', {
        1: '0.1',
        2: '0.001',
        3: '0.0001',
        4: '1e-05',
        5: '1e-06',
    }),
    0x0123: ('GrayResponseCurve', ),
    0x0124: ('T4Options', ),
    0x0125: ('T6Options', ),
    0x0128: ('ResolutionUnit', {
        1: 'Not Absolute',
        2: 'Pixels/Inch',
        3: 'Pixels/Centimeter'
    }),
    0x0129: ('PageNumber', ),
    0x012C: ('ColorResponseUnit', ),
    0x012D: ('TransferFunction', ),
    0x0131: ('Software', ),
    0x0132: ('DateTime', ),
    0x013B: ('Artist', ),
    0x013C: ('HostComputer', ),
    0x013D: ('Predictor', {
        1: 'None',
        2: 'Horizontal differencing'
    }),
    0x013E: ('WhitePoint', ),
    0x013F: ('PrimaryChromaticities', ),
    0x0140: ('ColorMap', ),
    0x0141: ('HalftoneHints', ),
    0x0142: ('TileWidth', ),
    0x0143: ('TileLength', ),
    0x0144: ('TileOffsets', ),
    0x0145: ('TileByteCounts', ),
    0x0146: ('BadFaxLines', ),
    0x0147: ('CleanFaxData', {
        0: 'Clean',
        1: 'Regenerated',
        2: 'Unclean'
    }),
    0x0148: ('ConsecutiveBadFaxLines', ),
    0x014C: ('InkSet', {
        1: 'CMYK',
        2: 'Not CMYK'
    }),
    0x014D: ('InkNames', ),
    0x014E: ('NumberofInks', ),
    0x0150: ('DotRange', ),
    0x0151: ('TargetPrinter', ),
    0x0152: ('ExtraSamples', {
        0: 'Unspecified',
        1: 'Associated Alpha',
        2: 'Unassociated Alpha'
    }),
    0x0153: ('SampleFormat', {
        1: 'Unsigned',
        2: 'Signed',
        3: 'Float',
        4: 'Undefined',
        5: 'Complex int',
        6: 'Complex float'
    }),
    0x0154: ('SMinSampleValue', ),
    0x0155: ('SMaxSampleValue', ),
    0x0156: ('TransferRange', ),
    0x0157: ('ClipPath', ),
    0x0200: ('JPEGProc', ),
    0x0201: ('JPEGInterchangeFormat', ),
    0x0202: ('JPEGInterchangeFormatLength', ),
    0x0211: ('YCbCrCoefficients', ),
    0x0212: ('YCbCrSubSampling', ),
    0x0213: ('YCbCrPositioning', {
        1: 'Centered',
        2: 'Co-sited'
    }),
    0x0214: ('ReferenceBlackWhite', ),
    0x02BC: ('ApplicationNotes', ),  # XPM Info
    0x4746: ('Rating', ),
    0x828D: ('CFARepeatPatternDim', ),
    0x828E: ('CFAPattern', ),
    0x828F: ('BatteryLevel', ),
    0x8298: ('Copyright', ),
    0x829A: ('ExposureTime', ),
    0x829D: ('FNumber', ),
    0x83BB: ('IPTC/NAA', ),
    0x8769: ('ExifOffset', ),  # Exif Tags
    0x8773: ('InterColorProfile', ),
    0x8822: ('ExposureProgram', {
        0: 'Unidentified',
        1: 'Manual',
        2: 'Program Normal',
        3: 'Aperture Priority',
        4: 'Shutter Priority',
        5: 'Program Creative',
        6: 'Program Action',
        7: 'Portrait Mode',
        8: 'Landscape Mode'
    }),
    0x8824: ('SpectralSensitivity', ),
    0x8825: ('GPSInfo', GPS_INFO),  # GPS tags
    0x8827: ('ISOSpeedRatings', ),
    0x8828: ('OECF', ),
    0x8830: ('SensitivityType', {
        0: 'Unknown',
        1: 'Standard Output Sensitivity',
        2: 'Recommended Exposure Index',
        3: 'ISO Speed',
        4: 'Standard Output Sensitivity and Recommended Exposure Index',
        5: 'Standard Output Sensitivity and ISO Speed',
        6: 'Recommended Exposure Index and ISO Speed',
        7: 'Standard Output Sensitivity, Recommended Exposure Index and ISO Speed'
    }),
    0x8832: ('RecommendedExposureIndex', ),
    0x8833: ('ISOSpeed', ),
    0x9000: ('ExifVersion', make_string),
    0x9003: ('DateTimeOriginal', ),
    0x9004: ('DateTimeDigitized', ),
    0x9101: ('ComponentsConfiguration', {
        0: '',
        1: 'Y',
        2: 'Cb',
        3: 'Cr',
        4: 'Red',
        5: 'Green',
        6: 'Blue'
    }),
    0x9102: ('CompressedBitsPerPixel', ),
    0x9201: ('ShutterSpeedValue', ),
    0x9202: ('ApertureValue', ),
    0x9203: ('BrightnessValue', ),
    0x9204: ('ExposureBiasValue', ),
    0x9205: ('MaxApertureValue', ),
    0x9206: ('SubjectDistance', ),
    0x9207: ('MeteringMode', {
        0: 'Unidentified',
        1: 'Average',
        2: 'CenterWeightedAverage',
        3: 'Spot',
        4: 'MultiSpot',
        5: 'Pattern',
        6: 'Partial',
        255: 'other'
    }),
    0x9208: ('LightSource', {
        0: 'Unknown',
        1: 'Daylight',
        2: 'Fluorescent',
        3: 'Tungsten (incandescent light)',
        4: 'Flash',
        9: 'Fine weather',
        10: 'Cloudy weather',
        11: 'Shade',
        12: 'Daylight fluorescent (D 5700 - 7100K)',
        13: 'Day white fluorescent (N 4600 - 5400K)',
        14: 'Cool white fluorescent (W 3900 - 4500K)',
        15: 'White fluorescent (WW 3200 - 3700K)',
        17: 'Standard light A',
        18: 'Standard light B',
        19: 'Standard light C',
        20: 'D55',
        21: 'D65',
        22: 'D75',
        23: 'D50',
        24: 'ISO studio tungsten',
        255: 'other light source'
    }),
    0x9209: ('Flash', {
        0: 'Flash did not fire',
        1: 'Flash fired',
        5: 'Strobe return light not detected',
        7: 'Strobe return light detected',
        9: 'Flash fired, compulsory flash mode',
        13: 'Flash fired, compulsory flash mode, return light not detected',
        15: 'Flash fired, compulsory flash mode, return light detected',
        16: 'Flash did not fire, compulsory flash mode',
        24: 'Flash did not fire, auto mode',
        25: 'Flash fired, auto mode',
        29: 'Flash fired, auto mode, return light not detected',
        31: 'Flash fired, auto mode, return light detected',
        32: 'No flash function',
        65: 'Flash fired, red-eye reduction mode',
        69: 'Flash fired, red-eye reduction mode, return light not detected',
        71: 'Flash fired, red-eye reduction mode, return light detected',
        73: 'Flash fired, compulsory flash mode, red-eye reduction mode',
        77: 'Flash fired, compulsory flash mode, red-eye reduction mode, return light not detected',
        79: 'Flash fired, compulsory flash mode, red-eye reduction mode, return light detected',
        89: 'Flash fired, auto mode, red-eye reduction mode',
        93: 'Flash fired, auto mode, return light not detected, red-eye reduction mode',
        95: 'Flash fired, auto mode, return light detected, red-eye reduction mode'
    }),
    0x920A: ('FocalLength', ),
    0x9214: ('SubjectArea', ),
    0x927C: ('MakerNote', ),
    0x9286: ('UserComment', make_string_uc),
    0x9290: ('SubSecTime', ),
    0x9291: ('SubSecTimeOriginal', ),
    0x9292: ('SubSecTimeDigitized', ),

    # used by Windows Explorer
    0x9C9B: ('XPTitle', ),
    0x9C9C: ('XPComment', ),
    0x9C9D: ('XPAuthor', make_string),  # (ignored by Windows Explorer if Artist exists)
    0x9C9E: ('XPKeywords', ),
    0x9C9F: ('XPSubject', ),
    0xA000: ('FlashPixVersion', make_string),
    0xA001: ('ColorSpace', {
        1: 'sRGB',
        2: 'Adobe RGB',
        65535: 'Uncalibrated'
    }),
    0xA002: ('ExifImageWidth', ),
    0xA003: ('ExifImageLength', ),
    0xA004: ('RelatedSoundFile', ),
    0xA005: ('InteroperabilityOffset', INTEROP_INFO),
    0xA20B: ('FlashEnergy', ),               # 0x920B in TIFF/EP
    0xA20C: ('SpatialFrequencyResponse', ),  # 0x920C
    0xA20E: ('FocalPlaneXResolution', ),     # 0x920E
    0xA20F: ('FocalPlaneYResolution', ),     # 0x920F
    0xA210: ('FocalPlaneResolutionUnit', ),  # 0x9210
    0xA214: ('SubjectLocation', ),           # 0x9214
    0xA215: ('ExposureIndex', ),             # 0x9215
    0xA217: ('SensingMethod', {              # 0x9217
        1: 'Not defined',
        2: 'One-chip color area',
        3: 'Two-chip color area',
        4: 'Three-chip color area',
        5: 'Color sequential area',
        7: 'Trilinear',
        8: 'Color sequential linear'
    }),
    0xA300: ('FileSource', {
        1: 'Film Scanner',
        2: 'Reflection Print Scanner',
        3: 'Digital Camera'
    }),
    0xA301: ('SceneType', {
        1: 'Directly Photographed'
    }),
    0xA302: ('CVAPattern', ),
    0xA401: ('CustomRendered', {
        0: 'Normal',
        1: 'Custom'
    }),
    0xA402: ('ExposureMode', {
        0: 'Auto Exposure',
        1: 'Manual Exposure',
        2: 'Auto Bracket'
    }),
    0xA403: ('WhiteBalance', {
        0: 'Auto',
        1: 'Manual'
    }),
    0xA404: ('DigitalZoomRatio', ),
    0xA405: ('FocalLengthIn35mmFilm', ),
    0xA406: ('SceneCaptureType', {
        0: 'Standard',
        1: 'Landscape',
        2: 'Portrait',
        3: 'Night)'
    }),
    0xA407: ('GainControl', {
        0: 'None',
        1: 'Low gain up',
        2: 'High gain up',
        3: 'Low gain down',
        4: 'High gain down'
    }),
    0xA408: ('Contrast', {
        0: 'Normal',
        1: 'Soft',
        2: 'Hard'
    }),
    0xA409: ('Saturation', {
        0: 'Normal',
        1: 'Soft',
        2: 'Hard'
    }),
    0xA40A: ('Sharpness', {
        0: 'Normal',
        1: 'Soft',
        2: 'Hard'
    }),
    0xA40B: ('DeviceSettingDescription', ),
    0xA40C: ('SubjectDistanceRange', ),
    0xA420: ('ImageUniqueID', ),
    0xA430: ('CameraOwnerName', ),
    0xA431: ('BodySerialNumber', ),
    0xA432: ('LensSpecification', ),
    0xA433: ('LensMake', ),
    0xA434: ('LensModel', ),
    0xA435: ('LensSerialNumber', ),
    0xA500: ('Gamma', ),
    0xC4A5: ('PrintIM', ),
    0xEA1C: ('Padding', ),
    0xEA1D: ('OffsetSchema', ),
    0xFDE8: ('OwnerName', ),
    0xFDE9: ('SerialNumber', ),
}
