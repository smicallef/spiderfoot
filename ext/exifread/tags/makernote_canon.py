"""
Makernote (proprietary) tag definitions for Canon.

http://www.sno.phy.queensu.ca/~phil/exiftool/TagNames/Canon.html
"""

TAGS = {
    0x0003: ('FlashInfo',),
    0x0006: ('ImageType', ),
    0x0007: ('FirmwareVersion', ),
    0x0008: ('ImageNumber', ),
    0x0009: ('OwnerName', ),
    0x000C: ('SerialNumber', ),
    0x000E: ('FileLength', ),
    0x0010: ('ModelID', {
        0x1010000: 'PowerShot A30',
        0x1040000: 'PowerShot S300 / Digital IXUS 300 / IXY Digital 300',
        0x1060000: 'PowerShot A20',
        0x1080000: 'PowerShot A10',
        0x1090000: 'PowerShot S110 / Digital IXUS v / IXY Digital 200',
        0x1100000: 'PowerShot G2',
        0x1110000: 'PowerShot S40',
        0x1120000: 'PowerShot S30',
        0x1130000: 'PowerShot A40',
        0x1140000: 'EOS D30',
        0x1150000: 'PowerShot A100',
        0x1160000: 'PowerShot S200 / Digital IXUS v2 / IXY Digital 200a',
        0x1170000: 'PowerShot A200',
        0x1180000: 'PowerShot S330 / Digital IXUS 330 / IXY Digital 300a',
        0x1190000: 'PowerShot G3',
        0x1210000: 'PowerShot S45',
        0x1230000: 'PowerShot SD100 / Digital IXUS II / IXY Digital 30',
        0x1240000: 'PowerShot S230 / Digital IXUS v3 / IXY Digital 320',
        0x1250000: 'PowerShot A70',
        0x1260000: 'PowerShot A60',
        0x1270000: 'PowerShot S400 / Digital IXUS 400 / IXY Digital 400',
        0x1290000: 'PowerShot G5',
        0x1300000: 'PowerShot A300',
        0x1310000: 'PowerShot S50',
        0x1340000: 'PowerShot A80',
        0x1350000: 'PowerShot SD10 / Digital IXUS i / IXY Digital L',
        0x1360000: 'PowerShot S1 IS',
        0x1370000: 'PowerShot Pro1',
        0x1380000: 'PowerShot S70',
        0x1390000: 'PowerShot S60',
        0x1400000: 'PowerShot G6',
        0x1410000: 'PowerShot S500 / Digital IXUS 500 / IXY Digital 500',
        0x1420000: 'PowerShot A75',
        0x1440000: 'PowerShot SD110 / Digital IXUS IIs / IXY Digital 30a',
        0x1450000: 'PowerShot A400',
        0x1470000: 'PowerShot A310',
        0x1490000: 'PowerShot A85',
        0x1520000: 'PowerShot S410 / Digital IXUS 430 / IXY Digital 450',
        0x1530000: 'PowerShot A95',
        0x1540000: 'PowerShot SD300 / Digital IXUS 40 / IXY Digital 50',
        0x1550000: 'PowerShot SD200 / Digital IXUS 30 / IXY Digital 40',
        0x1560000: 'PowerShot A520',
        0x1570000: 'PowerShot A510',
        0x1590000: 'PowerShot SD20 / Digital IXUS i5 / IXY Digital L2',
        0x1640000: 'PowerShot S2 IS',
        0x1650000: 'PowerShot SD430 / Digital IXUS Wireless / IXY Digital Wireless',
        0x1660000: 'PowerShot SD500 / Digital IXUS 700 / IXY Digital 600',
        0x1668000: 'EOS D60',
        0x1700000: 'PowerShot SD30 / Digital IXUS i Zoom / IXY Digital L3',
        0x1740000: 'PowerShot A430',
        0x1750000: 'PowerShot A410',
        0x1760000: 'PowerShot S80',
        0x1780000: 'PowerShot A620',
        0x1790000: 'PowerShot A610',
        0x1800000: 'PowerShot SD630 / Digital IXUS 65 / IXY Digital 80',
        0x1810000: 'PowerShot SD450 / Digital IXUS 55 / IXY Digital 60',
        0x1820000: 'PowerShot TX1',
        0x1870000: 'PowerShot SD400 / Digital IXUS 50 / IXY Digital 55',
        0x1880000: 'PowerShot A420',
        0x1890000: 'PowerShot SD900 / Digital IXUS 900 Ti / IXY Digital 1000',
        0x1900000: 'PowerShot SD550 / Digital IXUS 750 / IXY Digital 700',
        0x1920000: 'PowerShot A700',
        0x1940000: 'PowerShot SD700 IS / Digital IXUS 800 IS / IXY Digital 800 IS',
        0x1950000: 'PowerShot S3 IS',
        0x1960000: 'PowerShot A540',
        0x1970000: 'PowerShot SD600 / Digital IXUS 60 / IXY Digital 70',
        0x1980000: 'PowerShot G7',
        0x1990000: 'PowerShot A530',
        0x2000000: 'PowerShot SD800 IS / Digital IXUS 850 IS / IXY Digital 900 IS',
        0x2010000: 'PowerShot SD40 / Digital IXUS i7 / IXY Digital L4',
        0x2020000: 'PowerShot A710 IS',
        0x2030000: 'PowerShot A640',
        0x2040000: 'PowerShot A630',
        0x2090000: 'PowerShot S5 IS',
        0x2100000: 'PowerShot A460',
        0x2120000: 'PowerShot SD850 IS / Digital IXUS 950 IS / IXY Digital 810 IS',
        0x2130000: 'PowerShot A570 IS',
        0x2140000: 'PowerShot A560',
        0x2150000: 'PowerShot SD750 / Digital IXUS 75 / IXY Digital 90',
        0x2160000: 'PowerShot SD1000 / Digital IXUS 70 / IXY Digital 10',
        0x2180000: 'PowerShot A550',
        0x2190000: 'PowerShot A450',
        0x2230000: 'PowerShot G9',
        0x2240000: 'PowerShot A650 IS',
        0x2260000: 'PowerShot A720 IS',
        0x2290000: 'PowerShot SX100 IS',
        0x2300000: 'PowerShot SD950 IS / Digital IXUS 960 IS / IXY Digital 2000 IS',
        0x2310000: 'PowerShot SD870 IS / Digital IXUS 860 IS / IXY Digital 910 IS',
        0x2320000: 'PowerShot SD890 IS / Digital IXUS 970 IS / IXY Digital 820 IS',
        0x2360000: 'PowerShot SD790 IS / Digital IXUS 90 IS / IXY Digital 95 IS',
        0x2370000: 'PowerShot SD770 IS / Digital IXUS 85 IS / IXY Digital 25 IS',
        0x2380000: 'PowerShot A590 IS',
        0x2390000: 'PowerShot A580',
        0x2420000: 'PowerShot A470',
        0x2430000: 'PowerShot SD1100 IS / Digital IXUS 80 IS / IXY Digital 20 IS',
        0x2460000: 'PowerShot SX1 IS',
        0x2470000: 'PowerShot SX10 IS',
        0x2480000: 'PowerShot A1000 IS',
        0x2490000: 'PowerShot G10',
        0x2510000: 'PowerShot A2000 IS',
        0x2520000: 'PowerShot SX110 IS',
        0x2530000: 'PowerShot SD990 IS / Digital IXUS 980 IS / IXY Digital 3000 IS',
        0x2540000: 'PowerShot SD880 IS / Digital IXUS 870 IS / IXY Digital 920 IS',
        0x2550000: 'PowerShot E1',
        0x2560000: 'PowerShot D10',
        0x2570000: 'PowerShot SD960 IS / Digital IXUS 110 IS / IXY Digital 510 IS',
        0x2580000: 'PowerShot A2100 IS',
        0x2590000: 'PowerShot A480',
        0x2600000: 'PowerShot SX200 IS',
        0x2610000: 'PowerShot SD970 IS / Digital IXUS 990 IS / IXY Digital 830 IS',
        0x2620000: 'PowerShot SD780 IS / Digital IXUS 100 IS / IXY Digital 210 IS',
        0x2630000: 'PowerShot A1100 IS',
        0x2640000: 'PowerShot SD1200 IS / Digital IXUS 95 IS / IXY Digital 110 IS',
        0x2700000: 'PowerShot G11',
        0x2710000: 'PowerShot SX120 IS',
        0x2720000: 'PowerShot S90',
        0x2750000: 'PowerShot SX20 IS',
        0x2760000: 'PowerShot SD980 IS / Digital IXUS 200 IS / IXY Digital 930 IS',
        0x2770000: 'PowerShot SD940 IS / Digital IXUS 120 IS / IXY Digital 220 IS',
        0x2800000: 'PowerShot A495',
        0x2810000: 'PowerShot A490',
        0x2820000: 'PowerShot A3100 IS / A3150 IS',
        0x2830000: 'PowerShot A3000 IS',
        0x2840000: 'PowerShot SD1400 IS / IXUS 130 / IXY 400F',
        0x2850000: 'PowerShot SD1300 IS / IXUS 105 / IXY 200F',
        0x2860000: 'PowerShot SD3500 IS / IXUS 210 / IXY 10S',
        0x2870000: 'PowerShot SX210 IS',
        0x2880000: 'PowerShot SD4000 IS / IXUS 300 HS / IXY 30S',
        0x2890000: 'PowerShot SD4500 IS / IXUS 1000 HS / IXY 50S',
        0x2920000: 'PowerShot G12',
        0x2930000: 'PowerShot SX30 IS',
        0x2940000: 'PowerShot SX130 IS',
        0x2950000: 'PowerShot S95',
        0x2980000: 'PowerShot A3300 IS',
        0x2990000: 'PowerShot A3200 IS',
        0x3000000: 'PowerShot ELPH 500 HS / IXUS 310 HS / IXY 31S',
        0x3010000: 'PowerShot Pro90 IS',
        0x3010001: 'PowerShot A800',
        0x3020000: 'PowerShot ELPH 100 HS / IXUS 115 HS / IXY 210F',
        0x3030000: 'PowerShot SX230 HS',
        0x3040000: 'PowerShot ELPH 300 HS / IXUS 220 HS / IXY 410F',
        0x3050000: 'PowerShot A2200',
        0x3060000: 'PowerShot A1200',
        0x3070000: 'PowerShot SX220 HS',
        0x3080000: 'PowerShot G1 X',
        0x3090000: 'PowerShot SX150 IS',
        0x3100000: 'PowerShot ELPH 510 HS / IXUS 1100 HS / IXY 51S',
        0x3110000: 'PowerShot S100 (new)',
        0x3120000: 'PowerShot ELPH 310 HS / IXUS 230 HS / IXY 600F',
        0x3130000: 'PowerShot SX40 HS',
        0x3140000: 'IXY 32S',
        0x3160000: 'PowerShot A1300',
        0x3170000: 'PowerShot A810',
        0x3180000: 'PowerShot ELPH 320 HS / IXUS 240 HS / IXY 420F',
        0x3190000: 'PowerShot ELPH 110 HS / IXUS 125 HS / IXY 220F',
        0x3200000: 'PowerShot D20',
        0x3210000: 'PowerShot A4000 IS',
        0x3220000: 'PowerShot SX260 HS',
        0x3230000: 'PowerShot SX240 HS',
        0x3240000: 'PowerShot ELPH 530 HS / IXUS 510 HS / IXY 1',
        0x3250000: 'PowerShot ELPH 520 HS / IXUS 500 HS / IXY 3',
        0x3260000: 'PowerShot A3400 IS',
        0x3270000: 'PowerShot A2400 IS',
        0x3280000: 'PowerShot A2300',
        0x3330000: 'PowerShot G15',
        0x3340000: 'PowerShot SX50',
        0x3350000: 'PowerShot SX160 IS',
        0x3360000: 'PowerShot S110 (new)',
        0x3370000: 'PowerShot SX500 IS',
        0x3380000: 'PowerShot N',
        0x3390000: 'IXUS 245 HS / IXY 430F',
        0x3400000: 'PowerShot SX280 HS',
        0x3410000: 'PowerShot SX270 HS',
        0x3420000: 'PowerShot A3500 IS',
        0x3430000: 'PowerShot A2600',
        0x3450000: 'PowerShot A1400',
        0x3460000: 'PowerShot ELPH 130 IS / IXUS 140 / IXY 110F',
        0x3470000: 'PowerShot ELPH 115/120 IS / IXUS 132/135 / IXY 90F/100F',
        0x3490000: 'PowerShot ELPH 330 HS / IXUS 255 HS / IXY 610F',
        0x3510000: 'PowerShot A2500',
        0x3540000: 'PowerShot G16',
        0x3550000: 'PowerShot S120',
        0x3560000: 'PowerShot SX170 IS',
        0x3580000: 'PowerShot SX510 HS',
        0x3590000: 'PowerShot S200 (new)',
        0x3600000: 'IXY 620F',
        0x3610000: 'PowerShot N100',
        0x3640000: 'PowerShot G1 X Mark II',
        0x3650000: 'PowerShot D30',
        0x3660000: 'PowerShot SX700 HS',
        0x3670000: 'PowerShot SX600 HS',
        0x3680000: 'PowerShot ELPH 140 IS / IXUS 150',
        0x3690000: 'PowerShot ELPH 135 / IXUS 145 / IXY 120',
        0x3700000: 'PowerShot ELPH 340 HS / IXUS 265 HS / IXY 630',
        0x3710000: 'PowerShot ELPH 150 IS / IXUS 155 / IXY 140',
        0x3750000: 'PowerShot SX60 HS',
        0x3760000: 'PowerShot SX520 HS',
        0x3780000: 'PowerShot G7 X',
        0x4040000: 'PowerShot G1',
        0x6040000: 'PowerShot S100 / Digital IXUS / IXY Digital',
        0x4007d673: 'DC19/DC21/DC22',
        0x4007d674: 'XH A1',
        0x4007d675: 'HV10',
        0x4007d676: 'MD130/MD140/MD150/MD160/ZR850',
        0x4007d777: 'DC50',
        0x4007d778: 'HV20',
        0x4007d779: 'DC211',
        0x4007d77a: 'HG10',
        0x4007d77b: 'HR10',
        0x4007d77d: 'MD255/ZR950',
        0x4007d81c: 'HF11',
        0x4007d878: 'HV30',
        0x4007d87c: 'XH A1S',
        0x4007d87e: 'DC301/DC310/DC311/DC320/DC330',
        0x4007d87f: 'FS100',
        0x4007d880: 'HF10',
        0x4007d882: 'HG20/HG21',
        0x4007d925: 'HF21',
        0x4007d926: 'HF S11',
        0x4007d978: 'HV40',
        0x4007d987: 'DC410/DC411/DC420',
        0x4007d988: 'FS19/FS20/FS21/FS22/FS200',
        0x4007d989: 'HF20/HF200',
        0x4007d98a: 'HF S10/S100',
        0x4007da8e: 'HF R10/R16/R17/R18/R100/R106',
        0x4007da8f: 'HF M30/M31/M36/M300/M306',
        0x4007da90: 'HF S20/S21/S200',
        0x4007da92: 'FS31/FS36/FS37/FS300/FS305/FS306/FS307',
        0x4007dda9: 'HF G25',
        0x80000001: 'EOS-1D',
        0x80000167: 'EOS-1DS',
        0x80000168: 'EOS 10D',
        0x80000169: 'EOS-1D Mark III',
        0x80000170: 'EOS Digital Rebel / 300D / Kiss Digital',
        0x80000174: 'EOS-1D Mark II',
        0x80000175: 'EOS 20D',
        0x80000176: 'EOS Digital Rebel XSi / 450D / Kiss X2',
        0x80000188: 'EOS-1Ds Mark II',
        0x80000189: 'EOS Digital Rebel XT / 350D / Kiss Digital N',
        0x80000190: 'EOS 40D',
        0x80000213: 'EOS 5D',
        0x80000215: 'EOS-1Ds Mark III',
        0x80000218: 'EOS 5D Mark II',
        0x80000219: 'WFT-E1',
        0x80000232: 'EOS-1D Mark II N',
        0x80000234: 'EOS 30D',
        0x80000236: 'EOS Digital Rebel XTi / 400D / Kiss Digital X',
        0x80000241: 'WFT-E2',
        0x80000246: 'WFT-E3',
        0x80000250: 'EOS 7D',
        0x80000252: 'EOS Rebel T1i / 500D / Kiss X3',
        0x80000254: 'EOS Rebel XS / 1000D / Kiss F',
        0x80000261: 'EOS 50D',
        0x80000269: 'EOS-1D X',
        0x80000270: 'EOS Rebel T2i / 550D / Kiss X4',
        0x80000271: 'WFT-E4',
        0x80000273: 'WFT-E5',
        0x80000281: 'EOS-1D Mark IV',
        0x80000285: 'EOS 5D Mark III',
        0x80000286: 'EOS Rebel T3i / 600D / Kiss X5',
        0x80000287: 'EOS 60D',
        0x80000288: 'EOS Rebel T3 / 1100D / Kiss X50',
        0x80000289: 'EOS 7D Mark II',
        0x80000297: 'WFT-E2 II',
        0x80000298: 'WFT-E4 II',
        0x80000301: 'EOS Rebel T4i / 650D / Kiss X6i',
        0x80000302: 'EOS 6D',
        0x80000324: 'EOS-1D C',
        0x80000325: 'EOS 70D',
        0x80000326: 'EOS Rebel T5i / 700D / Kiss X7i',
        0x80000327: 'EOS Rebel T5 / 1200D / Kiss X70',
        0x80000331: 'EOS M',
        0x80000346: 'EOS Rebel SL1 / 100D / Kiss X7',
        0x80000355: 'EOS M2'
    }),
    0x0013: ('ThumbnailImageValidArea', ),
    0x0015: ('SerialNumberFormat', {
        0x90000000: 'Format 1',
        0xA0000000: 'Format 2'
    }),
    0x001A: ('SuperMacro', {
        0: 'Off',
        1: 'On (1)',
        2: 'On (2)'
    }),
    0x001C: ('DateStampMode', {
        0: 'Off',
        1: 'Date',
        2: 'Date & Time',
    }),
    0x001E: ('FirmwareRevision', ),
    0x0028: ('ImageUniqueID', ),
    0x0095: ('LensModel', ),
    0x0096: ('InternalSerialNumber ', ),
    0x0097: ('DustRemovalData ', ),
    0x0098: ('CropInfo ', ),
    0x009A: ('AspectInfo', ),
    0x00b4: ('ColorSpace', {
        1: 'sRGB',
        2: 'Adobe RGB'
    }),
}

# this is in element offset, name, optional value dictionary format
# 0x0001
CAMERA_SETTINGS = {
    1: ('Macromode', {
        1: 'Macro',
        2: 'Normal'
    }),
    2: ('SelfTimer', ),
    3: ('Quality', {
        1: 'Economy',
        2: 'Normal',
        3: 'Fine',
        5: 'Superfine'
    }),
    4: ('FlashMode', {
        0: 'Flash Not Fired',
        1: 'Auto',
        2: 'On',
        3: 'Red-Eye Reduction',
        4: 'Slow Synchro',
        5: 'Auto + Red-Eye Reduction',
        6: 'On + Red-Eye Reduction',
        16: 'external flash'
    }),
    5: ('ContinuousDriveMode', {
        0: 'Single Or Timer',
        1: 'Continuous',
        2: 'Movie',
    }),
    7: ('FocusMode', {
        0: 'One-Shot',
        1: 'AI Servo',
        2: 'AI Focus',
        3: 'MF',
        4: 'Single',
        5: 'Continuous',
        6: 'MF'
    }),
    9: ('RecordMode', {
        1: 'JPEG',
        2: 'CRW+THM',
        3: 'AVI+THM',
        4: 'TIF',
        5: 'TIF+JPEG',
        6: 'CR2',
        7: 'CR2+JPEG',
        9: 'Video'
    }),
    10: ('ImageSize', {
        0: 'Large',
        1: 'Medium',
        2: 'Small'
    }),
    11: ('EasyShootingMode', {
        0: 'Full Auto',
        1: 'Manual',
        2: 'Landscape',
        3: 'Fast Shutter',
        4: 'Slow Shutter',
        5: 'Night',
        6: 'B&W',
        7: 'Sepia',
        8: 'Portrait',
        9: 'Sports',
        10: 'Macro/Close-Up',
        11: 'Pan Focus'
    }),
    12: ('DigitalZoom', {
        0: 'None',
        1: '2x',
        2: '4x',
        3: 'Other'
    }),
    13: ('Contrast', {
        0xFFFF: 'Low',
        0: 'Normal',
        1: 'High'
    }),
    14: ('Saturation', {
        0xFFFF: 'Low',
        0: 'Normal',
        1: 'High'
    }),
    15: ('Sharpness', {
        0xFFFF: 'Low',
        0: 'Normal',
        1: 'High'
    }),
    16: ('ISO', {
        0: 'See ISOSpeedRatings Tag',
        15: 'Auto',
        16: '50',
        17: '100',
        18: '200',
        19: '400'
    }),
    17: ('MeteringMode', {
        0: 'Default',
        1: 'Spot',
        2: 'Average',
        3: 'Evaluative',
        4: 'Partial',
        5: 'Center-weighted'
    }),
    18: ('FocusType', {
        0: 'Manual',
        1: 'Auto',
        3: 'Close-Up (Macro)',
        8: 'Locked (Pan Mode)'
    }),
    19: ('AFPointSelected', {
        0x3000: 'None (MF)',
        0x3001: 'Auto-Selected',
        0x3002: 'Right',
        0x3003: 'Center',
        0x3004: 'Left'
    }),
    20: ('ExposureMode', {
        0: 'Easy Shooting',
        1: 'Program',
        2: 'Tv-priority',
        3: 'Av-priority',
        4: 'Manual',
        5: 'A-DEP'
    }),
    22: ('LensType', ),
    23: ('LongFocalLengthOfLensInFocalUnits', ),
    24: ('ShortFocalLengthOfLensInFocalUnits', ),
    25: ('FocalUnitsPerMM', ),
    28: ('FlashActivity', {
        0: 'Did Not Fire',
        1: 'Fired'
    }),
    29: ('FlashDetails', {
        0: 'Manual',
        1: 'TTL',
        2: 'A-TTL',
        3: 'E-TTL',
        4: 'FP Sync Enabled',
        7: '2nd("Rear")-Curtain Sync Used',
        11: 'FP Sync Used',
        13: 'Internal Flash',
        14: 'External E-TTL'
    }),
    32: ('FocusMode', {
        0: 'Single',
        1: 'Continuous',
        8: 'Manual'
    }),
    33: ('AESetting', {
        0: 'Normal AE',
        1: 'Exposure Compensation',
        2: 'AE Lock',
        3: 'AE Lock + Exposure Comp.',
        4: 'No AE'
    }),
    34: ('ImageStabilization', {
        0: 'Off',
        1: 'On',
        2: 'Shoot Only',
        3: 'Panning',
        4: 'Dynamic',
        256: 'Off',
        257: 'On',
        258: 'Shoot Only',
        259: 'Panning',
        260: 'Dynamic'
    }),
    39: ('SpotMeteringMode', {
        0: 'Center',
        1: 'AF Point'
    }),
    41: ('ManualFlashOutput', {
        0x0: 'n/a',
        0x500: 'Full',
        0x502: 'Medium',
        0x504: 'Low',
        0x7FFF: 'n/a'
    }),
}

# 0x0002
FOCAL_LENGTH = {
    1: ('FocalType', {
        1: 'Fixed',
        2: 'Zoom',
    }),
    2: ('FocalLength', ),
}

# 0x0004
SHOT_INFO = {
    7: ('WhiteBalance', {
        0: 'Auto',
        1: 'Sunny',
        2: 'Cloudy',
        3: 'Tungsten',
        4: 'Fluorescent',
        5: 'Flash',
        6: 'Custom'
    }),
    8: ('SlowShutter', {
        -1: 'n/a',
        0: 'Off',
        1: 'Night Scene',
        2: 'On',
        3: 'None'
    }),
    9: ('SequenceNumber', ),
    14: ('AFPointUsed', ),
    15: ('FlashBias', {
        0xFFC0: '-2 EV',
        0xFFCC: '-1.67 EV',
        0xFFD0: '-1.50 EV',
        0xFFD4: '-1.33 EV',
        0xFFE0: '-1 EV',
        0xFFEC: '-0.67 EV',
        0xFFF0: '-0.50 EV',
        0xFFF4: '-0.33 EV',
        0x0000: '0 EV',
        0x000C: '0.33 EV',
        0x0010: '0.50 EV',
        0x0014: '0.67 EV',
        0x0020: '1 EV',
        0x002C: '1.33 EV',
        0x0030: '1.50 EV',
        0x0034: '1.67 EV',
        0x0040: '2 EV'
    }),
    19: ('SubjectDistance', ),
}

# 0x0026
AF_INFO_2 = {
    2: ('AFAreaMode', {
        0: 'Off (Manual Focus)',
        2: 'Single-point AF',
        4: 'Multi-point AF or AI AF',
        5: 'Face Detect AF',
        6: 'Face + Tracking',
        7: 'Zone AF',
        8: 'AF Point Expansion',
        9: 'Spot AF',
        11: 'Flexizone Multi',
        13: 'Flexizone Single',
    }),
    3: ('NumAFPoints', ),
    4: ('ValidAFPoints', ),
    5: ('CanonImageWidth', ),
}

# 0x0093
FILE_INFO = {
    1: ('FileNumber', ),
    3: ('BracketMode', {
        0: 'Off',
        1: 'AEB',
        2: 'FEB',
        3: 'ISO',
        4: 'WB',
    }),
    4: ('BracketValue', ),
    5: ('BracketShotNumber', ),
    6: ('RawJpgQuality', {
        0xFFFF: 'n/a',
        1: 'Economy',
        2: 'Normal',
        3: 'Fine',
        4: 'RAW',
        5: 'Superfine',
        130: 'Normal Movie'
    }),
    7: ('RawJpgSize', {
        0: 'Large',
        1: 'Medium',
        2: 'Small',
        5: 'Medium 1',
        6: 'Medium 2',
        7: 'Medium 3',
        8: 'Postcard',
        9: 'Widescreen',
        10: 'Medium Widescreen',
        14: 'Small 1',
        15: 'Small 2',
        16: 'Small 3',
        128: '640x480 Movie',
        129: 'Medium Movie',
        130: 'Small Movie',
        137: '1280x720 Movie',
        142: '1920x1080 Movie',
    }),
    8: ('LongExposureNoiseReduction2', {
        0: 'Off',
        1: 'On (1D)',
        2: 'On',
        3: 'Auto'
    }),
    9: ('WBBracketMode', {
        0: 'Off',
        1: 'On (shift AB)',
        2: 'On (shift GM)'
    }),
    12: ('WBBracketValueAB', ),
    13: ('WBBracketValueGM', ),
    14: ('FilterEffect', {
        0: 'None',
        1: 'Yellow',
        2: 'Orange',
        3: 'Red',
        4: 'Green'
    }),
    15: ('ToningEffect', {
        0: 'None',
        1: 'Sepia',
        2: 'Blue',
        3: 'Purple',
        4: 'Green',
    }),
    16: ('MacroMagnification', ),
    19: ('LiveViewShooting', {
        0: 'Off',
        1: 'On'
    }),
    25: ('FlashExposureLock', {
        0: 'Off',
        1: 'On'
    })
}


def add_one(value):
    return value + 1


def subtract_one(value):
    return value - 1


def convert_temp(value):
    return '%d C' % (value - 128)

# CameraInfo data structures have variable sized members. Each entry here is:
# byte offset: (item name, data item type, decoding map).
# Note that the data item type is fed directly to struct.unpack at the
# specified offset.
CAMERA_INFO_TAG_NAME = 'MakerNote Tag 0x000D'

CAMERA_INFO_5D = {
    23: ('CameraTemperature', '<B', convert_temp),
    204: ('DirectoryIndex', '<L', subtract_one),
    208: ('FileIndex', '<H', add_one),
}

CAMERA_INFO_5DMKII = {
    25: ('CameraTemperature', '<B', convert_temp),
    443: ('FileIndex', '<L', add_one),
    455: ('DirectoryIndex', '<L', subtract_one),
}

CAMERA_INFO_5DMKIII = {
    27: ('CameraTemperature', '<B', convert_temp),
    652: ('FileIndex', '<L', add_one),
    656: ('FileIndex2', '<L', add_one),
    664: ('DirectoryIndex', '<L', subtract_one),
    668: ('DirectoryIndex2', '<L', subtract_one),
}

CAMERA_INFO_600D = {
    25: ('CameraTemperature', '<B', convert_temp),
    475: ('FileIndex', '<L', add_one),
    487: ('DirectoryIndex', '<L', subtract_one),
}

# A map of regular expressions on 'Image Model' to the CameraInfo spec
CAMERA_INFO_MODEL_MAP = {
    r'EOS 5D$': CAMERA_INFO_5D,
    r'EOS 5D Mark II$': CAMERA_INFO_5DMKII,
    r'EOS 5D Mark III$': CAMERA_INFO_5DMKIII,
    r'\b(600D|REBEL T3i|Kiss X5)\b': CAMERA_INFO_600D,
}
