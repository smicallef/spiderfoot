"""Auto-generated file, do not edit by hand. ES metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_ES = PhoneMetadata(id='ES', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[0-379]\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='0(?:16|67|88)|1(?:006|16\\d{3}|[3-7]\\d{2})|20\\d{4}', possible_number_pattern='\\d{3,6}', example_number='116111'),
    premium_rate=PhoneNumberDesc(national_number_pattern='1(?:18\\d{2}|2\\d{1,4})|2(?:2\\d{1,4}|[3-9]\\d{3,4})|[379]\\d{4,5}', possible_number_pattern='\\d{3,6}', example_number='23456'),
    emergency=PhoneNumberDesc(national_number_pattern='08[58]|112', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='0(?:1[0-26]|6[0-27]|8[058]|9[12])|1(?:0[03-57]\\d{1,3}|1(?:2|6(?:000|111)|8\\d{2})|2\\d{1,4}|3(?:[34]|\\d{2})|7(?:7|\\d{2})|[4-689]\\d{2})|2(?:[01]\\d{4}|2\\d{1,4}|[357]\\d{3}|80\\d{2})|3[357]\\d{3}|[79]9[57]\\d{3}', possible_number_pattern='\\d{3,6}', example_number='010'),
    standard_rate=PhoneNumberDesc(national_number_pattern='0(?:[16][0-2]|80|9[12])|21\\d{4}', possible_number_pattern='\\d{3,6}', example_number='211234'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='1(?:2\\d{1,4}|3[34]|77)|22\\d{1,4}', possible_number_pattern='\\d{3,6}', example_number='123'),
    short_data=True)
