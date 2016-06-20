"""Auto-generated file, do not edit by hand. IS metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_IS = PhoneMetadata(id='IS', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='1717', possible_number_pattern='\\d{4}', example_number='1717'),
    premium_rate=PhoneNumberDesc(national_number_pattern='1848', possible_number_pattern='\\d{4}', example_number='1848'),
    emergency=PhoneNumberDesc(national_number_pattern='112', possible_number_pattern='\\d{3,6}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:1(?:[28]|6(?:1(?:23|16)))|4(?:00|1[145]|4[0146])|55|7(?:00|17|7[07-9])|8(?:0[08]|1[016-9]|20|48|8[018])|900)', possible_number_pattern='\\d{3,6}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='1441', possible_number_pattern='\\d{4}', example_number='1441'),
    short_data=True)
