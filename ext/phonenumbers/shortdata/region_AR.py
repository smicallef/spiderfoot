"""Auto-generated file, do not edit by hand. AR metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_AR = PhoneMetadata(id='AR', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[01389]\\d{1,4}', possible_number_pattern='\\d{2,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='[09]\\d{2}|1(?:[02-9]\\d?|1[0-24-9]?)', possible_number_pattern='\\d{2,3}', example_number='111'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='10[017]|911', possible_number_pattern='\\d{3}', example_number='101'),
    short_code=PhoneNumberDesc(national_number_pattern='000|1(?:0[0-35-7]|1[02-5]|2[15]|9)|3372|89338|911', possible_number_pattern='\\d{2,5}', example_number='121'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='89338|911', possible_number_pattern='\\d{3,5}'),
    short_data=True)
