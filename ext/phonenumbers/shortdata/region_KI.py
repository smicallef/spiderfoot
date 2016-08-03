"""Auto-generated file, do not edit by hand. KI metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_KI = PhoneMetadata(id='KI', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[179]\\d{2,3}', possible_number_pattern='\\d{3,4}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='99[2349]', possible_number_pattern='\\d{3}', example_number='999'),
    short_code=PhoneNumberDesc(national_number_pattern='10(?:[0-8]|5[01259])|777|99[2349]', possible_number_pattern='\\d{3,4}', example_number='100'),
    standard_rate=PhoneNumberDesc(national_number_pattern='103', possible_number_pattern='\\d{3}', example_number='103'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
