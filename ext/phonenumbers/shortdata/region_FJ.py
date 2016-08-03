"""Auto-generated file, do not edit by hand. FJ metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_FJ = PhoneMetadata(id='FJ', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[0-579]\\d{1,4}', possible_number_pattern='\\d{2,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='91[17]', possible_number_pattern='\\d{3}', example_number='911'),
    short_code=PhoneNumberDesc(national_number_pattern='0(?:1[34]|8[1-4])|1(?:0[1-3]|[25]9)|2[289]|30|4(?:0404|4)|54|75|91[137]', possible_number_pattern='\\d{2,5}', example_number='22'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
