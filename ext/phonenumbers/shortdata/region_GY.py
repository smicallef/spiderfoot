"""Auto-generated file, do not edit by hand. GY metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_GY = PhoneMetadata(id='GY', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[019]\\d{2,3}', possible_number_pattern='\\d{3,4}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='91[123]', possible_number_pattern='\\d{3}', example_number='911'),
    short_code=PhoneNumberDesc(national_number_pattern='0(?:02|171|444|7(?:[67]7|9)|801|9(?:0[78]|[2-47]))|1(?:443|5[568])|91[123]', possible_number_pattern='\\d{3,4}', example_number='0801'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='1443', possible_number_pattern='\\d{4}'),
    short_data=True)
