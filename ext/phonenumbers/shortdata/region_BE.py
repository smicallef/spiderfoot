"""Auto-generated file, do not edit by hand. BE metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_BE = PhoneMetadata(id='BE', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{2,5}|[2-9]\\d{3}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='1(?:0[25-8]|1(?:0|6\\d{3})|7(?:12|77)|813)|8\\d{3}', possible_number_pattern='\\d{3,6}', example_number='116000'),
    premium_rate=PhoneNumberDesc(national_number_pattern='1(?:2(?:12|34)|3(?:07|13)|414|\\d04)|[2-79]\\d{3}', possible_number_pattern='\\d{4}', example_number='7212'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:0[01]|12)', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:0[0-8]|1(?:[027]|6(?:000|117))|2(?:0[47]|12|3[0-24]|99)|3(?:0[47]|13|99)|4(?:0[47]|14|50|99)|7(?:00|1[27-9]|33|65|7[17]|89)|81[39])|[2-9]\\d{3}', possible_number_pattern='\\d{3,6}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
