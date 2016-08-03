"""Auto-generated file, do not edit by hand. SA metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SA = PhoneMetadata(id='SA', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[19]\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='116111|937|998', possible_number_pattern='\\d{3,6}', example_number='116111'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='112|9(?:11|9[79])', possible_number_pattern='\\d{3}', example_number='999'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:1(?:00|2|6111)|410|9(?:00|1[89]|9(?:099|22|91)))|9(?:0[24-79]|11|3[379]|40|66|8[5-9]|9[02-9])', possible_number_pattern='\\d{3,6}', example_number='937'),
    standard_rate=PhoneNumberDesc(national_number_pattern='1410', possible_number_pattern='\\d{4}', example_number='1410'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='1(?:100|410)|90[24679]', possible_number_pattern='\\d{3,4}', example_number='902'),
    short_data=True)
