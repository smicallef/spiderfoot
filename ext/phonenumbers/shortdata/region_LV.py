"""Auto-generated file, do not edit by hand. LV metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_LV = PhoneMetadata(id='LV', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='0\\d|1\\d{2,6}|8\\d{3,4}', possible_number_pattern='\\d{2,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='116(?:000|111)', possible_number_pattern='\\d{6}', example_number='116000'),
    premium_rate=PhoneNumberDesc(national_number_pattern='1180|8(?:2\\d{3}|[89]\\d{2})', possible_number_pattern='\\d{4,5}'),
    emergency=PhoneNumberDesc(national_number_pattern='0[123]|11[023]', possible_number_pattern='\\d{2,3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='0[1-4]|1(?:1(?:[02-4]|6(?:000|111)|8[0189])|55|655|77)|821[57]4', possible_number_pattern='\\d{2,6}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='1181', possible_number_pattern='\\d{4}', example_number='1181'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='16\\d{2}', possible_number_pattern='\\d{4}', example_number='1655'),
    short_data=True)
