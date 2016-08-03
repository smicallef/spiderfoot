"""Auto-generated file, do not edit by hand. LV metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_LV = PhoneMetadata(id='LV', country_code=371, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2689]\\d{7}', possible_number_pattern='\\d{8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='6[3-8]\\d{6}', possible_number_pattern='\\d{8}', example_number='63123456'),
    mobile=PhoneNumberDesc(national_number_pattern='2\\d{7}', possible_number_pattern='\\d{8}', example_number='21234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='80\\d{6}', possible_number_pattern='\\d{8}', example_number='80123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90\\d{6}', possible_number_pattern='\\d{8}', example_number='90123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='81\\d{6}', possible_number_pattern='\\d{8}', example_number='81123456'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='([2689]\\d)(\\d{3})(\\d{3})', format='\\1 \\2 \\3')],
    mobile_number_portable_region=True)
