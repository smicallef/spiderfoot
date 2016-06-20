"""Auto-generated file, do not edit by hand. CY metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_CY = PhoneMetadata(id='CY', country_code=357, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[257-9]\\d{7}', possible_number_pattern='\\d{8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2[2-6]\\d{6}', possible_number_pattern='\\d{8}', example_number='22345678'),
    mobile=PhoneNumberDesc(national_number_pattern='9[4-79]\\d{6}', possible_number_pattern='\\d{8}', example_number='96123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{5}', possible_number_pattern='\\d{8}', example_number='80001234'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90[09]\\d{5}', possible_number_pattern='\\d{8}', example_number='90012345'),
    shared_cost=PhoneNumberDesc(national_number_pattern='80[1-9]\\d{5}', possible_number_pattern='\\d{8}', example_number='80112345'),
    personal_number=PhoneNumberDesc(national_number_pattern='700\\d{5}', possible_number_pattern='\\d{8}', example_number='70012345'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='(?:50|77)\\d{6}', possible_number_pattern='\\d{8}', example_number='77123456'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{6})', format='\\1 \\2')],
    mobile_number_portable_region=True)
