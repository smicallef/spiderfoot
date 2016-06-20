"""Auto-generated file, do not edit by hand. GW metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_GW = PhoneMetadata(id='GW', country_code=245, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='(?:4(?:0\\d{5}|4\\d{7})|9\\d{8})', possible_number_pattern='\\d{7,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='443(?:2[0125]|3[1245]|4[12]|5[1-4]|70|9[1-467])\\d{4}', possible_number_pattern='\\d{7,9}', example_number='443201234'),
    mobile=PhoneNumberDesc(national_number_pattern='9(?:55\\d|6(?:6\\d|9[012])|77\\d)\\d{5}', possible_number_pattern='\\d{7,9}', example_number='955012345'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='40\\d{5}', possible_number_pattern='\\d{7,9}', example_number='4012345'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'))
