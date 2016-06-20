"""Auto-generated file, do not edit by hand. AW metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_AW = PhoneMetadata(id='AW', country_code=297, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[25-9]\\d{6}', possible_number_pattern='\\d{7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='5(?:2\\d|8[1-9])\\d{4}', possible_number_pattern='\\d{7}', example_number='5212345'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:5(?:6\\d|9[2-478])|6(?:[039]0|22|4[01]|6[0-2])|7[34]\\d|9(?:6[45]|9[4-8]))\\d{4}', possible_number_pattern='\\d{7}', example_number='5601234'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{4}', possible_number_pattern='\\d{7}', example_number='8001234'),
    premium_rate=PhoneNumberDesc(national_number_pattern='900\\d{4}', possible_number_pattern='\\d{7}', example_number='9001234'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='28\\d{5}|501\\d{4}', possible_number_pattern='\\d{7}', example_number='5011234'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1 \\2')])
