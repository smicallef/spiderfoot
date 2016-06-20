"""Auto-generated file, do not edit by hand. PG metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_PG = PhoneMetadata(id='PG', country_code=675, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-9]\\d{6,7}', possible_number_pattern='\\d{7,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:3[0-2]\\d|4[25]\\d|5[34]\\d|64[1-9]|77(?:[0-24]\\d|30)|85[02-46-9]|9[78]\\d)\\d{4}', possible_number_pattern='\\d{7}', example_number='3123456'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:20150|68\\d{2}|7(?:[0-689]\\d|75)\\d{2})\\d{3}', possible_number_pattern='\\d{7,8}', example_number='6812345'),
    toll_free=PhoneNumberDesc(national_number_pattern='180\\d{4}', possible_number_pattern='\\d{7}', example_number='1801234'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='275\\d{4}', possible_number_pattern='\\d{7}', example_number='2751234'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[13-689]|27']),
        NumberFormat(pattern='(\\d{4})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['20|7'])])
