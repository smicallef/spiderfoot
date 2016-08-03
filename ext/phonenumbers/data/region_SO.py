"""Auto-generated file, do not edit by hand. SO metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SO = PhoneMetadata(id='SO', country_code=252, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-79]\\d{6,8}', possible_number_pattern='\\d{7,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:1\\d|2[0-79]|3[0-46-8]|4[0-7]|59)\\d{5}', possible_number_pattern='\\d{7}', example_number='4012345'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:15\\d|2(?:4\\d|8)|6[1-35-9]?\\d{2}|7(?:[1-8]\\d|99?\\d)|9(?:0[67]|[2-9])\\d)\\d{5}', possible_number_pattern='\\d{7,9}', example_number='71123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d)(\\d{6})', format='\\1 \\2', leading_digits_pattern=['2[0-79]|[13-5]']),
        NumberFormat(pattern='(\\d)(\\d{7})', format='\\1 \\2', leading_digits_pattern=['24|[67]']),
        NumberFormat(pattern='(\\d{2})(\\d{5,7})', format='\\1 \\2', leading_digits_pattern=['15|28|6[1-35-9]|799|9[2-9]']),
        NumberFormat(pattern='(90\\d)(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['90'])])
