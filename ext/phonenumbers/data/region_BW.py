"""Auto-generated file, do not edit by hand. BW metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_BW = PhoneMetadata(id='BW', country_code=267, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-79]\\d{6,7}', possible_number_pattern='\\d{7,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:2(?:4[0-48]|6[0-24]|9[0578])|3(?:1[0235-9]|55|[69]\\d|7[01])|4(?:6[03]|7[1267]|9[0-5])|5(?:3[0389]|4[0489]|7[1-47]|88|9[0-49])|6(?:2[1-35]|5[149]|8[067]))\\d{4}', possible_number_pattern='\\d{7}', example_number='2401234'),
    mobile=PhoneNumberDesc(national_number_pattern='7(?:[1-6]\\d|7[014-8])\\d{5}', possible_number_pattern='\\d{8}', example_number='71123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90\\d{5}', possible_number_pattern='\\d{7}', example_number='9012345'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='79[12][01]\\d{4}', possible_number_pattern='\\d{8}', example_number='79101234'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[2-6]']),
        NumberFormat(pattern='(7\\d)(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['7']),
        NumberFormat(pattern='(90)(\\d{5})', format='\\1 \\2', leading_digits_pattern=['9'])])
