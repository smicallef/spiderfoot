"""Auto-generated file, do not edit by hand. 882 metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_882 = PhoneMetadata(id='001', country_code=882, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[13]\\d{6,11}', possible_number_pattern='\\d{7,12}', example_number='3451234567'),
    fixed_line=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA', example_number='3451234567'),
    mobile=PhoneNumberDesc(national_number_pattern='3(?:2\\d{3}|37\\d{2}|4(?:2|7\\d{3}))\\d{4}', possible_number_pattern='\\d{7,10}', example_number='3451234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='1(?:3(?:0[0347]|[13][0139]|2[035]|4[013568]|6[0459]|7[06]|8[15678]|9[0689])\\d{4}|6\\d{5,10})|345\\d{7}', possible_number_pattern='\\d{7,12}', example_number='3451234567'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='348[57]\\d{7}', possible_number_pattern='\\d{11}', example_number='3451234567'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{4})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['3[23]']),
        NumberFormat(pattern='(\\d{2})(\\d{5})', format='\\1 \\2', leading_digits_pattern=['16|342']),
        NumberFormat(pattern='(\\d{2})(\\d{4})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['34[57]']),
        NumberFormat(pattern='(\\d{3})(\\d{4})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['348']),
        NumberFormat(pattern='(\\d{2})(\\d{2})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['1']),
        NumberFormat(pattern='(\\d{2})(\\d{3,4})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['16']),
        NumberFormat(pattern='(\\d{2})(\\d{4,5})(\\d{5})', format='\\1 \\2 \\3', leading_digits_pattern=['16'])])
