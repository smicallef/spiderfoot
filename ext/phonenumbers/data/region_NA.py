"""Auto-generated file, do not edit by hand. NA metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_NA = PhoneMetadata(id='NA', country_code=264, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[68]\\d{7,8}', possible_number_pattern='\\d{8,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='6(?:1(?:17|2(?:[0189]\\d|[2-6]|7\\d?)|3(?:[01378]|2\\d)|4(?:[024]|10?|3[15]?)|69|7[014])|2(?:17|5(?:[0-36-8]|4\\d?)|69|70)|3(?:17|2(?:[0237]\\d?|[14-689])|34|6[289]|7[01]|81)|4(?:17|2(?:[012]|7?)|4(?:[06]|1\\d?)|5(?:[01357]|[25]\\d?)|69|7[01])|5(?:17|2(?:[0459]|[23678]\\d?)|69|7[01])|6(?:17|2(?:5|6\\d?)|38|42|69|7[01])|7(?:17|2(?:[569]|[234]\\d?)|3(?:0\\d?|[13])|69|7[01]))\\d{4}', possible_number_pattern='\\d{8,9}', example_number='61221234'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:60|8[125])\\d{7}', possible_number_pattern='\\d{9}', example_number='811234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='8701\\d{5}', possible_number_pattern='\\d{9}', example_number='870123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='8(?:3\\d{2}|86)\\d{5}', possible_number_pattern='\\d{8,9}', example_number='88612345'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(8\\d)(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['8[1235]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(6\\d)(\\d{3})(\\d{3,4})', format='\\1 \\2 \\3', leading_digits_pattern=['6'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(88)(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['88'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(870)(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['870'], national_prefix_formatting_rule='0\\1')])
