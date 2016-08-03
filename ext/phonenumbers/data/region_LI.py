"""Auto-generated file, do not edit by hand. LI metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_LI = PhoneMetadata(id='LI', country_code=423, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='6\\d{8}|[23789]\\d{6}', possible_number_pattern='\\d{7,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:2(?:01|1[27]|3\\d|6[02-578]|96)|3(?:7[0135-7]|8[048]|9[0269]))\\d{4}', possible_number_pattern='\\d{7}', example_number='2345678'),
    mobile=PhoneNumberDesc(national_number_pattern='6(?:51[01]|6(?:0[0-6]|2[016-9]|39))\\d{5}|7(?:[37-9]\\d|42|56)\\d{4}', possible_number_pattern='\\d{7,9}', example_number='660234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='80(?:02[28]|9\\d{2})\\d{2}', possible_number_pattern='\\d{7}', example_number='8002222'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90(?:02[258]|1(?:23|3[14])|66[136])\\d{2}', possible_number_pattern='\\d{7}', example_number='9002222'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='870(?:28|87)\\d{2}', possible_number_pattern='\\d{7}', example_number='8702812'),
    voicemail=PhoneNumberDesc(national_number_pattern='697(?:42|56|[7-9]\\d)\\d{4}', possible_number_pattern='\\d{9}', example_number='697861234'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{2})(\\d{2})', format='\\1 \\2 \\3', leading_digits_pattern=['[23789]']),
        NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['6[56]']),
        NumberFormat(pattern='(69)(7\\d{2})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['697'])])
