"""Auto-generated file, do not edit by hand. RW metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_RW = PhoneMetadata(id='RW', country_code=250, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[027-9]\\d{7,8}', possible_number_pattern='\\d{8,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2[258]\\d{7}|06\\d{6}', possible_number_pattern='\\d{8,9}', example_number='250123456'),
    mobile=PhoneNumberDesc(national_number_pattern='7[238]\\d{7}', possible_number_pattern='\\d{9}', example_number='720123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{6}', possible_number_pattern='\\d{9}', example_number='800123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='900\\d{6}', possible_number_pattern='\\d{9}', example_number='900123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(2\\d{2})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['2'], national_prefix_formatting_rule='\\1'),
        NumberFormat(pattern='([7-9]\\d{2})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['[7-9]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(0\\d)(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['0'])],
    leading_zero_possible=True)
