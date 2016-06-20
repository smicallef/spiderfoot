"""Auto-generated file, do not edit by hand. FR metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_FR = PhoneMetadata(id='FR', country_code=33, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-9]\\d{8}', possible_number_pattern='\\d{9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='[1-5]\\d{8}', possible_number_pattern='\\d{9}', example_number='123456789'),
    mobile=PhoneNumberDesc(national_number_pattern='6\\d{8}|7(?:00\\d{6}|[3-9]\\d{7})', possible_number_pattern='\\d{9}', example_number='612345678'),
    toll_free=PhoneNumberDesc(national_number_pattern='80[0-5]\\d{6}', possible_number_pattern='\\d{9}', example_number='801234567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='89[1-37-9]\\d{6}', possible_number_pattern='\\d{9}', example_number='891123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='8(?:1[019]|2[0156]|84|90)\\d{6}', possible_number_pattern='\\d{9}', example_number='810123456'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='9\\d{8}', possible_number_pattern='\\d{9}', example_number='912345678'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='80[6-9]\\d{6}', possible_number_pattern='\\d{9}', example_number='806123456'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='([1-79])(\\d{2})(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4 \\5', leading_digits_pattern=['[1-79]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(1\\d{2})(\\d{3})', format='\\1 \\2', leading_digits_pattern=['11'], national_prefix_formatting_rule='\\1'),
        NumberFormat(pattern='(8\\d{2})(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['8'], national_prefix_formatting_rule='0 \\1')],
    intl_number_format=[NumberFormat(pattern='([1-79])(\\d{2})(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4 \\5', leading_digits_pattern=['[1-79]']),
        NumberFormat(pattern='(8\\d{2})(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['8'])],
    mobile_number_portable_region=True)
