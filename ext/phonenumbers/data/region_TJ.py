"""Auto-generated file, do not edit by hand. TJ metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_TJ = PhoneMetadata(id='TJ', country_code=992, international_prefix='810',
    general_desc=PhoneNumberDesc(national_number_pattern='[3-589]\\d{8}', possible_number_pattern='\\d{3,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:3(?:1[3-5]|2[245]|3[12]|4[24-7]|5[25]|72)|4(?:46|74|87))\\d{6}', possible_number_pattern='\\d{3,9}', example_number='372123456'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:41[18]|50[125]|88\\d|9[0-35-9]\\d)\\d{6}', possible_number_pattern='\\d{9}', example_number='917123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    preferred_international_prefix='8~10',
    national_prefix='8',
    national_prefix_for_parsing='8',
    number_format=[NumberFormat(pattern='([349]\\d{2})(\\d{2})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['[34]7|91[78]'], national_prefix_formatting_rule='(8) \\1', national_prefix_optional_when_formatting=True),
        NumberFormat(pattern='([4589]\\d)(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['4[148]|[58]|9(?:1[59]|[0235-9])'], national_prefix_formatting_rule='(8) \\1', national_prefix_optional_when_formatting=True),
        NumberFormat(pattern='(331700)(\\d)(\\d{2})', format='\\1 \\2 \\3', leading_digits_pattern=['331', '3317', '33170', '331700'], national_prefix_formatting_rule='(8) \\1', national_prefix_optional_when_formatting=True),
        NumberFormat(pattern='(\\d{4})(\\d)(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['3[1-5]', '3(?:[1245]|3(?:[02-9]|1[0-589]))'], national_prefix_formatting_rule='(8) \\1', national_prefix_optional_when_formatting=True)])
