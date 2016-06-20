"""Auto-generated file, do not edit by hand. TC metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_TC = PhoneMetadata(id='TC', country_code=1, international_prefix='011',
    general_desc=PhoneNumberDesc(national_number_pattern='[5689]\\d{9}', possible_number_pattern='\\d{7}(?:\\d{3})?'),
    fixed_line=PhoneNumberDesc(national_number_pattern='649(?:712|9(?:4\\d|50))\\d{4}', possible_number_pattern='\\d{7}(?:\\d{3})?', example_number='6497121234'),
    mobile=PhoneNumberDesc(national_number_pattern='649(?:2(?:3[129]|4[1-7])|3(?:3[1-389]|4[1-7])|4[34][1-3])\\d{4}', possible_number_pattern='\\d{10}', example_number='6492311234'),
    toll_free=PhoneNumberDesc(national_number_pattern='8(?:00|44|55|66|77|88)[2-9]\\d{6}', possible_number_pattern='\\d{10}', example_number='8002345678'),
    premium_rate=PhoneNumberDesc(national_number_pattern='900[2-9]\\d{6}', possible_number_pattern='\\d{10}', example_number='9002345678'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='5(?:00|33|44|66|77|88)[2-9]\\d{6}', possible_number_pattern='\\d{10}', example_number='5002345678'),
    voip=PhoneNumberDesc(national_number_pattern='64971[01]\\d{4}', possible_number_pattern='\\d{10}', example_number='6497101234'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='1',
    national_prefix_for_parsing='1',
    leading_digits='649')
