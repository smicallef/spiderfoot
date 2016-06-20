"""Auto-generated file, do not edit by hand. KY metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_KY = PhoneMetadata(id='KY', country_code=1, international_prefix='011',
    general_desc=PhoneNumberDesc(national_number_pattern='[3589]\\d{9}', possible_number_pattern='\\d{7}(?:\\d{3})?'),
    fixed_line=PhoneNumberDesc(national_number_pattern='345(?:2(?:22|44)|444|6(?:23|38|40)|7(?:4[35-79]|6[6-9]|77)|8(?:00|1[45]|25|[48]8)|9(?:14|4[035-9]))\\d{4}', possible_number_pattern='\\d{7}(?:\\d{3})?', example_number='3452221234'),
    mobile=PhoneNumberDesc(national_number_pattern='345(?:32[1-9]|5(?:1[67]|2[5-7]|4[6-8]|76)|9(?:1[67]|2[2-9]|3[689]))\\d{4}', possible_number_pattern='\\d{10}', example_number='3453231234'),
    toll_free=PhoneNumberDesc(national_number_pattern='8(?:00|44|55|66|77|88)[2-9]\\d{6}', possible_number_pattern='\\d{10}', example_number='8002345678'),
    premium_rate=PhoneNumberDesc(national_number_pattern='900[2-9]\\d{6}|345976\\d{4}', possible_number_pattern='\\d{10}', example_number='9002345678'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='5(?:00|33|44|66|77|88)[2-9]\\d{6}', possible_number_pattern='\\d{10}', example_number='5002345678'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='345849\\d{4}', possible_number_pattern='\\d{10}', example_number='3458491234'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='1',
    national_prefix_for_parsing='1',
    leading_digits='345')
