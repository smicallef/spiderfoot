"""Auto-generated file, do not edit by hand. SH metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SH = PhoneMetadata(id='SH', country_code=290, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[256]\\d{4}', possible_number_pattern='\\d{4,5}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2(?:[0-57-9]\\d|6[4-9])\\d{2}', possible_number_pattern='\\d{5}', example_number='22158'),
    mobile=PhoneNumberDesc(national_number_pattern='[56]\\d{4}', possible_number_pattern='\\d{5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='262\\d{2}', possible_number_pattern='\\d{5}'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    main_country_for_code=True)
