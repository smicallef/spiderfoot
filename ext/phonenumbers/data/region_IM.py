"""Auto-generated file, do not edit by hand. IM metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_IM = PhoneMetadata(id='IM', country_code=44, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[135789]\\d{6,9}', possible_number_pattern='\\d{6,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='1624\\d{6}', possible_number_pattern='\\d{6,10}', example_number='1624456789'),
    mobile=PhoneNumberDesc(national_number_pattern='7[569]24\\d{6}', possible_number_pattern='\\d{10}', example_number='7924123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='808162\\d{4}', possible_number_pattern='\\d{10}', example_number='8081624567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='(?:872299|90[0167]624)\\d{4}', possible_number_pattern='\\d{10}', example_number='9016247890'),
    shared_cost=PhoneNumberDesc(national_number_pattern='8(?:4(?:40[49]06|5624\\d)|70624\\d)\\d{3}', possible_number_pattern='\\d{10}', example_number='8456247890'),
    personal_number=PhoneNumberDesc(national_number_pattern='70\\d{8}', possible_number_pattern='\\d{10}', example_number='7012345678'),
    voip=PhoneNumberDesc(national_number_pattern='56\\d{8}', possible_number_pattern='\\d{10}', example_number='5612345678'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='3(?:08162\\d|3\\d{5}|4(?:40[49]06|5624\\d)|7(?:0624\\d|2299\\d))\\d{3}|55\\d{8}', possible_number_pattern='\\d{10}', example_number='5512345678'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    preferred_extn_prefix=' x',
    national_prefix_for_parsing='0')
