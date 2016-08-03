"""Auto-generated file, do not edit by hand. VA metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_VA = PhoneMetadata(id='VA', country_code=39, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='(?:0(?:878\\d{5}|6698\\d{5})|[1589]\\d{5,10}|3(?:[12457-9]\\d{8}|[36]\\d{7,9}))', possible_number_pattern='\\d{6,11}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='06698\\d{5}', possible_number_pattern='\\d{10}', example_number='0669812345'),
    mobile=PhoneNumberDesc(national_number_pattern='3(?:[12457-9]\\d{8}|6\\d{7,8}|3\\d{7,9})', possible_number_pattern='\\d{9,11}', example_number='3123456789'),
    toll_free=PhoneNumberDesc(national_number_pattern='80(?:0\\d{6}|3\\d{3})', possible_number_pattern='\\d{6,9}', example_number='800123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='0878\\d{5}|1(?:44|6[346])\\d{6}|89(?:2\\d{3}|4(?:[0-4]\\d{2}|[5-9]\\d{4})|5(?:[0-4]\\d{2}|[5-9]\\d{6})|9\\d{6})', possible_number_pattern='\\d{6,10}', example_number='899123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='84(?:[08]\\d{6}|[17]\\d{3})', possible_number_pattern='\\d{6,9}', example_number='848123456'),
    personal_number=PhoneNumberDesc(national_number_pattern='1(?:78\\d|99)\\d{6}', possible_number_pattern='\\d{9,10}', example_number='1781234567'),
    voip=PhoneNumberDesc(national_number_pattern='55\\d{8}', possible_number_pattern='\\d{10}', example_number='5512345678'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='848\\d{6}', possible_number_pattern='\\d{9}', example_number='848123456'),
    leading_zero_possible=True,
    mobile_number_portable_region=True)
