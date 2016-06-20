"""Auto-generated file, do not edit by hand. JE metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_JE = PhoneMetadata(id='JE', country_code=44, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[135789]\\d{6,9}', possible_number_pattern='\\d{6,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='1534\\d{6}', possible_number_pattern='\\d{6,10}', example_number='1534456789'),
    mobile=PhoneNumberDesc(national_number_pattern='7(?:509|7(?:00|97)|829|937)\\d{6}', possible_number_pattern='\\d{10}', example_number='7797123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='80(?:07(?:35|81)|8901)\\d{4}', possible_number_pattern='\\d{10}', example_number='8007354567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='(?:871206|90(?:066[59]|1810|71(?:07|55)))\\d{4}', possible_number_pattern='\\d{10}', example_number='9018105678'),
    shared_cost=PhoneNumberDesc(national_number_pattern='8(?:4(?:4(?:4(?:05|42|69)|703)|5(?:041|800))|70002)\\d{4}', possible_number_pattern='\\d{10}', example_number='8447034567'),
    personal_number=PhoneNumberDesc(national_number_pattern='701511\\d{4}', possible_number_pattern='\\d{10}', example_number='7015115678'),
    voip=PhoneNumberDesc(national_number_pattern='56\\d{8}', possible_number_pattern='\\d{10}', example_number='5612345678'),
    pager=PhoneNumberDesc(national_number_pattern='76(?:0[012]|2[356]|4[0134]|5[49]|6[0-369]|77|81|9[39])\\d{6}', possible_number_pattern='\\d{10}', example_number='7640123456'),
    uan=PhoneNumberDesc(national_number_pattern='3(?:0(?:07(?:35|81)|8901)|3\\d{4}|4(?:4(?:4(?:05|42|69)|703)|5(?:041|800))|7(?:0002|1206))\\d{4}|55\\d{8}', possible_number_pattern='\\d{10}', example_number='5512345678'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    preferred_extn_prefix=' x',
    national_prefix_for_parsing='0')
