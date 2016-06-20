"""Auto-generated file, do not edit by hand. GG metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_GG = PhoneMetadata(id='GG', country_code=44, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[135789]\\d{6,9}', possible_number_pattern='\\d{6,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='1481\\d{6}', possible_number_pattern='\\d{6,10}', example_number='1481456789'),
    mobile=PhoneNumberDesc(national_number_pattern='7(?:781|839|911)\\d{6}', possible_number_pattern='\\d{10}', example_number='7781123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='80(?:0(?:1111|\\d{6,7})|8\\d{7})|500\\d{6}', possible_number_pattern='\\d{7}(?:\\d{2,3})?', example_number='8001234567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='(?:87[123]|9(?:[01]\\d|8[0-3]))\\d{7}', possible_number_pattern='\\d{10}', example_number='9012345678'),
    shared_cost=PhoneNumberDesc(national_number_pattern='8(?:4(?:5464\\d|[2-5]\\d{7})|70\\d{7})', possible_number_pattern='\\d{7}(?:\\d{3})?', example_number='8431234567'),
    personal_number=PhoneNumberDesc(national_number_pattern='70\\d{8}', possible_number_pattern='\\d{10}', example_number='7012345678'),
    voip=PhoneNumberDesc(national_number_pattern='56\\d{8}', possible_number_pattern='\\d{10}', example_number='5612345678'),
    pager=PhoneNumberDesc(national_number_pattern='76(?:0[012]|2[356]|4[0134]|5[49]|6[0-369]|77|81|9[39])\\d{6}', possible_number_pattern='\\d{10}', example_number='7640123456'),
    uan=PhoneNumberDesc(national_number_pattern='(?:3[0347]|55)\\d{8}', possible_number_pattern='\\d{10}', example_number='5512345678'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    preferred_extn_prefix=' x',
    national_prefix_for_parsing='0')
