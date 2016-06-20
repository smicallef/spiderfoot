"""Auto-generated file, do not edit by hand. PA metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_PA = PhoneMetadata(id='PA', country_code=507, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-9]\\d{6,7}', possible_number_pattern='\\d{7,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:1(?:0[0-8]|1[49]|2[37]|3[0137]|4[147]|5[05]|6[58]|7[0167]|8[58]|9[139])|2(?:[0235679]\\d|1[0-7]|4[04-9]|8[028])|3(?:[09]\\d|1[014-7]|2[0-3]|3[03]|4[03-57]|55|6[068]|7[06-8]|8[06-9])|4(?:3[013-69]|4\\d|7[0-589])|5(?:[01]\\d|2[0-7]|[56]0|79)|7(?:0[09]|2[0-267]|3[06]|[469]0|5[06-9]|7[0-24-79]|8[7-9])|8(?:09|[34]\\d|5[0134]|8[02])|9(?:0[6-9]|1[016-8]|2[036-8]|3[3679]|40|5[0489]|6[06-9]|7[046-9]|8[36-8]|9[1-9]))\\d{4}', possible_number_pattern='\\d{7}', example_number='2001234'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:1[16]1|21[89]|8(?:1[01]|7[23]))\\d{4}|6(?:[024-9]\\d|1[0-5]|3[0-24-9])\\d{5}', possible_number_pattern='\\d{7,8}', example_number='60012345'),
    toll_free=PhoneNumberDesc(national_number_pattern='80[09]\\d{4}', possible_number_pattern='\\d{7}', example_number='8001234'),
    premium_rate=PhoneNumberDesc(national_number_pattern='(?:779|8(?:55|60|7[78])|9(?:00|81))\\d{4}', possible_number_pattern='\\d{7}', example_number='8601234'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1-\\2', leading_digits_pattern=['[1-57-9]']),
        NumberFormat(pattern='(\\d{4})(\\d{4})', format='\\1-\\2', leading_digits_pattern=['6'])],
    mobile_number_portable_region=True)
