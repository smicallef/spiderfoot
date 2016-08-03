"""Auto-generated file, do not edit by hand. IS metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_IS = PhoneMetadata(id='IS', country_code=354, international_prefix='1(?:0(?:01|10|20)|100)|00',
    general_desc=PhoneNumberDesc(national_number_pattern='[4-9]\\d{6}|38\\d{7}', possible_number_pattern='\\d{7,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:4(?:1[0-24-6]|2[0-7]|[37][0-8]|4[0-245]|5[0-68]|6\\d|8[0-36-8])|5(?:05|[156]\\d|2[02578]|3[013-79]|4[03-7]|7[0-2578]|8[0-35-9]|9[013-689])|87[23])\\d{4}', possible_number_pattern='\\d{7}', example_number='4101234'),
    mobile=PhoneNumberDesc(national_number_pattern='38[589]\\d{6}|(?:6(?:1[1-8]|2[056]|3[089]|4[0167]|5[0159]|[67][0-69]|9\\d)|7(?:5[057]|6[0-2]|[78]\\d)|8(?:2[0-59]|3[0-4]|[469]\\d|5[1-9]))\\d{4}', possible_number_pattern='\\d{7,9}', example_number='6111234'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{4}', possible_number_pattern='\\d{7}', example_number='8001234'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90\\d{5}', possible_number_pattern='\\d{7}', example_number='9011234'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='49\\d{5}', possible_number_pattern='\\d{7}', example_number='4921234'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='809\\d{4}', possible_number_pattern='\\d{7}', example_number='8091234'),
    voicemail=PhoneNumberDesc(national_number_pattern='(?:6(?:2[1-478]|49|8\\d)|8(?:7[0189]|80)|95[48])\\d{4}', possible_number_pattern='\\d{7}', example_number='6211234'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    preferred_international_prefix='00',
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[4-9]']),
        NumberFormat(pattern='(3\\d{2})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['3'])],
    mobile_number_portable_region=True)
