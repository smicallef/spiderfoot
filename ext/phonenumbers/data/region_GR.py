"""Auto-generated file, do not edit by hand. GR metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_GR = PhoneMetadata(id='GR', country_code=30, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[26-9]\\d{9}', possible_number_pattern='\\d{10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2(?:1\\d{2}|2(?:2[1-46-9]|3[1-8]|4[1-7]|5[1-4]|6[1-8]|7[1-5]|[89][1-9])|3(?:1\\d|2[1-57]|[35][1-3]|4[13]|7[1-7]|8[124-6]|9[1-79])|4(?:1\\d|2[1-8]|3[1-4]|4[13-5]|6[1-578]|9[1-5])|5(?:1\\d|[29][1-4]|3[1-5]|4[124]|5[1-6])|6(?:1\\d|3[1245]|4[1-7]|5[13-9]|[269][1-6]|7[14]|8[1-5])|7(?:1\\d|2[1-5]|3[1-6]|4[1-7]|5[1-57]|6[135]|9[125-7])|8(?:1\\d|2[1-5]|[34][1-4]|9[1-57]))\\d{6}', possible_number_pattern='\\d{10}', example_number='2123456789'),
    mobile=PhoneNumberDesc(national_number_pattern='69\\d{8}', possible_number_pattern='\\d{10}', example_number='6912345678'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{7}', possible_number_pattern='\\d{10}', example_number='8001234567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90[19]\\d{7}', possible_number_pattern='\\d{10}', example_number='9091234567'),
    shared_cost=PhoneNumberDesc(national_number_pattern='8(?:0[16]|12|25)\\d{7}', possible_number_pattern='\\d{10}', example_number='8011234567'),
    personal_number=PhoneNumberDesc(national_number_pattern='70\\d{8}', possible_number_pattern='\\d{10}', example_number='7012345678'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='([27]\\d)(\\d{4})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['21|7']),
        NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['2[2-9]1|[689]']),
        NumberFormat(pattern='(2\\d{3})(\\d{6})', format='\\1 \\2', leading_digits_pattern=['2[2-9][02-9]'])],
    mobile_number_portable_region=True)
