"""Auto-generated file, do not edit by hand. CH metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_CH = PhoneMetadata(id='CH', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[1-9]\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='1(?:16\\d{3}|47)|5200', possible_number_pattern='\\d{3,6}', example_number='116000'),
    premium_rate=PhoneNumberDesc(national_number_pattern='1(?:145|8\\d{2})|543|83111', possible_number_pattern='\\d{3,5}', example_number='543'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:1[278]|44)', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:0[78]\\d{2}|1(?:[278]|45|6(?:000|111))|4(?:[03457]|1[45])|6(?:00|[1-46])|8(?:02|1[189]|50|7|8[08]|99))|[2-9]\\d{2,4}', possible_number_pattern='\\d{3,6}', example_number='147'),
    standard_rate=PhoneNumberDesc(national_number_pattern='1(?:4(?:[035]|1\\d)|6\\d{1,2})', possible_number_pattern='\\d{3,4}', example_number='1600'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='5(?:200|35)', possible_number_pattern='\\d{3,4}', example_number='535'),
    short_data=True)
