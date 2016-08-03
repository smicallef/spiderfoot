"""Auto-generated file, do not edit by hand. CL metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_CL = PhoneMetadata(id='CL', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[1-9]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='1213|4342', possible_number_pattern='\\d{4}', example_number='4342'),
    premium_rate=PhoneNumberDesc(national_number_pattern='1(?:060|211|3(?:13|[348]0|5[01])|417|560|818|9(?:19|80))|2(?:0122|22[47]|323|777|882)|3(?:0(?:51|99)|132|3(?:29|77|90)|665)|4(?:142|243|3656|4(?:02|15|77)|554)|5(?:004|4154|5(?:66|77)|995)|6(?:0700|131|222|3(?:00|66)|500|699)|7878|8(?:011|11[28]|482|889)|9(?:011|[12]00|330)', possible_number_pattern='\\d{3,5}', example_number='2224'),
    emergency=PhoneNumberDesc(national_number_pattern='13[123]|911', possible_number_pattern='\\d{3,5}', example_number='133'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:06?0|21[13]|3(?:[02679]|13?|[348]0?|5[01]?)|4(?:0[02-6]|17|[379])|560|818|9(?:19|80))|2(?:0(?:01|122)|22[47]|323|777|882)|3(?:0(?:51|99)|132|3(?:29|37|77|90)|665)|4(?:142|243|3(?:42|656)|4(?:02|15|77)|554)|5(?:004|4154|5(?:66|77)|995)|6(?:0700|131|222|3(?:00|66)|500|699)|7878|8(?:011|11[28]|482|889)|9(?:011|1(?:1|00)|200|330)', possible_number_pattern='\\d{3,5}', example_number='139'),
    standard_rate=PhoneNumberDesc(national_number_pattern='2001|3337', possible_number_pattern='\\d{4}', example_number='3337'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
