"""Translate python-phonenumbers PhoneNumber to/from protobuf PhoneNumber

Examples of use:

>>> import phonenumbers
>>> from phonenumbers.pb2 import phonenumber_pb2, PBToPy, PyToPB
>>> x_py = phonenumbers.PhoneNumber(country_code=44, national_number=7912345678)
>>> print x_py
Country Code: 44 National Number: 7912345678
>>> y_pb = phonenumber_pb2.PhoneNumber()
>>> y_pb.country_code = 44
>>> y_pb.national_number = 7912345678
>>> print str(y_pb).strip()
country_code: 44
national_number: 7912345678
>>> # Check italian_leading_zero default value when not set
>>> y_pb.italian_leading_zero
False
>>> y_py = PBToPy(y_pb)
>>> print y_py
Country Code: 44 National Number: 7912345678
>>> x_pb = PyToPB(x_py)
>>> print str(x_pb).strip()
country_code: 44
national_number: 7912345678
>>> x_py == y_py
True
>>> x_pb == y_pb
True
>>> # Explicitly set the field to its default
>>> y_pb.italian_leading_zero = y_pb.italian_leading_zero
>>> x_pb == y_pb
False
"""

from phonenumber_pb2 import PhoneNumber as PhoneNumberPB
from phonenumbers import PhoneNumber

def PBToPy(numpb):
    """Convert phonenumber_pb2.PhoneNumber to phonenumber.PhoneNumber"""
    return PhoneNumber(country_code=numpb.country_code if numpb.HasField("country_code") else None,
                       national_number=numpb.national_number if numpb.HasField("national_number") else None,
                       extension=numpb.extension if numpb.HasField("extension") else None,
                       italian_leading_zero=numpb.italian_leading_zero if numpb.HasField("italian_leading_zero") else None,
                       number_of_leading_zeros=numpb.number_of_leading_zeros if numpb.HasField("number_of_leading_zeros") else None,
                       raw_input=numpb.raw_input if numpb.HasField("raw_input") else None,
                       country_code_source=numpb.country_code_source if numpb.HasField("country_code_source") else None,
                       preferred_domestic_carrier_code=numpb.preferred_domestic_carrier_code if numpb.HasField("preferred_domestic_carrier_code") else None)

def PyToPB(numobj):
    """Convert phonenumber.PhoneNumber to phonenumber_pb2.PhoneNumber"""
    numpb = PhoneNumberPB()
    if numobj.country_code is not None:
        numpb.country_code = numobj.country_code
    if numobj.national_number is not None:
        numpb.national_number = numobj.national_number
    if numobj.extension is not None:
        numpb.extension = numobj.extension
    if numobj.italian_leading_zero is not None:
        numpb.italian_leading_zero = numobj.italian_leading_zero
    if numobj.number_of_leading_zeros is not None:
        numpb.number_of_leading_zeros = numobj.number_of_leading_zeros
    if numobj.raw_input is not None:
        numpb.raw_input = numobj.raw_input
    if numobj.country_code_source is not None:
        numpb.country_code_source = numobj.country_code_source
    if numobj.preferred_domestic_carrier_code is not None:
        numpb.preferred_domestic_carrier_code = numobj.preferred_domestic_carrier_code
    return numpb

__all__ = ['PBToPy', 'PyToPB']

if __name__ == '__main__':  # pragma no cover
    import doctest
    doctest.testmod()
