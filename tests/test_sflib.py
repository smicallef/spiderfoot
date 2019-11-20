import pytest
from sflib import SpiderFoot


class TestSflib:
    @pytest.mark.parametrize(
        "test_string,parsed_emails",
        [
            ("amr@binarypool.com", ["amr@binarypool.com"]),  # valid email
            ("b@f.", []),  # too short (less than 5 charachters), should be ignored
            ("better%tomorrow@today.com", []),  # contains '%' should be ignored
            ("amr@wh...", []),  # truncated, should be ignored
        ],
    )
    def test_parse_emails(self, test_string, parsed_emails):
        sf = SpiderFoot(options={"_debug": False})

        assert sf.parseEmails(test_string) == parsed_emails
