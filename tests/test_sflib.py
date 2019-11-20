import pytest
from sflib import SpiderFoot


class TestSflib:
    @pytest.mark.parametrize(
        "test_string,expected_emails",
        [
            ("amr@binarypool.com", ["amr@binarypool.com"]),  # valid email
            ("b@f.", []),  # too short (less than 5 charachters), should be ignored
            ("better%tomorrow@today.com", []),  # contains '%' should be ignored
            ("amr@wh...", []),  # truncated, should be ignored
        ],
    )
    def test_parse_emails(self, test_string, expected_emails):
        sf = SpiderFoot(options={"_debug": False})

        assert sf.parseEmails(test_string) == expected_emails

    @pytest.mark.parametrize(
        "test_string,expected_links",
        [
            (  # valid full link
                "<a href='https://www.google.com/'></a>",
                {
                    "https://www.google.com/": {
                        "original": "https://www.google.com/",
                        "source": "https://www.example.com/",
                    }
                },
            ),
            (  # for a partial link, it's added to the source url
                "<a href='/partial'></a>",
                {
                    "https://www.example.com/partial": {
                        "original": "/partial",
                        "source": "https://www.example.com/",
                    }
                },
            ),
            ("<a href='#in-page-id'></a>", {},),  # In page ids are ignored
            ("<a href='mailto:test@binarypool.com'></a>", {},),  # mailto: are ignored
        ],
    )
    def test_parse_links(self, test_string, expected_links):
        sf = SpiderFoot(options={"_debug": False})

        parsed_links = sf.parseLinks(
            url="https://www.example.com/",
            data=test_string,
            domains=["testdomain.org"],
        )

        assert parsed_links == expected_links
