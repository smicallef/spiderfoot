import pytest
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


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


class TestSfPlugin:
    def test_notify_listeners_works(self, mocker):
        """Tests when a module calls notifyListeners with an event,
        all listener modules have 'handleEvent' called"""

        mocked_fn = mocker.patch("sflib.SpiderFootPlugin.handleEvent")

        sf_plugin = SpiderFootPlugin()
        sf_plugin_2 = SpiderFootPlugin()
        sf_plugin.registerListener(listener=sf_plugin_2)

        root_event = SpiderFootEvent(
            eventType="ROOT",
            data=u'binarypool.com',
            module="",
            sourceEvent=None
        )

        sf_plugin.notifyListeners(sfEvent=root_event)
        mocked_fn.assert_called_once()
        mocked_fn.assert_called_with(root_event)