import pytest
import requests

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

    @pytest.mark.parametrize(
        "input_value,expected_data",
        [
            (None, None),  # None returns None
            ("simple-string", "simple-string"),  # a string returns the same string
        ],
    )
    def test_opt_value_to_data(self, mocker, input_value, expected_data):
        sf = SpiderFoot(options={"_debug": False, "__logging": False})

        assert sf.optValueToData(val=input_value) == expected_data

    def test_opt_value_to_data_file_input_file_doesnt_exist(self, mocker):
        file_name = "test.txt"

        sf = SpiderFoot(options={"_debug": False, "__logging": False})
        mock_error = mocker.patch.object(SpiderFoot, "error")

        # if fatal=False, return 'None', no errors are logged
        assert sf.optValueToData(val=f"@{file_name}", fatal=False) is None
        mock_error.assert_not_called()

        # if fatal=True, log an error and return the file name
        assert sf.optValueToData(val=f"@{file_name}", fatal=True) == f"@{file_name}"
        mock_error.assert_called_once()

    def test_opt_value_to_data_file_input_file_exists(self, mocker):
        """if input start with '@', return the contents of that file"""
        test_content = "file-content"
        file_name = "test.txt"

        sf = SpiderFoot(options={"_debug": False, "__logging": False})
        mocker.patch("sflib.open", mocker.mock_open(read_data=test_content))

        assert sf.optValueToData(val=f"@{file_name}", splitLines=False) == test_content
        assert sf.optValueToData(val=f"@{file_name}", splitLines=True) == [test_content]

    def test_opt_value_to_data_url_input_url_exists(self, mocked_responses):
        """if input starts with 'http://' or 'https://', fetch the url content"""
        test_content = "url-content"
        test_url = "http://example.com"

        sf = SpiderFoot(options={"_debug": False, "__logging": False})
        mocked_responses.add(
            mocked_responses.GET, test_url, body=test_content, status=200
        )
        mocked_responses.add(
            mocked_responses.GET, test_url, body=test_content, status=200
        )

        # TODO: this function possibly returns unicode, will keep for now
        # to avoid breaking changes, but this should be fixed
        assert sf.optValueToData(val=test_url, splitLines=False) == test_content.encode(
            "utf-8"
        )
        assert sf.optValueToData(val=test_url, splitLines=True) == [
            test_content.encode("utf-8")
        ]

    # TODO: Make this test case pass
    @pytest.mark.xfail(
        reason=(
            "error responses are handled similarly to 200 for now "
            "to avoid breaking changes"
        )
    )
    def test_opt_value_to_data_url_input_404(self, mocked_responses, mocker):
        test_url = "http://example.com"

        sf = SpiderFoot(options={"_debug": False, "__logging": False})
        mocked_responses.add(
            mocked_responses.GET, test_url, json={"error": "not found"}, status=404
        )
        mocked_responses.add(
            mocked_responses.GET, test_url, json={"error": "not found"}, status=404
        )
        mock_error = mocker.patch.object(SpiderFoot, "error")

        # If fatal=False, return 'None', no errors are logged
        assert sf.optValueToData(val=test_url, fatal=False) is None
        mock_error.assert_not_called()

        # if fatal=True, log an error and return the url
        assert sf.optValueToData(val=test_url, fatal=True) == test_url
        mock_error.assert_called_once()


class TestFetchUrl:
    def test_successful_requests(self, mocked_responses):
        test_url = "http://example.com"
        test_content = "url-content"

        mocked_responses.add(
            mocked_responses.GET, test_url, body=test_content, status=200
        )

        sf = SpiderFoot(
            options={"_debug": False, "__logging": False, "_socks1type": ""}
        )
        result = sf.fetchUrl(url=test_url)

        expected_response = {
            # TODO: shouldn't 'code' be a number rather than a string?
            "code": "200",
            "content": "url-content",
            "headers": {"content-type": "text/plain"},
            "realurl": "http://example.com/",
            "status": None,
        }

        assert result == expected_response

    def test_error_handling(self, mocked_responses, mocker):
        test_url = "http://example.com"
        test_content = "url-content"
        headers = {
            "api_key": "samplekey",
            "Content-Type": "application/json",
        }

        mocked_responses.add(
            mocked_responses.GET,
            test_url,
            body=requests.exceptions.HTTPError("Timeout"),
        )

        sf = SpiderFoot(options={"_socks1type": "", "__logging": False,})

        # Assert error function is called
        mock_error = mocker.patch.object(SpiderFoot, "error")
        result = sf.fetchUrl(url=test_url, headers=headers)
        mock_error.assert_called()

    def test_404_requests(self, mocked_responses):
        test_url = "http://example.com"
        test_content = "not-found"

        mocked_responses.add(
            mocked_responses.GET, test_url, json={"error": test_content}, status=404
        )

        sf = SpiderFoot(
            options={"_debug": False, "__logging": False, "_socks1type": ""}
        )
        result = sf.fetchUrl(url=test_url)

        expected_response = {
            "code": "404",
            "content": '{"error": "not-found"}',
            "headers": {"content-type": "application/json"},
            "realurl": "http://example.com/",
            "status": None,
        }
        assert result == expected_response


class TestSfPlugin:
    def test_notify_listeners_works(self, mocker):
        """Tests when a module calls notifyListeners with an event,
        all listener modules have 'handleEvent' called"""

        mocked_fn = mocker.patch("sflib.SpiderFootPlugin.handleEvent")

        sf_plugin = SpiderFootPlugin()
        sf_plugin_2 = SpiderFootPlugin()
        sf_plugin.registerListener(listener=sf_plugin_2)

        root_event = SpiderFootEvent(
            eventType="ROOT", data="binarypool.com", module="", sourceEvent=None
        )

        sf_plugin.notifyListeners(sfEvent=root_event)
        mocked_fn.assert_called_once()
        mocked_fn.assert_called_with(root_event)
