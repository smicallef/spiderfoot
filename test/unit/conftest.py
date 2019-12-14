import pytest
import responses

@pytest.fixture
def mocked_responses():
    with responses.RequestsMock() as rsps:
        yield rsps