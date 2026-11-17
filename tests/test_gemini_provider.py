import pytest

from hybrid.providers.gemini import GeminiClient


class FakeModels:
    def __init__(self, text):
        self.text = text
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        return type("Response", (), {"text": self.text})()


class FakeClient:
    def __init__(self, text):
        self.models = FakeModels(text)


def test_returns_parsed_json_and_sends_prompt_and_document():
    client = FakeClient('{"obligations": []}')
    out = GeminiClient(client=client, model="m").complete_json("PROMPT", "DOC", {"type": "object"})
    assert out == {"obligations": []}
    call = client.models.calls[0]
    assert call["model"] == "m"
    assert "PROMPT" in call["contents"] and "DOC" in call["contents"]


def test_invalid_json_raises():
    with pytest.raises(ValueError):
        GeminiClient(client=FakeClient("not json"), model="m").complete_json("p", "d", {})


def test_empty_response_raises():
    with pytest.raises(ValueError):
        GeminiClient(client=FakeClient(""), model="m").complete_json("p", "d", {})


class TransientError(Exception):
    code = 503


class FlakyModels:
    def __init__(self, failures, text):
        self.failures = failures
        self.text = text
        self.calls = 0

    def generate_content(self, **kwargs):
        self.calls += 1
        if self.calls <= self.failures:
            raise TransientError("high demand")
        return type("Response", (), {"text": self.text})()


def flaky_client(failures):
    return type("C", (), {"models": FlakyModels(failures, '{"ok": true}')})()


def test_retries_on_503_then_succeeds():
    client = flaky_client(2)
    out = GeminiClient(client=client, model="m", sleep=lambda s: None).complete_json("p", "d", {})
    assert out == {"ok": True}
    assert client.models.calls == 3


def test_gives_up_after_all_retries():
    client = flaky_client(99)
    with pytest.raises(TransientError):
        GeminiClient(client=client, model="m", retries=2, sleep=lambda s: None).complete_json("p", "d", {})
    assert client.models.calls == 3
