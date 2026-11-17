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
