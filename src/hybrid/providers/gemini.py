from __future__ import annotations

import json
import os

DEFAULT_MODEL = "gemini-3.5-flash"


class GeminiClient:
    """Implements LLMClient. The google-genai package loads only when needed."""

    def __init__(self, client=None, model=None):
        if client is None:
            from google import genai

            client = genai.Client()  # reads the API key from the environment
        self._client = client
        self._model = model or os.getenv("GEMINI_MODEL", DEFAULT_MODEL)

    def complete_json(self, prompt: str, document: str, schema: dict) -> dict:
        contents = (
            f"{prompt}\n\nReturn only JSON matching this JSON schema:\n"
            f"{json.dumps(schema)}\n\nCONTRACT:\n{document}"
        )
        response = self._client.models.generate_content(
            model=self._model,
            contents=contents,
            config={"response_mime_type": "application/json", "temperature": 0},
        )
        text = response.text
        if not text:
            raise ValueError("empty response from the model")
        return json.loads(text)
