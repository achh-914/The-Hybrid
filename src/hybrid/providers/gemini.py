from __future__ import annotations

import json
import os
import time

DEFAULT_MODEL = "gemini-3.5-flash-lite"
RETRYABLE = {429, 500, 502, 503, 504}


class GeminiClient:
    """Implements LLMClient. The google-genai package loads only when needed."""

    def __init__(self, client=None, model=None, retries=4, sleep=time.sleep):
        if client is None:
            from google import genai

            client = genai.Client()  # reads the API key from the environment
        self._client = client
        self._model = model or os.getenv("GEMINI_MODEL", DEFAULT_MODEL)
        self._retries = retries
        self._sleep = sleep

    def complete_json(self, prompt: str, document: str, schema: dict) -> dict:
        contents = (
            f"{prompt}\n\nReturn only JSON matching this JSON schema:\n"
            f"{json.dumps(schema)}\n\nCONTRACT:\n{document}"
        )
        for attempt in range(self._retries + 1):
            try:
                response = self._client.models.generate_content(
                    model=self._model,
                    contents=contents,
                    config={"response_mime_type": "application/json", "temperature": 0},
                )
                break
            except Exception as e:
                if getattr(e, "code", None) not in RETRYABLE or attempt == self._retries:
                    raise
                self._sleep(2**attempt)
        text = response.text
        if not text:
            raise ValueError("empty response from the model")
        return json.loads(text)
