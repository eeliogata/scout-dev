import asyncio
import json
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from threat_monitor.storage.db import ConfigurationError


OUTPUT_TOKENS = 2048
REQUEST_TIMEOUT = 120
STARTUP_TIMEOUT = 900


class InferenceError(RuntimeError):
    def __init__(self, message, *, status=None):
        super().__init__(message)
        self.status = status


class AnalysisIncomplete(RuntimeError):
    pass


def create_client(settings):
    settings.matching_analysis_provider()
    if settings.analysis_provider == "gemini":
        from threat_monitor.analysis.gemini import GeminiClient

        return GeminiClient(settings)
    return ModalClient(settings)


def served_model_name(settings):
    revision = settings.analysis_model_revision
    if not revision or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ConfigurationError("Set ANALYSIS_MODEL_REVISION to an immutable 40-character commit SHA")
    return f"{settings.analysis_model}@{revision}"


class ModalClient:
    def __init__(self, settings):
        self.model = served_model_name(settings)
        self.context_length = settings.analysis_context_length
        self.url = (settings.modal_inference_url or "").rstrip("/").removesuffix("/v1")
        parsed = urlsplit(self.url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.query or parsed.fragment:
            raise ConfigurationError("Set MODAL_INFERENCE_URL to the inference server base URL")
        if parsed.username or parsed.password:
            raise ConfigurationError("Use MODAL_INFERENCE_TOKEN for inference authentication")
        secret = settings.modal_inference_token
        if secret is None or not secret.get_secret_value().strip():
            raise ConfigurationError("Set MODAL_INFERENCE_TOKEN to a Modal proxy bearer token")
        self.token = secret.get_secret_value()

    def _send(self, path, payload, *, authenticated=True, timeout=REQUEST_TIMEOUT):
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        request = Request(self.url + path, data=data, headers=headers)
        try:
            with urlopen(request, timeout=timeout) as response:
                body = response.read()
        except HTTPError as exc:
            status = exc.code
            exc.close()
            raise InferenceError(f"Modal inference returned HTTP {status}", status=status) from None
        except (URLError, TimeoutError, OSError):
            raise InferenceError("Modal inference connection failed or timed out") from None
        if not body:
            return {}
        try:
            result = json.loads(body)
        except (ValueError, UnicodeError):
            raise InferenceError("Modal inference returned invalid JSON") from None
        if not isinstance(result, dict):
            raise InferenceError("Modal inference returned an unexpected response shape")
        return result

    async def request(self, path, payload=None, **kwargs):
        return await asyncio.to_thread(self._send, path, payload, **kwargs)

    async def ready(self):
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while True:
            try:
                await self.request("/health", timeout=min(REQUEST_TIMEOUT, max(1, deadline - time.monotonic())))
                break
            except InferenceError as exc:
                if exc.status != 503 or time.monotonic() >= deadline:
                    raise
                await asyncio.sleep(2)
        response = await self.request("/v1/models")
        models = response.get("data")
        if not isinstance(models, list) or not any(
            isinstance(model, dict) and model.get("id") == self.model for model in models
        ):
            raise ConfigurationError("Modal endpoint does not serve the configured model and pinned revision")

    async def chat(self, messages, *, tools=None, schema=None):
        token_request = {
            "model": self.model,
            "messages": messages,
            "add_generation_prompt": True,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        if tools:
            token_request["tools"] = tools
        token_response = await self.request("/tokenize", token_request)
        count = token_response.get("count")
        server_limit = token_response.get("max_model_len")
        if type(count) is not int or count < 0 or type(server_limit) is not int or server_limit <= 0:
            raise InferenceError("Modal tokenizer returned invalid token counts")
        limit = min(self.context_length, server_limit)
        if count + OUTPUT_TOKENS > limit:
            raise AnalysisIncomplete(f"Context budget exceeded: {count} input tokens plus {OUTPUT_TOKENS} reserved, limit {limit}")
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": OUTPUT_TOKENS,
            "temperature": 0.7,
            "top_p": 0.8,
            "top_k": 20,
            "stream": False,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        if tools:
            payload.update(tools=tools, tool_choice="auto", parallel_tool_calls=False)
        if schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "company_findings", "schema": schema},
            }
        response = await self.request("/v1/chat/completions", payload)
        try:
            choice = response["choices"][0]
            message = choice["message"]
            reason = choice["finish_reason"]
        except (KeyError, IndexError, TypeError):
            raise InferenceError("Modal inference returned an invalid completion") from None
        if reason == "length":
            raise AnalysisIncomplete("Model output reached the response token limit")
        if reason not in ("stop", "tool_calls") or not isinstance(message, dict):
            raise AnalysisIncomplete("Model did not finish a valid response")
        if message.get("role") != "assistant":
            raise InferenceError("Modal inference returned an invalid assistant message")
        if reason == "tool_calls" and not message.get("tool_calls"):
            raise AnalysisIncomplete("Model ended with a tool call but supplied no calls")
        return message
