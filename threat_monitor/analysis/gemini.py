import copy
import json
from uuid import uuid4

from threat_monitor.analysis.client import AnalysisIncomplete, InferenceError, OUTPUT_TOKENS
from threat_monitor.ingestion.providers import request_gemini
from threat_monitor.storage.db import ConfigurationError


class GeminiClient:
    def __init__(self, settings):
        settings.matching_analysis_provider()
        if settings.analysis_provider != "gemini":
            raise ConfigurationError("Set ANALYSIS_PROVIDER=gemini for Gemini analysis")
        if settings.gemini_api_key is None or not settings.gemini_api_key.get_secret_value().strip():
            raise ConfigurationError("Set GEMINI_API_KEY for Gemini analysis")
        self.settings = settings
        self.model = settings.analysis_model

    async def ready(self):
        # Access is checked by countTokens before each generation; Gemini has no cold-start endpoint.
        return None

    async def request(self, method, payload):
        try:
            return await request_gemini(self.model, method, payload, settings=self.settings)
        except (RuntimeError, ValueError) as exc:
            raise InferenceError(str(exc)) from None

    def conversation(self, messages):
        contents, system, calls = [], [], {}
        for message in messages:
            role = message["role"]
            if role == "system":
                system.append({"text": message["content"]})
                continue
            if role == "assistant":
                native = message.get("_gemini_content")
                if native is not None:
                    parts = copy.deepcopy(native["parts"])
                else:
                    parts = [{"text": message["content"]}] if message.get("content") else []
                    parts.extend({"functionCall": {
                        "name": call["function"]["name"], "id": call["id"],
                        "args": json.loads(call["function"]["arguments"]),
                    }} for call in message.get("tool_calls", []))
                native_calls = [part["functionCall"] for part in parts if "functionCall" in part]
                for call, native_call in zip(message.get("tool_calls", []), native_calls, strict=True):
                    calls[call["id"]] = native_call
                role = "model"
            elif role == "tool":
                call = calls[message["tool_call_id"]]
                response = {"name": call["name"], "response": json.loads(message["content"])}
                if call.get("id"):
                    response["id"] = call["id"]
                parts = [{"functionResponse": response}]
                role = "user"
            else:
                parts = [{"text": message["content"]}]
            if contents and contents[-1]["role"] == role:
                contents[-1]["parts"].extend(parts)
            else:
                contents.append({"role": role, "parts": parts})
        payload = {"contents": contents}
        if system:
            payload["systemInstruction"] = {"parts": system}
        return payload

    async def chat(self, messages, *, tools=None, schema=None):
        payload = self.conversation(messages)
        payload["generationConfig"] = {
            "maxOutputTokens": OUTPUT_TOKENS,
            "thinkingConfig": {"thinkingLevel": "LOW"},
        }
        if tools:
            payload["tools"] = [{"functionDeclarations": [{
                "name": item["function"]["name"], "description": item["function"]["description"],
                "parametersJsonSchema": item["function"]["parameters"],
            } for item in tools]}]
            payload["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}
        if schema is not None:
            payload["generationConfig"].update(responseMimeType="application/json", responseJsonSchema=schema)
        counted = await self.request("countTokens", {
            "generateContentRequest": {"model": "models/" + self.model, **payload},
        })
        count = counted.get("totalTokens")
        if type(count) is not int or count < 0:
            raise InferenceError("Gemini tokenizer returned an invalid token count")
        if count + OUTPUT_TOKENS > self.settings.analysis_context_length:
            raise AnalysisIncomplete(
                f"Context budget exceeded: {count} input tokens plus {OUTPUT_TOKENS} reserved, "
                f"limit {self.settings.analysis_context_length}"
            )
        response = await self.request("generateContent", payload)
        candidates = response.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise AnalysisIncomplete("Gemini returned no candidate; the request may have been blocked")
        candidate = candidates[0]
        if not isinstance(candidate, dict):
            raise InferenceError("Gemini returned an invalid candidate")
        if candidate.get("finishReason") == "MAX_TOKENS":
            raise AnalysisIncomplete("Model output reached the response token limit")
        if candidate.get("finishReason") != "STOP":
            raise AnalysisIncomplete("Gemini did not finish a valid response")
        native = candidate.get("content")
        if not isinstance(native, dict) or native.get("role") != "model" or not isinstance(native.get("parts"), list):
            raise InferenceError("Gemini returned an invalid model message")
        texts, calls = [], []
        for part in native["parts"]:
            if not isinstance(part, dict):
                raise InferenceError("Gemini returned an invalid content part")
            if "functionCall" in part:
                call = part["functionCall"]
                if (
                    not isinstance(call, dict) or not isinstance(call.get("name"), str) or not call["name"]
                    or not isinstance(call.get("args", {}), dict)
                    or ("id" in call and (not isinstance(call["id"], str) or not call["id"]))
                ):
                    raise AnalysisIncomplete("Gemini returned a malformed function call")
                calls.append({"id": call.get("id") or "gemini-" + uuid4().hex, "type": "function", "function": {
                    "name": call["name"], "arguments": json.dumps(call.get("args", {}), ensure_ascii=False),
                }})
            elif not part.get("thought") and isinstance(part.get("text"), str):
                texts.append(part["text"])
        if not calls and not any(text.strip() for text in texts):
            raise AnalysisIncomplete("Gemini returned no usable text or tool calls")
        message = {"role": "assistant", "content": "".join(texts) or None,
                   "_gemini_content": copy.deepcopy(native)}
        if calls:
            message["tool_calls"] = calls
        return message
