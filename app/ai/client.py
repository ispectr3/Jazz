import json
import os
import time
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable


Message = Dict[str, str]


@dataclass
class LLMResponse:
    content: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    finish_reason: str = "stop"
    latency_ms: float = 0.0
    raw: Any = field(default=None, repr=False)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class LLMClient(ABC):
    @property
    @abstractmethod
    def model(self) -> str:
        ...

    @property
    def provider(self) -> str:
        return "unknown"

    @abstractmethod
    def chat(
        self,
        messages: List[Message],
        *,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> LLMResponse:
        ...

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> LLMResponse:
        msgs: List[Message] = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        return self.chat(msgs, temperature=temperature, max_tokens=max_tokens, **kwargs)


ProviderBuilder = Callable[[Dict[str, Any]], LLMClient]

_PROVIDERS: Dict[str, ProviderBuilder] = {}


def register_provider(name: str, builder: ProviderBuilder) -> None:
    _PROVIDERS[name] = builder


def available_providers() -> List[str]:
    return sorted(_PROVIDERS)


def create_llm(config: Dict[str, Any], **overrides: Any) -> LLMClient:
    cfg = dict(config)
    for key, value in overrides.items():
        if value is not None:
            cfg[key] = value
    provider = cfg.get("provider", "auto")
    if provider == "auto":
        provider = _auto_detect_provider()
        cfg["provider"] = provider
    builder = _PROVIDERS.get(provider)
    if builder is None:
        raise ValueError(f"Unknown provider '{provider}'. Available: {available_providers()}")
    return builder(cfg)


def _auto_detect_provider() -> str:
    if os.environ.get("GROQ_API_KEY"):
        return "groq"
    if os.environ.get("NVIDIA_API_KEY"):
        return "nvidia"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("DEEPSEEK_API_KEY"):
        return "deepseek"
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    if os.environ.get("FREE_API_KEY") or _has_cached_free_keys():
        return "free-gateway"
    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    if _ollama_available(ollama_url):
        return "ollama"
    return "fallback"


def _has_cached_free_keys() -> bool:
    try:
        from app.ai.key_manager import _load_cache
        return bool(_load_cache())
    except Exception:
        return False


def _ollama_available(url: str) -> bool:
    try:
        req = urllib.request.Request(f"{url}/api/tags", method="GET")
        resp = urllib.request.urlopen(req, timeout=2)
        return resp.status == 200
    except Exception:
        return False


class GroqClient(LLMClient):
    _key_index: int = 0

    def __init__(self, config: Dict[str, Any]):
        self._model = config.get("model", "llama-3.1-8b-instant")
        self._keys = self._collect_keys(config)

    @classmethod
    def _collect_keys(cls, config: dict) -> list[str]:
        keys = []
        primary = config.get("api_key") or os.environ.get("GROQ_API_KEY", "")
        if primary:
            keys.append(primary)
        for i in range(2, 10):
            k = os.environ.get(f"GROQ_API_KEY_{i}", "")
            if k:
                keys.append(k)
        return keys or [""]

    @classmethod
    def _next_key(cls) -> str:
        keys = cls._collect_keys({})
        if not keys:
            return ""
        idx = cls._key_index % len(keys)
        cls._key_index += 1
        return keys[idx]

    @property
    def model(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return "groq"

    def chat(
        self,
        messages: List[Message],
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        from groq import Groq
        from groq import RateLimitError, APIStatusError
        start_key = GroqClient._key_index
        GroqClient._key_index += 1
        errors = []
        num_keys = len(self._keys)
        for attempt in range(num_keys):
            api_key = self._keys[(start_key + attempt) % num_keys]
            try:
                start = time.time()
                client = Groq(api_key=api_key)
                groq_kwargs = dict(
                    model=self._model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                if "response_format" in kwargs:
                    groq_kwargs["response_format"] = kwargs["response_format"]
                chat = client.chat.completions.create(**groq_kwargs)
                elapsed = (time.time() - start) * 1000
                choice = chat.choices[0]
                usage = chat.usage
                return LLMResponse(
                    content=choice.message.content or "",
                    model=self._model,
                    prompt_tokens=usage.prompt_tokens if usage else 0,
                    completion_tokens=usage.completion_tokens if usage else 0,
                    finish_reason=choice.finish_reason or "stop",
                    latency_ms=elapsed,
                )
            except (RateLimitError, APIStatusError) as e:
                errors.append(f"key_{attempt}: {e}")
                continue
        raise Exception(f"Todas as {num_keys} chaves Groq falharam: {'; '.join(errors)}")


class OllamaClient(LLMClient):
    def __init__(self, config: Dict[str, Any]):
        self._model = config.get("model") or os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:latest")
        self._url = config.get("url") or os.environ.get("OLLAMA_URL", "http://localhost:11434")

    @property
    def model(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return "ollama"

    def chat(
        self,
        messages: List[Message],
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        start = time.time()
        payload = json.dumps({
            "model": self._model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }).encode()
        req = urllib.request.Request(
            f"{self._url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=120)
        data = json.loads(resp.read().decode())
        elapsed = (time.time() - start) * 1000
        return LLMResponse(
            content=data.get("message", {}).get("content", ""),
            model=self._model,
            latency_ms=elapsed,
        )


class OpenAIClient(LLMClient):
    def __init__(self, config: Dict[str, Any]):
        self._model = config.get("model", "gpt-4o-mini")
        self._api_key = config.get("api_key") or os.environ.get("OPENAI_API_KEY", "")
        self._base_url = config.get("base_url") or os.environ.get("OPENAI_BASE_URL", "")

    @property
    def model(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return "openai"

    def chat(
        self,
        messages: List[Message],
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        from openai import OpenAI
        start = time.time()
        client_kwargs = {"api_key": self._api_key}
        if self._base_url:
            client_kwargs["base_url"] = self._base_url
        client = OpenAI(**client_kwargs)
        oai_kwargs = dict(
            model=self._model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if "response_format" in kwargs:
            oai_kwargs["response_format"] = kwargs["response_format"]
        chat = client.chat.completions.create(**oai_kwargs)
        elapsed = (time.time() - start) * 1000
        choice = chat.choices[0]
        usage = chat.usage
        return LLMResponse(
            content=choice.message.content or "",
            model=self._model,
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            finish_reason=choice.finish_reason or "stop",
            latency_ms=elapsed,
        )


class DeepSeekClient(LLMClient):
    def __init__(self, config: Dict[str, Any]):
        self._model = config.get("model", "deepseek-chat")
        self._api_key = config.get("api_key") or os.environ.get("DEEPSEEK_API_KEY", "")

    @property
    def model(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return "deepseek"

    def chat(
        self,
        messages: List[Message],
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        from openai import OpenAI
        start = time.time()
        client = OpenAI(api_key=self._api_key, base_url="https://api.deepseek.com")
        ds_kwargs = dict(
            model=self._model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if "response_format" in kwargs:
            ds_kwargs["response_format"] = kwargs["response_format"]
        chat = client.chat.completions.create(**ds_kwargs)
        elapsed = (time.time() - start) * 1000
        choice = chat.choices[0]
        usage = chat.usage
        return LLMResponse(
            content=choice.message.content or "",
            model=self._model,
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            finish_reason=choice.finish_reason or "stop",
            latency_ms=elapsed,
        )


class GeminiClient(LLMClient):
    def __init__(self, config: Dict[str, Any]):
        self._model = config.get("model", "gemini-2.0-flash")
        self._api_key = config.get("api_key") or os.environ.get("GEMINI_API_KEY", "")

    @property
    def model(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return "gemini"

    def chat(
        self,
        messages: List[Message],
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        import google.genai as genai
        start = time.time()
        client = genai.Client(api_key=self._api_key)
        # Convert messages to Gemini format
        contents = []
        system_prompt = None
        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            if role == "system":
                system_prompt = content
            elif role == "user":
                contents.append({"role": "user", "parts": [{"text": content}]})
            elif role == "assistant":
                contents.append({"role": "model", "parts": [{"text": content}]})
        genai_kwargs = dict(
            model=self._model,
            contents=contents,
            config={"temperature": temperature, "max_output_tokens": max_tokens},
        )
        if system_prompt:
            genai_kwargs["config"]["system_instruction"] = system_prompt
        response = client.models.generate_content(**genai_kwargs)
        elapsed = (time.time() - start) * 1000
        return LLMResponse(
            content=response.text or "",
            model=self._model,
            latency_ms=elapsed,
        )


class NvidiaClient(LLMClient):
    MODEL_ALIASES = {
        "nemotron-super": "nvidia/nemotron-3-super-120b-a12b",
        "nemotron-nano": "nvidia/nemotron-3-nano-30b-a12b",
        "deepseek-v4-flash": "deepseek-ai/deepseek-v4-flash",
        "deepseek-v4-pro": "deepseek-ai/deepseek-v4-pro",
        "llama-3.3": "meta/llama-3.3-70b-instruct",
        "llama-3.1": "meta/llama-3.1-8b-instruct",
        "llama-3.2-1b": "meta/llama-3.2-1b-instruct",
        "llama-guard-4": "meta/llama-guard-4-12b",
        "mistral-small": "mistralai/mistral-small-24b-instruct-2501",
    }
    _key_index: int = 0

    def __init__(self, config: Dict[str, Any]):
        raw_model = config.get("model", "nemotron-super")
        self._model = self.MODEL_ALIASES.get(raw_model, raw_model)
        self._keys = self._collect_keys(config)
        self._nim_url = config.get("nim_url") or os.environ.get("NVIDIA_NIM_URL", "")

    @classmethod
    def _collect_keys(cls, config: dict) -> list[str]:
        keys = []
        primary = config.get("api_key") or os.environ.get("NVIDIA_API_KEY", "")
        if primary:
            keys.append(primary)
        for i in range(2, 10):
            k = os.environ.get(f"NVIDIA_API_KEY_{i}", "")
            if k:
                keys.append(k)
        return keys or [""]

    @property
    def model(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return "nvidia"

    def _base_url(self) -> str:
        if self._nim_url:
            return self._nim_url.rstrip("/")
        return "https://integrate.api.nvidia.com/v1"

    def chat(
        self,
        messages: List[Message],
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        from openai import OpenAI, APIStatusError
        start_key = NvidiaClient._key_index
        NvidiaClient._key_index += 1
        errors = []
        num_keys = len(self._keys)
        base_url = self._base_url()
        for attempt in range(num_keys):
            api_key = self._keys[(start_key + attempt) % num_keys]
            try:
                start = time.time()
                client = OpenAI(api_key=api_key, base_url=base_url)
                nv_kwargs = dict(
                    model=self._model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                if "response_format" in kwargs:
                    nv_kwargs["response_format"] = kwargs["response_format"]
                chat = client.chat.completions.create(**nv_kwargs)
                elapsed = (time.time() - start) * 1000
                choice = chat.choices[0]
                usage = chat.usage
                return LLMResponse(
                    content=choice.message.content or "",
                    model=self._model,
                    prompt_tokens=usage.prompt_tokens if usage else 0,
                    completion_tokens=usage.completion_tokens if usage else 0,
                    finish_reason=choice.finish_reason or "stop",
                    latency_ms=elapsed,
                )
            except APIStatusError as e:
                errors.append(f"key_{attempt}: {e}")
                continue
        raise Exception(f"Todas as {num_keys} chaves NVIDIA falharam: {'; '.join(errors)}")


def _resolve_free_key(config: dict) -> str:
    api_key = config.get("api_key") or os.environ.get("FREE_API_KEY", "")
    if api_key:
        return api_key
    try:
        from app.ai.key_manager import get_best_key
        key = get_best_key()
        if key:
            os.environ["FREE_API_KEY"] = key
            return key
    except Exception:
        pass
    return ""


class FreeGatewayClient(LLMClient):
    MODEL_ALIASES = {
        "deepseek-v4-pro": "deepseek-v4-pro",
        "deepseek-v4-flash": "deepseek-v4-flash",
        "deepseek-chat": "deepseek-chat",
        "smart-chat": "smart-chat",
        "claude-opus": "claude-opus-4-7",
        "gpt-5.5": "gpt-5.5",
        "gemini-flash": "gemini-2.5-flash",
        "kimi": "kimi-k2.5",
        "nemotron-nano": "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
        "grok": "x-ai/grok-4.3",
        "qwen-max": "qwen/qwen3.6-max-preview",
    }

    def __init__(self, config: Dict[str, Any]):
        raw_model = config.get("model", "deepseek-chat")
        self._model = self.MODEL_ALIASES.get(raw_model, raw_model)
        self._api_key = _resolve_free_key(config)
        self._base_url = config.get("base_url") or os.environ.get("FREE_API_URL", "https://aiapiv2.pekpik.com/v1")

    @property
    def model(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return "free-gateway"

    def chat(
        self,
        messages: List[Message],
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        from openai import OpenAI
        start = time.time()
        client = OpenAI(api_key=self._api_key, base_url=self._base_url)
        gw_kwargs = dict(
            model=self._model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if "response_format" in kwargs:
            gw_kwargs["response_format"] = kwargs["response_format"]
        chat = client.chat.completions.create(**gw_kwargs)
        elapsed = (time.time() - start) * 1000
        choice = chat.choices[0]
        usage = chat.usage
        return LLMResponse(
            content=choice.message.content or "",
            model=self._model,
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            finish_reason=choice.finish_reason or "stop",
            latency_ms=elapsed,
        )


class FallbackClient(LLMClient):
    def __init__(self, config: Dict[str, Any]):
        self._config = config

    @property
    def model(self) -> str:
        return "fallback"

    @property
    def provider(self) -> str:
        return "fallback"

    def chat(
        self,
        messages: List[Message],
        *,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> LLMResponse:
        user_content = "\n".join(
            m.get("content", "") for m in messages if m.get("role") == "user"
        )
        return LLMResponse(
            content=json.dumps({
                "findings": [
                    {
                        "index": 0,
                        "severity": "Info",
                        "cvss_estimate": "0.0",
                        "cwe": "N/A",
                        "executive_summary": "Sem LLM disponivel. Configure GROQ_API_KEY, OPENAI_API_KEY, DEEPSEEK_API_KEY ou GEMINI_API_KEY no .env.",
                        "attack_vector": "N/A",
                        "remediation": "N/A",
                        "exploitability": "dificil",
                        "chainable": False,
                    }
                ]
            }),
            model="fallback",
            finish_reason="stop",
        )


register_provider("groq", lambda c: GroqClient(c))
register_provider("nvidia", lambda c: NvidiaClient(c))
register_provider("ollama", lambda c: OllamaClient(c))
register_provider("openai", lambda c: OpenAIClient(c))
register_provider("deepseek", lambda c: DeepSeekClient(c))
register_provider("gemini", lambda c: GeminiClient(c))
register_provider("free-gateway", lambda c: FreeGatewayClient(c))
register_provider("fallback", lambda c: FallbackClient(c))
register_provider("auto", lambda c: create_llm(c))
