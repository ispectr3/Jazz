import json
import threading
from typing import Optional, List, Dict, Any

from app.ai.client import (
    create_llm,
    LLMResponse,
    Message,
    available_providers,
)


_DEFAULT_CONFIG: Dict[str, Any] = {}

_current_flow = threading.local()


def set_current_flow(flow_id: int):
    _current_flow.id = flow_id


def get_current_flow() -> int:
    return getattr(_current_flow, "id", 0)


def configure(config: Dict[str, Any]) -> None:
    _DEFAULT_CONFIG.clear()
    _DEFAULT_CONFIG.update(config)


def chat(
    messages: List[Message],
    model: str = "llama-3.1-8b-instant",
    temperature: float = 0.15,
    max_tokens: int = 4096,
    response_format: Optional[Dict[str, str]] = None,
    *,
    target: str = "",
    phase: str = "",
    decision: str = "",
) -> str:
    from app.ai.tracer import TraceContext
    from app.events import get_stream_manager

    overrides = {}
    if response_format:
        overrides["response_format"] = response_format

    config = dict(_DEFAULT_CONFIG) if _DEFAULT_CONFIG else {}
    config.setdefault("model", model)

    with TraceContext(target=target, phase=phase) as tc:
        tc.messages = messages
        llm = create_llm(config)
        tc.provider = llm.provider
        tc.model = llm.model
        try:
            resp = llm.chat(
                messages,
                temperature=temperature,
                max_tokens=max_tokens,
                **overrides,
            )
            tc.log(resp, decision=decision)
            flow_id = get_current_flow()
            if flow_id:
                get_stream_manager().emit_llm_call(flow_id, llm.provider, llm.model, phase, resp.latency_ms)
            return resp.content
        except Exception as e:
            tc.error = str(e)
            raise


def chat_with(
    messages: List[Message],
    *,
    provider: str = "auto",
    model: Optional[str] = None,
    temperature: float = 0.15,
    max_tokens: int = 4096,
    response_format: Optional[Dict[str, str]] = None,
    target: str = "",
    phase: str = "",
    decision: str = "",
) -> str:
    from app.ai.tracer import TraceContext
    from app.events import get_stream_manager

    overrides = {}
    if response_format:
        overrides["response_format"] = response_format

    config = dict(_DEFAULT_CONFIG) if _DEFAULT_CONFIG else {}
    config["provider"] = provider
    if model:
        config["model"] = model

    with TraceContext(target=target, phase=phase) as tc:
        tc.messages = messages
        llm = create_llm(config)
        tc.provider = llm.provider
        tc.model = llm.model
        try:
            resp = llm.chat(
                messages,
                temperature=temperature,
                max_tokens=max_tokens,
                **overrides,
            )
            tc.log(resp, decision=decision)
            flow_id = get_current_flow()
            if flow_id:
                get_stream_manager().emit_llm_call(flow_id, llm.provider, llm.model, phase, resp.latency_ms)
            return resp.content
        except Exception as e:
            tc.error = str(e)
            raise


def get_available_providers() -> List[str]:
    return available_providers()
