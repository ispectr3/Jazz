import json
import time
import os
from collections import defaultdict
from flask import current_app
from flask.sessions import SessionMixin

LANGFUSE_ENABLED = bool(os.environ.get("LANGFUSE_SECRET_KEY"))


def get_langfuse():
    if not LANGFUSE_ENABLED:
        return None
    try:
        from langfuse import Langfuse
        return Langfuse(
            secret_key=os.environ["LANGFUSE_SECRET_KEY"],
            public_key=os.environ.get("LANGFUSE_PUBLIC_KEY", ""),
            host=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        )
    except Exception:
        return None


_langfuse_client = None


def langfuse():
    global _langfuse_client
    if _langfuse_client is None:
        _langfuse_client = get_langfuse()
    return _langfuse_client


class StreamManager:
    def __init__(self):
        self._sockets: dict[int, list] = defaultdict(list)

    def subscribe(self, flow_id: int, ws):
        self._sockets[flow_id].append(ws)

    def unsubscribe(self, flow_id: int, ws):
        try:
            self._sockets[flow_id].remove(ws)
            if not self._sockets[flow_id]:
                del self._sockets[flow_id]
        except (ValueError, KeyError):
            pass

    def broadcast(self, flow_id: int, event_type: str, data: dict):
        payload = json.dumps({"type": event_type, "data": data, "ts": time.time()})
        stale = []
        for ws in self._sockets.get(flow_id, []):
            try:
                ws.send(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.unsubscribe(flow_id, ws)

    def emit_progress(self, flow_id: int, message: str, phase: str = ""):
        self.broadcast(flow_id, "progress", {"message": message, "phase": phase})

    def emit_phase_start(self, flow_id: int, phase: str):
        self.broadcast(flow_id, "phase_start", {"phase": phase})

    def emit_phase_end(self, flow_id: int, phase: str, status: str = "completed", findings: int = 0):
        self.broadcast(flow_id, "phase_end", {"phase": phase, "status": status, "findings": findings})

    def emit_llm_call(self, flow_id: int, provider: str, model: str, phase: str, latency_ms: float = 0):
        self.broadcast(flow_id, "llm_call", {"provider": provider, "model": model, "phase": phase, "latency_ms": latency_ms})

    def emit_tool_call(self, flow_id: int, tool: str, target: str, status: str = "running"):
        self.broadcast(flow_id, "tool_call", {"tool": tool, "target": target, "status": status})

    def emit_finding(self, flow_id: int, title: str, severity: str, source: str):
        self.broadcast(flow_id, "finding", {"title": title, "severity": severity, "source": source})

    def emit_error(self, flow_id: int, error: str, phase: str = ""):
        self.broadcast(flow_id, "error", {"error": error, "phase": phase})

    def emit_complete(self, flow_id: int, findings_count: int):
        self.broadcast(flow_id, "complete", {"findings_count": findings_count})


_stream_manager: StreamManager | None = None


def get_stream_manager() -> StreamManager:
    global _stream_manager
    if _stream_manager is None:
        _stream_manager = StreamManager()
    return _stream_manager
