import json
import os
import sqlite3
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

TRACER_DB = os.path.join(".ralph", "traces.db")

# Langfuse — only init if env var is set
_lf = None


def _get_langfuse():
    global _lf
    if _lf is not None:
        return _lf
    if not os.environ.get("LANGFUSE_SECRET_KEY"):
        _lf = False
        return None
    try:
        from langfuse import Langfuse
        _lf = Langfuse(
            secret_key=os.environ["LANGFUSE_SECRET_KEY"],
            public_key=os.environ.get("LANGFUSE_PUBLIC_KEY", ""),
            host=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        )
        return _lf
    except Exception:
        _lf = False
        return None


def _db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(TRACER_DB), exist_ok=True)
    conn = sqlite3.connect(TRACER_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS traces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            phase TEXT,
            provider TEXT,
            model TEXT,
            prompt_preview TEXT,
            response_preview TEXT,
            full_prompt TEXT,
            full_response TEXT,
            prompt_tokens INTEGER DEFAULT 0,
            completion_tokens INTEGER DEFAULT 0,
            latency_ms REAL DEFAULT 0,
            decision TEXT,
            source_validation TEXT,
            success INTEGER DEFAULT 1,
            error TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    return conn


def trace_llm(
    *,
    target: str = "",
    phase: str = "",
    provider: str = "",
    model: str = "",
    messages: List[Dict[str, str]],
    response: str = "",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    latency_ms: float = 0.0,
    decision: str = "",
    source_validation: str = "",
    success: bool = True,
    error: str = "",
):
    full_prompt = json.dumps(messages, ensure_ascii=False)
    prompt_text = "\n".join(m.get("content", "") for m in messages if m.get("role") == "user")
    conn = _db()
    conn.execute(
        """INSERT INTO traces
           (target, phase, provider, model, prompt_preview, response_preview,
            full_prompt, full_response, prompt_tokens, completion_tokens,
            latency_ms, decision, source_validation, success, error)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            target[:100],
            phase[:50],
            provider,
            model,
            prompt_text[:500],
            response[:500],
            full_prompt,
            response,
            prompt_tokens,
            completion_tokens,
            round(latency_ms, 1),
            decision[:1000],
            source_validation[:500],
            1 if success else 0,
            error[:500] if error else None,
        ),
    )
    conn.commit()
    conn.close()


def get_traces(
    target: Optional[str] = None,
    phase: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> List[dict]:
    conn = _db()
    query = "SELECT * FROM traces WHERE 1=1"
    params = []
    if target:
        query += " AND target = ?"
        params.append(target)
    if phase:
        query += " AND phase = ?"
        params.append(phase)
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_trace_stats(target: Optional[str] = None) -> dict:
    conn = _db()
    where = "WHERE target = ?" if target else ""
    params = [target] if target else []
    row = conn.execute(
        f"""SELECT
            COUNT(*) as total_calls,
            SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_calls,
            SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as error_calls,
            ROUND(AVG(latency_ms), 1) as avg_latency_ms,
            ROUND(AVG(prompt_tokens + completion_tokens), 1) as avg_tokens,
            COUNT(DISTINCT provider) as providers_used,
            COUNT(DISTINCT model) as models_used
        FROM traces {where}""",
        params,
    ).fetchone()
    conn.close()
    return dict(row) if row else {}


class TraceContext:
    def __init__(self, target: str = "", phase: str = ""):
        self.target = target
        self.phase = phase
        self.start = time.time()
        self.provider = ""
        self.model = ""
        self.messages = []
        self.response = ""
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.decision = ""
        self.source_validation = ""
        self.success = True
        self.error = ""

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = (time.time() - self.start) * 1000
        if exc_type:
            self.success = False
            self.error = str(exc_val)
        trace_llm(
            target=self.target,
            phase=self.phase,
            provider=self.provider,
            model=self.model,
            messages=self.messages,
            response=self.response,
            prompt_tokens=self.prompt_tokens,
            completion_tokens=self.completion_tokens,
            latency_ms=elapsed,
            decision=self.decision,
            source_validation=self.source_validation,
            success=self.success,
            error=self.error,
        )
        self._langfuse_trace(elapsed)

    def _langfuse_trace(self, elapsed_ms: float):
        lf = _get_langfuse()
        if not lf:
            return
        try:
            generation = lf.generation(
                name=self.phase or "llm_call",
                model=self.model,
                model_parameters={"provider": self.provider, "temperature": 0.15},
                input=self.messages,
                output=self.response,
                usage={
                    "input": self.prompt_tokens,
                    "output": self.completion_tokens,
                    "unit": "TOKENS",
                },
                latency=elapsed_ms / 1000,
            )
            if not self.success:
                generation.end(
                    level="ERROR",
                    status_message=self.error[:500] if self.error else "Unknown error",
                )
            else:
                generation.end()
        except Exception:
            pass

    def log(self, response_obj=None, decision: str = ""):
        if response_obj:
            self.response = getattr(response_obj, 'content', str(response_obj))
            self.prompt_tokens = getattr(response_obj, 'prompt_tokens', 0)
            self.completion_tokens = getattr(response_obj, 'completion_tokens', 0)
            self.provider = getattr(response_obj, 'provider', getattr(response_obj, 'model', ''))
            self.model = getattr(response_obj, 'model', '')
        if decision:
            self.decision = decision
