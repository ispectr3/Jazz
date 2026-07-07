import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

SUMMARIZER_DB = os.path.join(".ralph", "summarizer.db")


def _db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(SUMMARIZER_DB), exist_ok=True)
    conn = sqlite3.connect(SUMMARIZER_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS qa_pairs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            phase TEXT,
            iteration INTEGER DEFAULT 1,
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            tokens INTEGER DEFAULT 0,
            source TEXT DEFAULT 'llm',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS context_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            iteration INTEGER DEFAULT 1,
            summary TEXT NOT NULL,
            token_count INTEGER DEFAULT 0,
            qa_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_qa_flow
        ON qa_pairs(flow_id, iteration)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_summary_flow
        ON context_summaries(flow_id, iteration)
    """)
    conn.commit()
    return conn


def save_qa(
    flow_id: int,
    question: str,
    answer: str,
    phase: str = "",
    iteration: int = 1,
    tokens: int = 0,
    source: str = "llm",
):
    conn = _db()
    conn.execute(
        "INSERT INTO qa_pairs (flow_id, phase, iteration, question, answer, tokens, source) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (flow_id, phase, iteration, question[:2000], answer[:5000], tokens, source),
    )
    conn.commit()
    conn.close()


def get_qa_history(
    flow_id: int,
    iteration: Optional[int] = None,
    limit: int = 50,
) -> List[dict]:
    conn = _db()
    query = "SELECT * FROM qa_pairs WHERE flow_id = ?"
    params = [flow_id]
    if iteration:
        query += " AND iteration = ?"
        params.append(iteration)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_context_summary(flow_id: int, iteration: int) -> Optional[dict]:
    conn = _db()
    row = conn.execute(
        "SELECT * FROM context_summaries WHERE flow_id = ? AND iteration = ? ORDER BY created_at DESC LIMIT 1",
        (flow_id, iteration),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


class SummarizerQA:
    def __init__(self, flow_id: int, max_tokens: int = 4000):
        self.flow_id = flow_id
        self.max_tokens = max_tokens
        self._qa_cache: List[dict] = []

    def record(self, question: str, answer: str, phase: str = "", iteration: int = 1, tokens: int = 0):
        save_qa(self.flow_id, question, answer, phase, iteration, tokens)
        self._qa_cache.append({
            "question": question,
            "answer": answer,
            "phase": phase,
            "iteration": iteration,
            "tokens": tokens,
        })

    def build_context(self, iteration: int = 1) -> str:
        ctx = get_context_summary(self.flow_id, iteration - 1) if iteration > 1 else None
        qa_list = get_qa_history(self.flow_id, iteration, limit=20)

        parts = []
        if ctx:
            parts.append(f"[Context Summary from iteration {iteration - 1}]\n{ctx['summary']}")

        if qa_list:
            parts.append(f"[QA History for iteration {iteration}]")
            for qa in reversed(qa_list):
                parts.append(f"Q: {qa['question']}")
                parts.append(f"A: {qa['answer'][:500]}")

        return "\n\n".join(parts)

    def summarize_context(self, iteration: int) -> str:
        qa_list = get_qa_history(self.flow_id, iteration, limit=100)
        if not qa_list:
            return ""

        summary = (
            f"Pipeline iteration {iteration}: "
            f"{len(qa_list)} QA pairs recorded. "
            f"Phases: {', '.join(set(q['phase'] for q in qa_list if q['phase']))}."
        )

        conn = _db()
        conn.execute(
            "INSERT INTO context_summaries (flow_id, iteration, summary, token_count, qa_count) VALUES (?, ?, ?, ?, ?)",
            (self.flow_id, iteration, summary[:5000], 0, len(qa_list)),
        )
        conn.commit()
        conn.close()
        return summary


def summarize_flow(flow_id: int, iteration: int = 1) -> str:
    summarizer = SummarizerQA(flow_id)
    return summarizer.summarize_context(iteration)


def get_flow_context(flow_id: int, iteration: int = 1, include_summary: bool = True) -> str:
    summarizer = SummarizerQA(flow_id)
    return summarizer.build_context(iteration)
