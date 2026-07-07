import asyncio
import json
import os
import sqlite3
from collections import defaultdict
from datetime import datetime
from typing import Optional

from app.events import get_stream_manager

RALPH_DIR = ".ralph"
RALPH_PROGRESS = os.path.join(RALPH_DIR, "progress.txt")
RALPH_PLAN = os.path.join(RALPH_DIR, "plan.json")
RALPH_ITERATION = os.path.join(RALPH_DIR, "iteration.txt")
CHECKPOINT_DB = os.path.join(RALPH_DIR, "checkpoint.db")


def _checkpoint_db() -> sqlite3.Connection:
    os.makedirs(RALPH_DIR, exist_ok=True)
    conn = sqlite3.connect(CHECKPOINT_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS checkpoints (
            target TEXT,
            phase TEXT,
            iteration INTEGER,
            data TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_checkpoint
        ON checkpoints(target, phase, iteration)
    """)
    conn.commit()
    return conn


def save_checkpoint(ctx: "PipelineContext", phase_name: str):
    conn = _checkpoint_db()
    data = json.dumps(ctx.to_dict(), default=str)
    conn.execute(
        "INSERT OR REPLACE INTO checkpoints (target, phase, iteration, data) VALUES (?, ?, ?, ?)",
        (ctx.target, phase_name, ctx.iteration, data),
    )
    conn.commit()
    conn.close()


def load_checkpoint(target: str, phase: str, iteration: int) -> Optional[dict]:
    conn = _checkpoint_db()
    row = conn.execute(
        "SELECT data FROM checkpoints WHERE target = ? AND phase = ? AND iteration = ? ORDER BY created_at DESC LIMIT 1",
        (target, phase, iteration),
    ).fetchone()
    conn.close()
    if row:
        return json.loads(row["data"])
    return None


def list_checkpoints(target: Optional[str] = None) -> list[dict]:
    conn = _checkpoint_db()
    if target:
        rows = conn.execute(
            "SELECT target, phase, iteration, created_at FROM checkpoints WHERE target = ? ORDER BY created_at DESC",
            (target,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT target, phase, iteration, created_at FROM checkpoints ORDER BY created_at DESC"
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_checkpoints(target: Optional[str] = None):
    conn = _checkpoint_db()
    if target:
        conn.execute("DELETE FROM checkpoints WHERE target = ?", (target,))
    else:
        conn.execute("DELETE FROM checkpoints")
    conn.commit()
    conn.close()


class PipelineContext:
    def __init__(self, target: str, project_id: int, flow_id: int = 0):
        self.target = target
        self.project_id = project_id
        self.flow_id = flow_id
        self.target_ip = None
        self.domains = []
        self.subdomains = []
        self.ports = []
        self.technologies = []
        self.cves = []
        self.findings = []
        self.web_issues = []
        self.risk_scores = {}
        self.ai_report = None
        self.report_paths = {}
        self.modules_findings = {}
        self.tools_selected = []
        self.ai_analysis = {}
        self.exploitation_guide = []
        self.nist_csf = {}
        self.iteration = 0
        self.max_iterations = 1
        self.ralph_mode = False
        self.scope_validator = None
        self.execution_monitor = None

    def to_dict(self):
        return {
            "target": self.target,
            "target_ip": self.target_ip,
            "domains": self.domains,
            "subdomains": self.subdomains,
            "ports": self.ports,
            "technologies": self.technologies,
            "cves": self.cves[:5],
            "findings": self.findings[:10],
            "risk_scores": self.risk_scores,
            "modules_findings": {
                mod: findings[:10] for mod, findings in self.modules_findings.items()
            },
            "tools_selected": self.tools_selected,
            "ai_analysis": self.ai_analysis,
            "iteration": self.iteration,
        }

    def append_progress(self, text: str, phase: str = ""):
        if self.ralph_mode:
            os.makedirs(RALPH_DIR, exist_ok=True)
            with open(RALPH_PROGRESS, "a") as f:
                f.write(f"[{datetime.now().isoformat()}] {text}\n")
        if self.flow_id:
            get_stream_manager().emit_progress(self.flow_id, text, phase)

    def read_progress(self) -> str:
        if not os.path.exists(RALPH_PROGRESS):
            return ""
        with open(RALPH_PROGRESS) as f:
            return f.read()

    def merge_previous_state(self, prev: "PipelineContext"):
        for key in ("technologies", "cves", "findings", "web_issues", "ports", "domains", "subdomains"):
            prev_val = getattr(prev, key, [])
            cur_val = getattr(self, key, [])
            seen = set()
            merged = []
            for item in prev_val + cur_val:
                if isinstance(item, dict):
                    sig = json.dumps(item, sort_keys=True, default=str)
                else:
                    sig = str(item)
                if sig not in seen:
                    seen.add(sig)
                    merged.append(item)
            setattr(self, key, merged)
        for scalar in ("target_ip",):
            if getattr(prev, scalar, None) and not getattr(self, scalar, None):
                setattr(self, scalar, getattr(prev, scalar))
        self.modules_findings.update(prev.modules_findings)
        if prev.risk_scores:
            self.risk_scores.update(prev.risk_scores)
        if prev.nist_csf:
            self.nist_csf.update(prev.nist_csf)


class PipelinePhase:
    name = ""
    description = ""
    parallel_group: int = 0

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        raise NotImplementedError


class Pipeline:
    def __init__(self):
        self.phases = []

    def add_phase(self, phase: PipelinePhase):
        self.phases.append(phase)
        return self

    async def execute(self, target: str, project_id: int, max_iterations: int = 1, resume: bool = False, flow_id: int = 0) -> PipelineContext:
        combined = PipelineContext(target, project_id, flow_id=flow_id)
        combined.max_iterations = max_iterations
        combined.ralph_mode = max_iterations > 1

        from app.ai.scope_validator import ScopeValidator
        from app.ai.execution_monitor import ExecutionMonitor
        combined.scope_validator = ScopeValidator.from_target(target)
        combined.execution_monitor = ExecutionMonitor.from_env()

        scope_check = combined.scope_validator.is_target_allowed(target)
        if not scope_check[0]:
            raise PermissionError(f"Target fora do escopo: {scope_check[1]}")

        start_iteration = 1
        start_phase_idx = 0

        if resume:
            checkpoints = list_checkpoints(target)
            if checkpoints:
                latest = checkpoints[0]
                start_iteration = latest.get("iteration", 1)
                for i, phase in enumerate(self.phases):
                    if phase.name == latest.get("phase", ""):
                        start_iteration = latest["iteration"]
                        start_phase_idx = i + 1
                        saved = load_checkpoint(target, phase.name, start_iteration)
                        if saved:
                            combined.__dict__.update(saved)
                        combined.append_progress(f"Resumindo da fase {phase.name}, iteracao {start_iteration}")
                        break

        for iteration in range(start_iteration, max_iterations + 1):
            ctx = PipelineContext(target, project_id)
            ctx.iteration = iteration
            ctx.max_iterations = max_iterations
            ctx.ralph_mode = combined.ralph_mode

            phase_start = start_phase_idx if iteration == start_iteration else 0

            if iteration > 1:
                ctx.append_progress(f"Inicio da iteracao {iteration}/{max_iterations}")
                ctx.merge_previous_state(combined)

            groups = defaultdict(list)
            for phase in self.phases[phase_start:]:
                groups[phase.parallel_group].append(phase)

            for group_id in sorted(groups):
                phases_in_group = groups[group_id]
                for p in phases_in_group:
                    if flow_id:
                        get_stream_manager().emit_phase_start(flow_id, p.name)
                    ctx.append_progress(f"Iniciando fase: {p.name}", phase=p.name)
                if len(phases_in_group) == 1:
                    ctx = await phases_in_group[0].run(ctx)
                    save_checkpoint(ctx, phases_in_group[0].name)
                    ctx.append_progress(f"Fase {phases_in_group[0].name} concluida ({len(ctx.findings)} findings)")
                    if flow_id:
                        get_stream_manager().emit_phase_end(flow_id, phases_in_group[0].name, findings=len(ctx.findings))
                else:
                    results = await asyncio.gather(*[p.run(PipelineContext(target, project_id, flow_id=flow_id)) for p in phases_in_group], return_exceptions=True)
                    for phase, result in zip(phases_in_group, results):
                        if isinstance(result, Exception):
                            ctx.append_progress(f"Fase {phase.name} falhou: {result}")
                            if flow_id:
                                get_stream_manager().emit_phase_end(flow_id, phase.name, status="failed")
                        else:
                            ctx.merge_previous_state(result)
                            save_checkpoint(result, phase.name)
                            ctx.append_progress(f"Fase {phase.name} concluida ({len(result.findings)} findings)")
                            if flow_id:
                                get_stream_manager().emit_phase_end(flow_id, phase.name, findings=len(result.findings))

            combined.merge_previous_state(ctx)

            if iteration < max_iterations:
                combined.append_progress(
                    f"Iteracao {iteration} concluida: "
                    f"{len(combined.findings)} findings, "
                    f"{len(combined.cves)} CVEs, "
                    f"{len(combined.technologies)} tecnologias"
                )

        if flow_id:
            get_stream_manager().emit_complete(flow_id, len(combined.findings))
        return combined
