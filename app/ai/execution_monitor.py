import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ToolCallRecord:
    tool_name: str
    tool_input: str
    success: bool
    timestamp: float
    duration_ms: int = 0


@dataclass
class MonitorState:
    total_calls: int = 0
    consecutive_failures: int = 0
    tool_call_history: List[ToolCallRecord] = field(default_factory=list)
    same_tool_count: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    last_intervention: Optional[str] = None
    intervention_count: int = 0

    def record_tool_call(self, tool_name: str, tool_input: str, success: bool, duration_ms: int = 0):
        self.total_calls += 1
        self.tool_call_history.append(ToolCallRecord(
            tool_name=tool_name,
            tool_input=tool_input,
            success=success,
            timestamp=datetime.now().timestamp(),
            duration_ms=duration_ms,
        ))
        if success:
            self.consecutive_failures = 0
            self.same_tool_count[tool_name] = self.same_tool_count.get(tool_name, 0) + 1
        else:
            self.consecutive_failures += 1

    def get_identical_tool_calls(self, tool_name: str, tool_input: str) -> int:
        count = 0
        for record in reversed(self.tool_call_history):
            if record.tool_name == tool_name and record.tool_input == tool_input:
                count += 1
            else:
                break
        return count


class ExecutionMonitor:
    def __init__(
        self,
        max_same_tool_calls: int = 5,
        max_total_tool_calls: int = 50,
        max_consecutive_failures: int = 3,
        max_identical_calls: int = 3,
        enabled: bool = True,
    ):
        self.max_same_tool_calls = max_same_tool_calls
        self.max_total_tool_calls = max_total_tool_calls
        self.max_consecutive_failures = max_consecutive_failures
        self.max_identical_calls = max_identical_calls
        self.enabled = enabled

        self._states: Dict[str, MonitorState] = defaultdict(MonitorState)

    @classmethod
    def from_env(cls):
        return cls(
            max_same_tool_calls=int(os.environ.get("MONITOR_MAX_SAME_TOOL_CALLS", "5")),
            max_total_tool_calls=int(os.environ.get("MONITOR_MAX_TOTAL_TOOL_CALLS", "50")),
            max_consecutive_failures=int(os.environ.get("MONITOR_MAX_CONSECUTIVE_FAILURES", "3")),
            max_identical_calls=int(os.environ.get("MONITOR_MAX_IDENTICAL_CALLS", "3")),
            enabled=os.environ.get("MONITOR_ENABLED", "true").lower() == "true",
        )

    def get_state(self, agent_id: str) -> MonitorState:
        return self._states[agent_id]

    def reset_state(self, agent_id: str):
        self._states.pop(agent_id, None)

    def check_tool_call(self, agent_id: str, tool_name: str, tool_input: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        state = self._states[agent_id]

        if state.total_calls >= self.max_total_tool_calls:
            return {
                "action": "stop",
                "reason": f"tool_call_limit",
                "message": f"Limite de {self.max_total_tool_calls} chamadas de ferramenta excedido.",
                "suggestion": "Consolidar descobertas e finalizar. Revisar resultados obtidos até agora.",
            }

        if state.consecutive_failures >= self.max_consecutive_failures:
            state.intervention_count += 1
            return {
                "action": "redirect",
                "reason": "consecutive_failures",
                "message": f"{state.consecutive_failures} falhas consecutivas detectadas.",
                "suggestion": "Tentar abordagem diferente. Verificar conectividade com o alvo ou usar ferramenta alternativa.",
            }

        same_tool = state.same_tool_count.get(tool_name, 0)
        if same_tool >= self.max_same_tool_calls:
            state.intervention_count += 1
            return {
                "action": "redirect",
                "reason": "same_tool_repetition",
                "message": f"Ferramenta '{tool_name}' chamada {same_tool} vezes.",
                "suggestion": f"Resultados de '{tool_name}' ja coletados. Tentar ferramenta diferente ou avancar para proxima etapa.",
            }

        identical = state.get_identical_tool_calls(tool_name, tool_input)
        if identical >= self.max_identical_calls:
            state.intervention_count += 1
            return {
                "action": "skip",
                "reason": "identical_call",
                "message": f"Chamada identica a '{tool_name}' repetida {identical} vezes.",
                "suggestion": "Comando ja foi executado. Avancar sem repetir.",
            }

        return None

    def record_result(self, agent_id: str, tool_name: str, tool_input: str, success: bool, duration_ms: int = 0):
        if not self.enabled:
            return
        state = self._states[agent_id]
        state.record_tool_call(tool_name, tool_input, success, duration_ms)

    def get_summary(self, agent_id: str) -> Dict[str, Any]:
        state = self._states.get(agent_id)
        if not state:
            return {"total_calls": 0, "interventions": 0}

        return {
            "total_calls": state.total_calls,
            "consecutive_failures": state.consecutive_failures,
            "interventions": state.intervention_count,
            "tool_breakdown": dict(state.same_tool_count),
        }

    def get_all_summaries(self) -> Dict[str, Any]:
        return {
            agent_id: self.get_summary(agent_id)
            for agent_id in self._states
        }
