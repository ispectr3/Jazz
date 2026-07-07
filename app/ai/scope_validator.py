import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


SCOPE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<engagement_scope>
  <client>
    <name>{client_name}</name>
    <authorizer>{authorizer}</authorizer>
  </client>

  <targets>
    <allowed>
      <domain>{target_domain}</domain>
    </allowed>
    <forbidden>
      <!-- <domain>example.com</domain> -->
    </forbidden>
  </targets>

  <rules_of_engagement>
    <forbidden_actions>
      <action>social_engineering</action>
      <action>denial_of_service</action>
      <action>data_exfiltration</action>
      <action>phishing</action>
      <action>physical_access</action>
    </forbidden_actions>
    <allowed_techniques>
      <technique>reconnaissance</technique>
      <technique>vulnerability_scanning</technique>
      <technique>exploitation</technique>
      <technique>post_exploitation</technique>
    </allowed_techniques>
  </rules_of_engagement>

  <constraints>
    <rate_limit>10</rate_limit>
    <max_concurrent_tasks>3</max_concurrent_tasks>
    <max_duration_hours>8</max_duration_hours>
    <time_window>09:00-18:00</time_window>
    <timezone>UTC</timezone>
  </constraints>

  <stop_conditions>
    <condition>admin_access_obtained</condition>
    <condition>customer_data_accessed</condition>
    <condition>critical_system_compromised</condition>
  </stop_conditions>

  <evidence_requirements>
    <format>screenshot</format>
    <format>command_output</format>
    <format>tool_log</format>
    <format>network_capture</format>
  </evidence_requirements>
</engagement_scope>
"""


@dataclass
class ScopeConfig:
    client_name: str = ""
    authorizer: str = ""
    allowed_domains: Set[str] = field(default_factory=set)
    allowed_ips: List[str] = field(default_factory=list)
    forbidden_domains: Set[str] = field(default_factory=set)
    forbidden_actions: Set[str] = field(default_factory=lambda: {
        "social_engineering", "denial_of_service", "data_exfiltration",
        "phishing", "physical_access",
    })
    allowed_techniques: Set[str] = field(default_factory=lambda: {
        "reconnaissance", "vulnerability_scanning", "exploitation",
    })
    rate_limit: int = 10
    max_concurrent_tasks: int = 3
    max_duration_hours: int = 8
    time_window: str = "09:00-18:00"
    timezone: str = "UTC"
    stop_conditions: Set[str] = field(default_factory=lambda: {
        "admin_access_obtained", "customer_data_accessed",
    })


class ScopeValidator:
    def __init__(self, config: Optional[ScopeConfig] = None):
        self.config = config or ScopeConfig()
        self._action_log: List[Tuple[str, str, float]] = []

    @classmethod
    def from_target(cls, target: str) -> "ScopeValidator":
        parsed = urlparse(target)
        domain = parsed.hostname or target
        config = ScopeConfig(
            client_name=domain,
            authorizer="auto",
            allowed_domains={domain},
        )
        return cls(config)

    def is_target_allowed(self, target: str) -> Tuple[bool, str]:
        parsed = urlparse(target)
        hostname = parsed.hostname or target

        if self.config.forbidden_domains:
            for fd in self.config.forbidden_domains:
                if hostname == fd or hostname.endswith("." + fd):
                    return False, f"Dominio '{hostname}' esta na lista de proibidos"

        if not self.config.allowed_domains:
            return True, ""

        for ad in self.config.allowed_domains:
            if hostname == ad or hostname.endswith("." + ad):
                return True, ""

        return False, f"Dominio '{hostname}' nao esta na lista de permitidos"

    def is_action_allowed(self, action: str) -> Tuple[bool, str]:
        action_key = action.lower().replace(" ", "_")
        if action_key in self.config.forbidden_actions:
            return False, f"Acao '{action}' esta proibida pelo escopo"
        return True, ""

    def is_rate_limited(self) -> Tuple[bool, float]:
        import time
        now = time.time()
        window = 60.0
        recent = [t for _, _, t in self._action_log if now - t < window]
        if len(recent) >= self.config.rate_limit:
            wait = window - (now - recent[0])
            return True, wait
        return False, 0.0

    def log_action(self, tool: str, target: str):
        import time
        self._action_log.append((tool, target, time.time()))

    def validate_tool_execution(self, tool_name: str, tool_target: str, tool_action: str = "") -> Optional[Dict]:
        allowed_target, reason = self.is_target_allowed(tool_target)
        if not allowed_target:
            return {"allowed": False, "reason": reason, "action": "block"}

        if tool_action:
            allowed_action, reason = self.is_action_allowed(tool_action)
            if not allowed_action:
                return {"allowed": False, "reason": reason, "action": "block"}

        limited, wait = self.is_rate_limited()
        if limited:
            return {"allowed": False, "reason": f"rate_limit (wait {wait:.0f}s)", "action": "delay", "wait_seconds": wait}

        self.log_action(tool_name, tool_target)
        return {"allowed": True}

    def generate_scope_xml(self) -> str:
        domain = next(iter(self.config.allowed_domains), "target.example.com")
        return SCOPE_TEMPLATE.format(
            client_name=self.config.client_name or domain,
            authorizer=self.config.authorizer or "auto",
            target_domain=domain,
        )

    def to_dict(self) -> Dict:
        return {
            "client_name": self.config.client_name,
            "allowed_domains": list(self.config.allowed_domains),
            "forbidden_domains": list(self.config.forbidden_domains),
            "forbidden_actions": list(self.config.forbidden_actions),
            "allowed_techniques": list(self.config.allowed_techniques),
            "rate_limit": self.config.rate_limit,
            "max_concurrent_tasks": self.config.max_concurrent_tasks,
            "max_duration_hours": self.config.max_duration_hours,
            "actions_logged": len(self._action_log),
        }
