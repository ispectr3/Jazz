import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.ai.client import Message
from app.ai.skills.loader import load_all_skills
from app.ai.skills import get_registry


AGENT_ROLES = [
    "pentester",
    "searcher",
    "coder",
    "installer",
    "enricher",
    "adviser",
    "reflector",
    "planner",
]

AGENT_SKILL_DOMAINS: Dict[str, List[str]] = {
    "pentester": ["web-application-security", "ai-security"],
    "searcher": [],
    "coder": ["web-application-security"],
    "installer": [],
    "enricher": ["methodology"],
    "adviser": ["methodology", "web-application-security"],
    "reflector": ["methodology"],
    "planner": ["web-application-security", "methodology"],
}

AGENT_SKILL_TAGS: Dict[str, List[str]] = {
    "pentester": ["xss", "injection", "ssrf", "web-security"],
    "searcher": [],
    "coder": ["browser-security", "worker"],
    "installer": [],
    "enricher": ["lessons-learned"],
    "adviser": ["lessons-learned", "methodology"],
    "reflector": ["validation", "lessons-learned"],
    "planner": ["web-security", "methodology"],
}


def _build_skill_augmented_prompt(base: str, role: str) -> str:
    registry = get_registry()
    if registry.count() == 0:
        load_all_skills()
    domains = AGENT_SKILL_DOMAINS.get(role, [])
    tags = AGENT_SKILL_TAGS.get(role, [])
    skills = registry.find_relevant("", domains=domains, tags=tags)
    if not skills:
        return base
    skill_text = registry.format_for_prompt(skills)
    return f"{base}\n\n{skill_text}"


SYSTEM_PROMPTS: Dict[str, str] = {
    "pentester": _build_skill_augmented_prompt(
        "You are a senior penetration testing specialist. You exploit vulnerabilities, "
        "execute attack chains, and validate security findings. "
        "You have deep knowledge of OWASP Top 10, network protocols, and exploitation techniques. "
        "Always provide concrete commands, payloads, and step-by-step instructions. "
        "Focus on practical exploitation, not theoretical vulnerabilities.",
        "pentester",
    ),
    "searcher": (
        "You are an OSINT and reconnaissance specialist. You gather information about targets "
        "from public sources, search engines, and security databases. "
        "You are efficient and thorough, finding relevant CVE data, exploit code, "
        "and technical documentation. Be concise and actionable."
    ),
    "coder": _build_skill_augmented_prompt(
        "You are an exploit developer and script writer. You create proof-of-concept exploits, "
        "custom scripts, and automation tools in Python, Bash, and Go. "
        "Your code is clean, well-structured, and handles errors gracefully. "
        "Always test your code mentally before presenting it.",
        "coder",
    ),
    "installer": (
        "You are a DevSecOps engineer who sets up penetration testing environments. "
        "You install tools, configure Docker containers, manage dependencies, "
        "and ensure the testing infrastructure is ready. "
        "You are methodical and document every step."
    ),
    "enricher": _build_skill_augmented_prompt(
        "You are a security data analyst. You correlate findings, identify patterns, "
        "and provide context for discovered vulnerabilities. "
        "You map findings to MITRE ATT&CK techniques and CWE categories. "
        "You help separate real vulnerabilities from noise.",
        "enricher",
    ),
    "adviser": _build_skill_augmented_prompt(
        "You are a senior security advisor providing strategic guidance. "
        "You review the current state of the penetration test and suggest next steps. "
        "You detect when the agent is stuck in a loop or going down a dead end. "
        "You recommend alternative approaches when the current strategy fails. "
        "Be concise and direct.",
        "adviser",
    ),
    "reflector": _build_skill_augmented_prompt(
        "You are a quality assurance reviewer. You review findings for accuracy, "
        "completeness, and evidence quality. You check for hallucinations, "
        "false positives, and insufficient evidence. "
        "You ensure every finding has actionable remediation guidance. "
        "Be critical and thorough.",
        "reflector",
    ),
    "planner": _build_skill_augmented_prompt(
        "You are a penetration testing strategist. You decompose complex testing goals "
        "into 3-7 specific, actionable steps. Each step targets a specific attack surface "
        "or testing phase. You consider the full attack chain from recon to exploitation "
        "and ensure no critical path is missed.",
        "planner",
    ),
}


@dataclass
class AgentRoleConfig:
    role: str
    model: str
    provider: str = ""
    temperature: float = 0.15
    max_tokens: int = 4096
    description: str = ""


DEFAULT_ROLE_CONFIGS: Dict[str, Dict[str, Any]] = {
    "pentester": {"model": "deepseek-v4-pro", "provider": "free-gateway", "temperature": 0.15, "max_tokens": 8192},
    "searcher": {"model": "deepseek-chat", "provider": "free-gateway", "temperature": 0.1, "max_tokens": 4096},
    "coder": {"model": "deepseek-chat", "provider": "free-gateway", "temperature": 0.1, "max_tokens": 8192},
    "installer": {"model": "llama-3.1-8b-instant", "provider": "groq", "temperature": 0.1, "max_tokens": 4096},
    "enricher": {"model": "llama-3.1-8b-instant", "provider": "groq", "temperature": 0.1, "max_tokens": 4096},
    "adviser": {"model": "deepseek-v4-pro", "provider": "free-gateway", "temperature": 0.3, "max_tokens": 4096},
    "reflector": {"model": "deepseek-chat", "provider": "free-gateway", "temperature": 0.1, "max_tokens": 4096},
    "planner": {"model": "deepseek-v4-pro", "provider": "free-gateway", "temperature": 0.2, "max_tokens": 4096},
}


class AgentRouter:
    def __init__(self, config_overrides: Optional[Dict[str, Dict[str, Any]]] = None):
        self._role_configs: Dict[str, AgentRoleConfig] = {}

        for role in AGENT_ROLES:
            defaults = dict(DEFAULT_ROLE_CONFIGS.get(role, {}))
            overrides = (config_overrides or {}).get(role, {})
            defaults.update(overrides)
            env_prefix = f"AGENT_{role.upper()}_"
            model = os.environ.get(f"{env_prefix}MODEL") or defaults.get("model", "deepseek-chat")
            provider = os.environ.get(f"{env_prefix}PROVIDER") or defaults.get("provider", "")
            temperature = float(os.environ.get(f"{env_prefix}TEMPERATURE") or defaults.get("temperature", 0.15))
            max_tokens = int(os.environ.get(f"{env_prefix}MAX_TOKENS") or defaults.get("max_tokens", 4096))
            self._role_configs[role] = AgentRoleConfig(
                role=role,
                model=model,
                provider=provider,
                temperature=temperature,
                max_tokens=max_tokens,
                description=defaults.get("description", ""),
            )

    def get_config(self, role: str) -> AgentRoleConfig:
        if role not in self._role_configs:
            raise ValueError(f"Unknown agent role '{role}'. Available: {list(self._role_configs.keys())}")
        return self._role_configs[role]

    def chat(
        self,
        role: str,
        messages: List[Message],
        *,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> str:
        cfg = self.get_config(role)
        from app.ai.llm import chat_with

        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}] + messages

        provider = cfg.provider or "auto"

        return chat_with(
            messages,
            provider=provider,
            model=cfg.model,
            temperature=temperature if temperature is not None else cfg.temperature,
            max_tokens=max_tokens if max_tokens is not None else cfg.max_tokens,
            response_format=response_format,
            **kwargs,
        )

    def chat_for_agent(
        self,
        role: str,
        messages: List[Message],
        **kwargs: Any,
    ) -> str:
        prompt = SYSTEM_PROMPTS.get(role, "")
        return self.chat(role, messages, system_prompt=prompt, **kwargs)

    def get_system_prompt(self, role: str) -> str:
        return SYSTEM_PROMPTS.get(role, "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            role: {
                "model": cfg.model,
                "provider": cfg.provider or "auto",
                "temperature": cfg.temperature,
                "max_tokens": cfg.max_tokens,
            }
            for role, cfg in self._role_configs.items()
        }


_global_router: Optional[AgentRouter] = None


def get_router() -> AgentRouter:
    global _global_router
    if _global_router is None:
        _global_router = AgentRouter()
    return _global_router


class BaseAgent:
    role: str = ""

    def __init__(self, router: Optional[AgentRouter] = None):
        self._router = router or get_router()

    @property
    def config(self) -> AgentRoleConfig:
        return self._router.get_config(self.role)

    @property
    def system_prompt(self) -> str:
        return SYSTEM_PROMPTS.get(self.role, "")

    def chat(
        self,
        messages: List[Message],
        *,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> str:
        return self._router.chat_for_agent(
            self.role,
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
            **kwargs,
        )


class PentesterAgent(BaseAgent):
    role = "pentester"


class SearcherAgent(BaseAgent):
    role = "searcher"


class CoderAgent(BaseAgent):
    role = "coder"


class InstallerAgent(BaseAgent):
    role = "installer"


class EnricherAgent(BaseAgent):
    role = "enricher"


class AdviserAgent(BaseAgent):
    role = "adviser"


class ReflectorAgent(BaseAgent):
    role = "reflector"


class PlannerAgent(BaseAgent):
    role = "planner"
