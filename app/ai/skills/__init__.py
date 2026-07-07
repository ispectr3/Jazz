from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Skill:
    name: str
    description: str
    domain: str
    subdomain: str
    tags: List[str]
    mitre_attack: List[str]
    nist_csf: List[str]
    mitre_atlas: List[str]
    version: str
    author: str
    license: str
    body: str
    file_path: str = ""


class SkillRegistry:
    def __init__(self):
        self._skills: Dict[str, Skill] = {}
        self._domain_index: Dict[str, List[str]] = {}
        self._tag_index: Dict[str, List[str]] = {}

    def register(self, skill: Skill):
        self._skills[skill.name] = skill
        self._domain_index.setdefault(skill.domain, []).append(skill.name)
        for tag in skill.tags:
            self._tag_index.setdefault(tag.lower(), []).append(skill.name)

    def get(self, name: str) -> Optional[Skill]:
        return self._skills.get(name)

    def list_all(self) -> List[Skill]:
        return list(self._skills.values())

    def list_names(self) -> List[str]:
        return list(self._skills.keys())

    def filter_by_domain(self, domain: str) -> List[Skill]:
        names = self._domain_index.get(domain, [])
        return [self._skills[n] for n in names]

    def filter_by_tag(self, tag: str) -> List[Skill]:
        names = self._tag_index.get(tag.lower(), [])
        return [self._skills[n] for n in names]

    def filter_by_mitre(self, technique: str) -> List[Skill]:
        return [s for s in self._skills.values() if technique in s.mitre_attack]

    def find_relevant(self, context: str, domains: Optional[List[str]] = None, tags: Optional[List[str]] = None) -> List[Skill]:
        scored = []
        context_lower = context.lower()
        for skill in self._skills.values():
            score = 0
            if domains and skill.domain in domains:
                score += 3
            if tags:
                for t in tags:
                    if t.lower() in skill.tags:
                        score += 2
            if context_lower and (skill.name.lower() in context_lower or any(t in context_lower for t in skill.tags)):
                score += 1
            if score > 0:
                scored.append((score, skill))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:5]]

    def format_for_prompt(self, skills: List[Skill]) -> str:
        if not skills:
            return ""
        parts = ["## Active Skills\n"]
        for s in skills:
            parts.append(f"### {s.name}")
            parts.append(f"Domain: {s.domain}/{s.subdomain}")
            if s.mitre_attack:
                parts.append(f"MITRE ATT&CK: {', '.join(s.mitre_attack)}")
            parts.append("")
            parts.append(s.body[:2000])
            parts.append("")
        return "\n".join(parts)

    def count(self) -> int:
        return len(self._skills)


_global_registry: Optional[SkillRegistry] = None


def get_registry() -> SkillRegistry:
    global _global_registry
    if _global_registry is None:
        _global_registry = SkillRegistry()
    return _global_registry
