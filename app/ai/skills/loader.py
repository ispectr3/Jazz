import os
import re
from typing import Optional

from app.ai.skills import Skill, get_registry


SKILLS_DIR = os.path.join(os.path.dirname(__file__))


def _parse_frontmatter(content: str) -> tuple[Optional[dict], str]:
    content = content.lstrip("\n")
    if not content.startswith("---"):
        return None, content
    end = content.find("---", 3)
    if end == -1:
        return None, content
    raw = content[3:end].strip()
    body = content[end + 3:].strip()
    meta = {}
    for line in raw.split("\n"):
        line = line.strip()
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if val.startswith("[") and val.endswith("]"):
                val = [v.strip().strip('"').strip("'") for v in val[1:-1].split(",")]
            elif val.startswith(">"):
                continue
            else:
                val = val.strip('"').strip("'")
            meta[key] = val
    return meta, body


def _find_skill_dirs() -> list[str]:
    dirs = []
    for entry in os.listdir(SKILLS_DIR):
        full = os.path.join(SKILLS_DIR, entry)
        if os.path.isdir(full):
            skill_file = os.path.join(full, "SKILL.md")
            if os.path.isfile(skill_file):
                dirs.append(skill_file)
    return dirs


def load_all_skills():
    registry = get_registry()
    skill_files = _find_skill_dirs()
    for filepath in skill_files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            meta, body = _parse_frontmatter(content)
            if not meta or not meta.get("name"):
                continue
            skill = Skill(
                name=meta["name"],
                description=meta.get("description", ""),
                domain=meta.get("domain", "general"),
                subdomain=meta.get("subdomain", ""),
                tags=meta.get("tags", []),
                mitre_attack=meta.get("mitre_attack", []),
                nist_csf=meta.get("nist_csf", []),
                mitre_atlas=meta.get("mitre_atlas", []),
                version=meta.get("version", "1.0"),
                author=meta.get("author", "Jaizz Noir"),
                license=meta.get("license", "Apache-2.0"),
                body=body,
                file_path=filepath,
            )
            registry.register(skill)
        except Exception:
            continue


def load_skills():
    load_all_skills()
    return get_registry()
