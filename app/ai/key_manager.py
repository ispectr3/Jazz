import json
import os
import re
import time
import urllib.request
from typing import Dict, List, Optional

CACHE_FILE = os.path.join(".ralph", "free_keys.json")
CACHE_TTL = 3600
RAW_URL = "https://raw.githubusercontent.com/alistaitsacle/free-llm-api-keys/main/README.md"

KEY_PATTERN = re.compile(r"`(sk-[A-Za-z0-9]{40,})`\s*\|\s*`?([a-z0-9][a-z0-9/._:-]+)`?")


def _fetch_readme() -> Optional[str]:
    try:
        req = urllib.request.Request(RAW_URL, headers={"User-Agent": "JazzNoir/1.0"})
        resp = urllib.request.urlopen(req, timeout=15)
        return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return None


def _parse_keys(text: str) -> List[Dict[str, str]]:
    keys = []
    seen = set()

    in_table = False
    for line in text.split("\n"):
        line_stripped = line.strip()

        if line_stripped.startswith("| `sk-"):
            in_table = True
            parts = [p.strip().strip("`") for p in line_stripped.split("|")]
            if len(parts) >= 3:
                key = parts[1] if parts[1].startswith("sk-") else ""
                model = parts[2]
                if key and key not in seen:
                    seen.add(key)
                    budget = parts[4] if len(parts) > 4 else ""
                    expires = parts[6] if len(parts) > 6 else ""
                    keys.append({
                        "key": key,
                        "model": model,
                        "budget": budget,
                        "expires": expires,
                    })
        elif in_table and not line_stripped.startswith("|"):
            in_table = False

    for match in KEY_PATTERN.finditer(text):
        key = match.group(1)
        model = match.group(2)
        if key not in seen:
            seen.add(key)
            keys.append({
                "key": key,
                "model": model,
                "budget": "",
                "expires": "",
            })

    return keys


def fetch_keys(force: bool = False) -> List[Dict[str, str]]:
    if not force:
        cached = _load_cache()
        if cached:
            return cached
    text = _fetch_readme()
    if not text:
        cached = _load_cache()
        return cached or []
    keys = _parse_keys(text)
    _save_cache(keys)
    return keys


def get_key_for_model(model: str, force_refresh: bool = False) -> Optional[str]:
    keys = fetch_keys(force=force_refresh)
    for k in keys:
        if k["model"].lower() == model.lower():
            return k["key"]
    return None


def get_best_key(models: List[str] = None) -> Optional[str]:
    keys = fetch_keys()
    if not keys:
        return None
    model_priority = [m.lower() for m in (models or ["deepseek-chat", "deepseek-v4-pro", "smart-chat", "gemini-2.5-flash"])]
    for mp in model_priority:
        for k in keys:
            if k["model"].lower() == mp:
                return k["key"]
    return keys[0]["key"]


def available_models() -> List[str]:
    keys = fetch_keys()
    return list({k["model"] for k in keys})


def _cache_path() -> str:
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    return CACHE_FILE


def _save_cache(keys: List[Dict[str, str]]):
    data = {
        "timestamp": time.time(),
        "keys": keys,
    }
    with open(_cache_path(), "w") as f:
        json.dump(data, f)


def _load_cache() -> Optional[List[Dict[str, str]]]:
    path = _cache_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            data = json.load(f)
        if time.time() - data.get("timestamp", 0) > CACHE_TTL:
            return None
        return data.get("keys", [])
    except Exception:
        return None
