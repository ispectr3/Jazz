import importlib
import pkgutil
import os

_all_payloads = []
_all_categories = {}

def load_all_payloads():
    global _all_payloads, _all_categories
    _all_payloads = []
    _all_categories = {}
    package_dir = os.path.dirname(__file__)
    for importer, modname, ispkg in pkgutil.iter_modules([package_dir]):
        if modname == "__init__":
            continue
        mod = importlib.import_module(f"pincer_payloads.{modname}")
        payloads = getattr(mod, "PAYLOADS", [])
        turn_chains = getattr(mod, "TURN_CHAINS", [])
        flat_payloads = getattr(mod, "FLAT_PAYLOADS", [])
        combined = payloads + flat_payloads
        _all_payloads.extend(combined)
        for p in combined:
            cat = p.get("category", "uncategorized")
            if cat not in _all_categories:
                _all_categories[cat] = []
            _all_categories[cat].append(p)
    return _all_payloads

def get_all_payloads():
    if not _all_payloads:
        load_all_payloads()
    return _all_payloads

def get_payloads_by_category(category=None):
    if not _all_payloads:
        load_all_payloads()
    if category:
        return _all_categories.get(category, [])
    return _all_categories

def get_categories():
    if not _all_payloads:
        load_all_payloads()
    return list(_all_categories.keys())
