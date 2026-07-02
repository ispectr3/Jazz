"""Auto-module loader — descobre e registra todos os ScannerAdapters via importlib + decorator."""

import importlib
import inspect
import os
import pkgutil
import sys
from pathlib import Path
from typing import Any

from app.plugins.base import ScannerAdapter


_REGISTRY: dict[str, type[ScannerAdapter]] = {}
_INSTANCES: dict[str, ScannerAdapter] = {}


def register(name: str | None = None):
    """Decorator para registrar um ScannerAdapter automaticamente."""
    def wrapper(cls: type[ScannerAdapter]):
        key = name or cls.__name__.lower().replace('adapter', '').replace('scanner', '')
        _REGISTRY[key] = cls
        return cls
    return wrapper


def discover(plugins_dir: str | Path | None = None) -> dict[str, type[ScannerAdapter]]:
    """Varre o diretorio de plugins, importa cada modulo e coleta adapters registrados."""
    if plugins_dir is None:
        plugins_dir = Path(__file__).resolve().parent

    plugins_dir = Path(plugins_dir)
    if not plugins_dir.is_dir():
        return {}

    sys.path.insert(0, str(plugins_dir.parent))

    for importer, modname, ispkg in pkgutil.iter_modules([str(plugins_dir)]):
        if modname.startswith('_') or modname == 'base' or modname == 'loader':
            continue
        try:
            module = importlib.import_module(f'app.plugins.{modname}')
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, ScannerAdapter) and obj is not ScannerAdapter
                        and obj not in _REGISTRY.values()):
                    key = modname.replace('_adapter', '').replace('_scanner', '')
                    _REGISTRY[key] = obj
        except Exception as e:
            print(f'[loader] WARN: {modname}: {e}')

    return dict(_REGISTRY)


def get(name: str) -> ScannerAdapter | None:
    """Retorna instancia (singleton) de um adapter pelo nome da chave."""
    if not _INSTANCES:
        if not _REGISTRY:
            discover()
        for key, cls in _REGISTRY.items():
            try:
                _INSTANCES[key] = cls()
            except Exception as e:
                print(f'[loader] WARN: instanciando {key}: {e}')

    if name in _INSTANCES:
        return _INSTANCES[name]

    for key, inst in _INSTANCES.items():
        if name.replace('_', '') in key or key in name.replace('_', ''):
            return inst
    return None


def list_adapters() -> list[dict[str, Any]]:
    """Lista todos os adapters registrados com metadados."""
    if not _REGISTRY:
        discover()
    result = []
    for key, cls in _REGISTRY.items():
        try:
            inst = _INSTANCES.get(key) or cls()
            _INSTANCES[key] = inst
            result.append({'key': key, 'name': inst.name, 'class': cls.__name__})
        except Exception as e:
            result.append({'key': key, 'name': cls.__name__, 'error': str(e)})
    return result
