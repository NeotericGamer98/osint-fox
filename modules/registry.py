import importlib
import inspect
import os
import pkgutil

from modules.base import OSINTModule, ModuleMeta


_registry = {}


def register(meta):
    _registry[meta.name] = meta


def get_module(name):
    meta = _registry.get(name)
    if meta:
        return meta.module_class()
    return None


def get_all_metas():
    return list(_registry.values())


def discover_modules():
    pkg_dir = os.path.dirname(__file__)
    plugins_dir = os.path.join(pkg_dir, "plugins")
    for importer, modname, ispkg in pkgutil.iter_modules([pkg_dir]):
        if modname.startswith("_") or modname == "registry":
            continue
        try:
            module = importlib.import_module(f"modules.{modname}")
            _scan_module(module)
        except Exception:
            pass
    if os.path.isdir(plugins_dir):
        syspath_snapshot = list(__import__("sys").path)
        if plugins_dir not in __import__("sys").path:
            __import__("sys").path.insert(0, plugins_dir)
        for importer, modname, ispkg in pkgutil.iter_modules([plugins_dir]):
            if modname.startswith("_"):
                continue
            try:
                module = importlib.import_module(modname)
                _scan_module(module)
            except Exception:
                pass
        __import__("sys").path = syspath_snapshot


def _scan_module(module):
    for name, obj in inspect.getmembers(module):
        if (inspect.isclass(obj) and issubclass(obj, OSINTModule)
                and obj is not OSINTModule):
            meta_attr = getattr(obj, "_meta", None)
            if meta_attr:
                register(meta_attr)
            else:
                inst = obj()
                meta = ModuleMeta(
                    name=inst.name,
                    icon=getattr(inst, "icon", "\u2699"),
                    description=getattr(inst, "description", ""),
                    module_class=obj,
                    inputs=["text"]
                )
                register(meta)


def builtin_meta(name, icon, description, inputs=None):
    def decorator(cls):
        cls._meta = ModuleMeta(name, icon, description, cls, inputs or ["text"])
        return cls
    return decorator
