"""Backward-compatibility shim.

Historically callers imported the class with
``from DNScanner.DNScanner import DNScanner``. The engine now lives in
:mod:`DNScanner.engine` (no import-time side effects); this module simply
re-exports it so existing imports keep working.
"""
from DNScanner.engine import DNScanner

__all__ = ["DNScanner"]


if __name__ == "__main__":
    pass
