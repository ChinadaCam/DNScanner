#!/usr/bin/env python3
"""Thin entry point so `python3 menu.py` keeps working.

The interactive menu now lives in :mod:`DNScanner.menu`.
"""
import sys

from DNScanner.menu import run_menu

if __name__ == "__main__":
    run_menu(sys.argv[1] if len(sys.argv) > 1 else None)
