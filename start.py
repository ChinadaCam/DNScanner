#!/usr/bin/env python3
"""Thin entry point so `python3 start.py ...` keeps working.

The real CLI now lives in :mod:`DNScanner.cli`; once installed, the console
command ``dnscanner`` is available too. With no arguments (or ``-m``) this
launches the interactive menu.
"""
from DNScanner.cli import main

if __name__ == "__main__":
    main()
