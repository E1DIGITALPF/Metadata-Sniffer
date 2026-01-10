#!/usr/bin/env python3
"""
Helper script to list folders and get their IDs
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'src'))

from helpers import list_folders

if __name__ == '__main__':
    list_folders()
