# tests/conftest.py
"""
Ajoute la racine du projet au sys.path pour que les imports
(detector, blocker, counter...) fonctionnent depuis tests/.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))