"""Removes local filesystem paths from text that is returned to API clients."""
import os
import re
from pathlib import Path

_REPO = str(Path(__file__).resolve().parent.parent)
_HOME = str(Path.home())
_WINDOWS_PATH = re.compile(r"[A-Za-z]:\\(?:[^\\\s'\"<>|]+\\)*")


def redact(text: str) -> str:
    """Replaces the repository root, the home directory and other absolute Windows directories."""
    if not text:
        return text
    for root, label in ((_REPO, "<repo>"), (_HOME, "<home>")):
        for variant in {root, root.replace("\\", "/"), root.replace("\\", "\\\\")}:
            text = text.replace(variant, label)
    return _WINDOWS_PATH.sub("<path>\\\\", text) if os.name == "nt" else text
