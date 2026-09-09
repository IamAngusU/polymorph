from __future__ import annotations

import os
from pathlib import Path


def data_home() -> Path:
    override = os.environ.get("POLYMORPH_HOME") or os.environ.get("ANGUSU_BRIDGE_HOME")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        base = Path(local) if local else Path.home() / "AppData" / "Local"
        preferred = base / "Polymorph"
        legacy = base / "Angusu" / "Bridge"
        return legacy if legacy.exists() and not preferred.exists() else preferred
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    preferred = base / "polymorph"
    legacy = base / "angusu-bridge"
    return legacy if legacy.exists() and not preferred.exists() else preferred


def model_home(profile: str) -> Path:
    return data_home() / "models" / profile


def recipe_store_path() -> Path:
    return data_home() / "recipes.sqlite"
