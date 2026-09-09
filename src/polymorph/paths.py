from __future__ import annotations

import os
from pathlib import Path


def data_home() -> Path:
    override = os.environ.get("ANGUSU_BRIDGE_HOME")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "Angusu" / "Bridge"
        return Path.home() / "AppData" / "Local" / "Angusu" / "Bridge"
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "angusu-bridge"
    return Path.home() / ".local" / "share" / "angusu-bridge"


def model_home(profile: str) -> Path:
    return data_home() / "models" / profile


def recipe_store_path() -> Path:
    return data_home() / "recipes.sqlite"
