from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"


def list_profiles() -> dict[str, dict[str, Any]]:
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    profiles: dict[str, dict[str, Any]] = {}
    for p in sorted(PROFILE_DIR.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            profiles[p.stem] = data
        except Exception:
            continue
    return profiles


def load_profile(profile_key: str) -> dict[str, Any]:
    path = PROFILE_DIR / f"{profile_key}.json"
    if not path.exists():
        raise FileNotFoundError(f"Không tìm thấy profile: {profile_key}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_profile(profile_key: str, data: dict[str, Any]) -> None:
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    path = PROFILE_DIR / f"{profile_key}.json"
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
