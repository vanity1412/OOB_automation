from __future__ import annotations

from core.database import backup_db, init_db, prune_backups
from core.repository import get_setting


def main() -> None:
    init_db()
    path = backup_db()
    keep = int(get_setting("backup_keep_count", "30"))
    removed = prune_backups(keep)
    print(f"Backup created: {path}")
    print(f"Old backups removed: {removed}")


if __name__ == "__main__":
    main()
