import json
import sqlite3
import threading
from typing import Optional


class StateManager:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock:
            with self._connect() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS container_state (
                        container_id      TEXT PRIMARY KEY,
                        name              TEXT NOT NULL,
                        ports             TEXT NOT NULL,
                        policy_ids        TEXT NOT NULL,
                        vip_names         TEXT NOT NULL,
                        service_obj_names TEXT NOT NULL
                    )
                """)
                # Migrate existing DBs that still have the old address_obj_name column
                cols = {row[1] for row in conn.execute("PRAGMA table_info(container_state)")}
                if "vip_names" not in cols:
                    conn.execute("ALTER TABLE container_state ADD COLUMN vip_names TEXT NOT NULL DEFAULT '[]'")
                if "service_obj_names" not in cols:
                    conn.execute("ALTER TABLE container_state ADD COLUMN service_obj_names TEXT NOT NULL DEFAULT '[]'")

    def load_all(self) -> dict:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM container_state").fetchall()
        return {row["container_id"]: self._row_to_dict(row) for row in rows}

    def save(self, container_id: str, data: dict):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO container_state
                        (container_id, name, ports, policy_ids, vip_names, service_obj_names)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(container_id) DO UPDATE SET
                        name              = excluded.name,
                        ports             = excluded.ports,
                        policy_ids        = excluded.policy_ids,
                        vip_names         = excluded.vip_names,
                        service_obj_names = excluded.service_obj_names
                    """,
                    (
                        container_id,
                        data["name"],
                        json.dumps(data["ports"]),
                        json.dumps(data["policy_ids"]),
                        json.dumps(data["vip_names"]),
                        json.dumps(data["service_obj_names"]),
                    ),
                )

    def remove(self, container_id: str):
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM container_state WHERE container_id = ?", (container_id,))

    def get(self, container_id: str) -> Optional[dict]:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM container_state WHERE container_id = ?", (container_id,)
                ).fetchone()
        return self._row_to_dict(row) if row else None

    @staticmethod
    def _row_to_dict(row) -> dict:
        return {
            "name": row["name"],
            "ports": json.loads(row["ports"]),
            "policy_ids": json.loads(row["policy_ids"]),
            "vip_names": json.loads(row["vip_names"]),
            "service_obj_names": json.loads(row["service_obj_names"]),
        }
