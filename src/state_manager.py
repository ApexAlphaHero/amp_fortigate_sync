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
                    CREATE TABLE IF NOT EXISTS instance_state (
                        instance_name     TEXT PRIMARY KEY,
                        ports             TEXT NOT NULL,
                        running           INTEGER NOT NULL DEFAULT 0,
                        policy_ids        TEXT NOT NULL,
                        vip_names         TEXT NOT NULL,
                        service_obj_names TEXT NOT NULL
                    )
                """)
                # Migrate old container_state table if present
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if "container_state" in tables and "instance_state" not in tables:
                    conn.execute("""
                        INSERT OR IGNORE INTO instance_state
                            (instance_name, ports, running, policy_ids, vip_names, service_obj_names)
                        SELECT name, ports, 0, policy_ids, vip_names, service_obj_names
                        FROM container_state
                    """)
                    conn.execute("DROP TABLE container_state")
                # Add running column to instance_state if missing (first migration from container_state)
                cols = {row[1] for row in conn.execute("PRAGMA table_info(instance_state)")}
                if "running" not in cols:
                    conn.execute("ALTER TABLE instance_state ADD COLUMN running INTEGER NOT NULL DEFAULT 0")

    def load_all(self) -> dict:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM instance_state").fetchall()
        return {row["instance_name"]: self._row_to_dict(row) for row in rows}

    def save(self, instance_name: str, data: dict):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO instance_state
                        (instance_name, ports, running, policy_ids, vip_names, service_obj_names)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(instance_name) DO UPDATE SET
                        ports             = excluded.ports,
                        running           = excluded.running,
                        policy_ids        = excluded.policy_ids,
                        vip_names         = excluded.vip_names,
                        service_obj_names = excluded.service_obj_names
                    """,
                    (
                        instance_name,
                        json.dumps(data["ports"]),
                        int(data.get("running", False)),
                        json.dumps(data["policy_ids"]),
                        json.dumps(data["vip_names"]),
                        json.dumps(data["service_obj_names"]),
                    ),
                )

    def remove(self, instance_name: str):
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM instance_state WHERE instance_name = ?", (instance_name,))

    def get(self, instance_name: str) -> Optional[dict]:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM instance_state WHERE instance_name = ?", (instance_name,)
                ).fetchone()
        return self._row_to_dict(row) if row else None

    @staticmethod
    def _row_to_dict(row) -> dict:
        return {
            "ports": json.loads(row["ports"]),
            "running": bool(row["running"]),
            "policy_ids": json.loads(row["policy_ids"]),
            "vip_names": json.loads(row["vip_names"]),
            "service_obj_names": json.loads(row["service_obj_names"]),
        }
