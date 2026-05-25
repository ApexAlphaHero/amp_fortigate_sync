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
                        instance_name TEXT PRIMARY KEY,
                        ports         TEXT NOT NULL,
                        running       INTEGER NOT NULL DEFAULT 0,
                        policy_id     TEXT,
                        vip_names     TEXT NOT NULL
                    )
                """)
                cols = {row[1] for row in conn.execute("PRAGMA table_info(instance_state)")}
                # Migrate old schema: policy_ids (list) → policy_id (scalar)
                if "policy_ids" in cols and "policy_id" not in cols:
                    conn.execute("ALTER TABLE instance_state ADD COLUMN policy_id TEXT")
                    conn.execute("""
                        UPDATE instance_state
                        SET policy_id = (
                            SELECT json_extract(policy_ids, '$[0]')
                        )
                    """)
                # Drop obsolete columns (SQLite <3.35 can't DROP COLUMN, so we recreate)
                if "policy_ids" in cols or "service_obj_names" in cols:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS instance_state_new (
                            instance_name TEXT PRIMARY KEY,
                            ports         TEXT NOT NULL,
                            running       INTEGER NOT NULL DEFAULT 0,
                            policy_id     TEXT,
                            vip_names     TEXT NOT NULL
                        )
                    """)
                    conn.execute("""
                        INSERT OR REPLACE INTO instance_state_new
                            (instance_name, ports, running, policy_id, vip_names)
                        SELECT instance_name, ports, running,
                               COALESCE(policy_id, json_extract(policy_ids, '$[0]')),
                               vip_names
                        FROM instance_state
                    """)
                    conn.execute("DROP TABLE instance_state")
                    conn.execute("ALTER TABLE instance_state_new RENAME TO instance_state")

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
                        (instance_name, ports, running, policy_id, vip_names)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(instance_name) DO UPDATE SET
                        ports     = excluded.ports,
                        running   = excluded.running,
                        policy_id = excluded.policy_id,
                        vip_names = excluded.vip_names
                    """,
                    (
                        instance_name,
                        json.dumps(data["ports"]),
                        int(data.get("running", False)),
                        json.dumps(data.get("policy_id")),
                        json.dumps(data["vip_names"]),
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
            "policy_id": json.loads(row["policy_id"]) if row["policy_id"] else None,
            "vip_names": json.loads(row["vip_names"]),
        }
