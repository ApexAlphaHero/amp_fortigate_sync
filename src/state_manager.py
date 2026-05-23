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
                        container_id   TEXT PRIMARY KEY,
                        name           TEXT NOT NULL,
                        ports          TEXT NOT NULL,
                        policy_ids     TEXT NOT NULL,
                        address_obj_name TEXT NOT NULL
                    )
                """)

    def load_all(self) -> dict:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM container_state").fetchall()
        result = {}
        for row in rows:
            result[row["container_id"]] = {
                "name": row["name"],
                "ports": json.loads(row["ports"]),
                "policy_ids": json.loads(row["policy_ids"]),
                "address_obj_name": row["address_obj_name"],
            }
        return result

    def save(self, container_id: str, data: dict):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO container_state (container_id, name, ports, policy_ids, address_obj_name)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(container_id) DO UPDATE SET
                        name             = excluded.name,
                        ports            = excluded.ports,
                        policy_ids       = excluded.policy_ids,
                        address_obj_name = excluded.address_obj_name
                    """,
                    (
                        container_id,
                        data["name"],
                        json.dumps(data["ports"]),
                        json.dumps(data["policy_ids"]),
                        data["address_obj_name"],
                    ),
                )

    def remove(self, container_id: str):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM container_state WHERE container_id = ?",
                    (container_id,),
                )

    def get(self, container_id: str) -> Optional[dict]:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM container_state WHERE container_id = ?",
                    (container_id,),
                ).fetchone()
        if row is None:
            return None
        return {
            "name": row["name"],
            "ports": json.loads(row["ports"]),
            "policy_ids": json.loads(row["policy_ids"]),
            "address_obj_name": row["address_obj_name"],
        }
