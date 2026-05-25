import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import schedule
import uvicorn
import yaml
from dotenv import load_dotenv
from fastapi import FastAPI

sys.path.insert(0, str(Path(__file__).parent))

from amp_client import AMPClient
from docker_inspector import DockerInspector
from fortigate_client import FortigateClient
from reconciler import Reconciler
from state_manager import StateManager

load_dotenv()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    config_path = Path(__file__).parent.parent / "config.yaml"
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    cfg.setdefault("amp", {})["username"] = os.environ.get("AMP_USERNAME", cfg["amp"].get("username", ""))
    cfg["amp"]["password"] = os.environ.get("AMP_PASSWORD", cfg["amp"].get("password", ""))
    cfg.setdefault("fortigate", {})["token"] = os.environ.get("FORTIGATE_API_TOKEN", cfg["fortigate"].get("token", ""))
    return cfg


def _sync_flag_path(cfg: dict) -> Path:
    db_path = cfg.get("state_db_path", "/var/lib/amp-fw-sync/state.db")
    return Path(db_path).parent / "sync_enabled"


# ---------------------------------------------------------------------------
# Module-level state (shared between threads and FastAPI)
# ---------------------------------------------------------------------------

_status = {
    "started_at": datetime.now(timezone.utc).isoformat(),
    "last_reconcile": None,
    "last_reconcile_stats": {},
    "container_count": 0,
    "sync_enabled": False,
}

_reconciler: Reconciler = None
_docker_inspector: DockerInspector = None
_sync_flag: Path = None

# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(title="amp-fw-sync")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/status")
def status():
    return {**_status, "sync_enabled": _sync_flag.exists() if _sync_flag else False}


@app.post("/sync/now")
def sync_now():
    stats = {}
    if _reconciler and _docker_inspector:
        from reconciler import Reconciler
        s = _reconciler.reconcile()
        _status["last_reconcile"] = datetime.now(timezone.utc).isoformat()
        _status["last_reconcile_stats"] = s
        _status["container_count"] = len(_docker_inspector.get_running_containers())
        stats = s
    return {"stats": stats}


@app.post("/sync/enable")
def sync_enable():
    _sync_flag.touch()
    _status["sync_enabled"] = True
    threading.Thread(
        target=_run_reconcile,
        args=(_reconciler, _docker_inspector),
        daemon=True,
        name="reconcile-on-enable",
    ).start()
    return {"sync_enabled": True, "message": "Sync enabled; reconcile triggered"}


@app.post("/sync/disable")
def sync_disable():
    _sync_flag.unlink(missing_ok=True)
    _status["sync_enabled"] = False
    return {"sync_enabled": False, "message": "Sync disabled"}


# ---------------------------------------------------------------------------
# Background threads
# ---------------------------------------------------------------------------

def _run_reconcile(reconciler: Reconciler, docker_inspector: DockerInspector):
    if not _sync_flag or not _sync_flag.exists():
        return
    stats = reconciler.reconcile()
    _status["last_reconcile"] = datetime.now(timezone.utc).isoformat()
    _status["last_reconcile_stats"] = stats
    _status["container_count"] = len(docker_inspector.get_running_containers())
    _status["sync_enabled"] = True


def _event_listener(reconciler: Reconciler, docker_inspector: DockerInspector):
    logger = logging.getLogger("event_listener")
    logger.info("Docker event listener started")
    for event in docker_inspector.listen_events():
        if not _sync_flag or not _sync_flag.exists():
            continue
        logger.debug("Docker event: %s %s", event.get("Action"), event.get("id", "")[:12])
        try:
            _run_reconcile(reconciler, docker_inspector)
        except Exception as e:
            logger.error("Reconcile triggered by event failed: %s", e)


def _poll_loop(reconciler: Reconciler, docker_inspector: DockerInspector, interval: int):
    logger = logging.getLogger("poll_loop")
    schedule.every(interval).seconds.do(_run_reconcile, reconciler, docker_inspector)
    logger.info("Poll loop started (interval=%ds)", interval)
    while True:
        schedule.run_pending()
        time.sleep(1)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    global _reconciler, _docker_inspector, _sync_flag

    cfg = _load_config()

    logging.basicConfig(
        level=getattr(logging, cfg.get("log_level", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("main")

    docker_cfg = cfg.get("docker", {})
    _docker_inspector = DockerInspector(
        socket_url=docker_cfg.get("socket", "unix:///var/run/docker.sock"),
        label_filter=docker_cfg.get("label_filter") or None,
    )

    fg_cfg = cfg.get("fortigate", {})
    fg_client = FortigateClient(
        host=fg_cfg["host"],
        token=fg_cfg["token"],
        ssl_verify=fg_cfg.get("ssl_verify", True),
    )

    amp_cfg = cfg.get("amp", {})
    amp_client = None
    if amp_cfg.get("host") and amp_cfg.get("username") and amp_cfg.get("password"):
        excluded = set(amp_cfg.get("excluded_instances", ["ADS01"]))
        amp_client = AMPClient(
            host=amp_cfg["host"],
            username=amp_cfg["username"],
            password=amp_cfg["password"],
            excluded_instances=excluded,
        )

    db_path = cfg.get("state_db_path", "/var/lib/amp-fw-sync/state.db")
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    state_manager = StateManager(db_path=db_path)

    ext_ip = fg_cfg.get("ext_ip", "")
    if not ext_ip:
        logger.warning("fortigate.ext_ip is not set — VIPs will be created with an empty external IP")

    host_ip = cfg.get("host_ip", "")
    if not host_ip:
        host_ip = Reconciler._detect_host_ip()
        logger.info("Auto-detected host IP: %s", host_ip)
    else:
        logger.info("Using configured host IP: %s", host_ip)

    _reconciler = Reconciler(
        docker_inspector=_docker_inspector,
        state_manager=state_manager,
        fortigate_client=fg_client,
        ext_ip=ext_ip,
        host_ip=host_ip,
        amp_client=amp_client,
    )
    _reconciler._ssl_ssh_profile = fg_cfg.get("ssl_ssh_profile") or None
    _reconciler._policy_insert_after = fg_cfg.get("policy_insert_after") or None
    _reconciler._service_category = fg_cfg.get("service_category") or None

    _sync_flag = _sync_flag_path(cfg)
    _status["sync_enabled"] = _sync_flag.exists()

    if _sync_flag.exists():
        logger.info("Sync is ENABLED — running initial reconcile")
        _run_reconcile(_reconciler, _docker_inspector)
    else:
        logger.info("Sync is DISABLED — run 'cli.py enable-sync' or POST /sync/enable to start syncing")

    threading.Thread(
        target=_event_listener,
        args=(_reconciler, _docker_inspector),
        daemon=True,
        name="docker-events",
    ).start()

    threading.Thread(
        target=_poll_loop,
        args=(_reconciler, _docker_inspector, cfg.get("poll_interval_seconds", 300)),
        daemon=True,
        name="poll-loop",
    ).start()

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")


if __name__ == "__main__":
    main()
