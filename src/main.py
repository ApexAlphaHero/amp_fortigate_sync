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

# Allow bare imports from src/
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
    # Inject secrets from environment
    cfg.setdefault("amp", {})["username"] = os.environ.get("AMP_USERNAME", cfg["amp"].get("username", ""))
    cfg["amp"]["password"] = os.environ.get("AMP_PASSWORD", cfg["amp"].get("password", ""))
    cfg.setdefault("fortigate", {})["token"] = os.environ.get("FORTIGATE_API_TOKEN", cfg["fortigate"].get("token", ""))
    return cfg


# ---------------------------------------------------------------------------
# Global state for /status endpoint
# ---------------------------------------------------------------------------

_status = {
    "started_at": datetime.now(timezone.utc).isoformat(),
    "last_reconcile": None,
    "last_reconcile_stats": {},
    "container_count": 0,
}

# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(title="amp-fw-sync")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/status")
def status():
    return _status


# ---------------------------------------------------------------------------
# Background threads
# ---------------------------------------------------------------------------

def _run_reconcile(reconciler: Reconciler, docker_inspector: DockerInspector):
    stats = reconciler.reconcile()
    _status["last_reconcile"] = datetime.now(timezone.utc).isoformat()
    _status["last_reconcile_stats"] = stats
    _status["container_count"] = len(docker_inspector.get_running_containers())


def _event_listener(reconciler: Reconciler, docker_inspector: DockerInspector):
    logger = logging.getLogger("event_listener")
    logger.info("Docker event listener started")
    for event in docker_inspector.listen_events():
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
    cfg = _load_config()

    logging.basicConfig(
        level=getattr(logging, cfg.get("log_level", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("main")

    docker_cfg = cfg.get("docker", {})
    docker_inspector = DockerInspector(
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
        amp_client = AMPClient(
            host=amp_cfg["host"],
            username=amp_cfg["username"],
            password=amp_cfg["password"],
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

    reconciler = Reconciler(
        docker_inspector=docker_inspector,
        state_manager=state_manager,
        fortigate_client=fg_client,
        ext_ip=ext_ip,
        host_ip=host_ip,
        amp_client=amp_client,
        interfaces=fg_cfg.get("interfaces", ["port1"]),
    )

    logger.info("Running initial reconcile...")
    _run_reconcile(reconciler, docker_inspector)

    threading.Thread(
        target=_event_listener,
        args=(reconciler, docker_inspector),
        daemon=True,
        name="docker-events",
    ).start()

    threading.Thread(
        target=_poll_loop,
        args=(reconciler, docker_inspector, cfg.get("poll_interval_seconds", 30)),
        daemon=True,
        name="poll-loop",
    ).start()

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")


if __name__ == "__main__":
    main()
