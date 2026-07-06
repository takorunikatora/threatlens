"""ThreatLens — Flask API server (production-hardened)."""
import os
import json
import secrets
import logging
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS

from .engine import ingest_log_file, run_all_detections, AnomalyDetector, DETECTION_RULES
from . import __version__

# ─── Security Config ─────────────────────────────────────────
ALLOWED_LOG_DIRS = [
    "/tmp",
    "/var/log",
    str(Path.home() / "logs"),
]
API_KEY = os.environ.get("THREATLENS_API_KEY", "")
CORS_ORIGINS = os.environ.get("THREATLENS_CORS", "http://localhost:5173,http://localhost:3000").split(",")

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app, origins=[o.strip() for o in CORS_ORIGINS if o.strip()])

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("threatlens")

# ─── Auth ────────────────────────────────────────────────────

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if API_KEY:
            auth = request.headers.get("Authorization", "")
            key = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
            if not secrets.compare_digest(key, API_KEY):
                logger.warning(f"Unauthorized request from {request.remote_addr}")
                return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def _validate_log_path(path: str) -> bool:
    """Only allow paths inside ALLOWED_LOG_DIRS — blocks traversal."""
    resolved = os.path.realpath(path)
    for allowed in ALLOWED_LOG_DIRS:
        allowed_real = os.path.realpath(allowed)
        if resolved.startswith(allowed_real + os.sep) or resolved == allowed_real:
            return True
    return False


# ─── API ─────────────────────────────────────────────────────

@app.route("/api/status")
def status():
    return jsonify({
        "version": __version__,
        "rules_loaded": len(DETECTION_RULES),
        "auth_enabled": bool(API_KEY),
    })


@app.route("/api/detect", methods=["POST"])
@require_auth
def detect():
    """Upload log file, run detection, return alerts."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    tmp = f"/tmp/threatlens_{secrets.token_hex(8)}.log"
    try:
        f.save(tmp)
        events = ingest_log_file(tmp)
        alerts = run_all_detections(events)
        return jsonify({
            "events": len(events),
            "alerts": len(alerts),
            "results": [a.to_dict() for a in alerts],
        })
    except Exception as exc:
        logger.exception("Detection failed")
        return jsonify({"error": str(exc)}), 500
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


@app.route("/api/rules")
def rules():
    return jsonify([{
        "id": r[0], "name": r[1], "severity": r[2],
        "description": r[3], "mitre": r[4]
    } for r in DETECTION_RULES])


@app.route("/api/events")
@require_auth
def events():
    """Ingest from log path and return parsed events."""
    path = request.args.get("path", "")
    if not path:
        return jsonify({"error": "path parameter required"}), 400
    if not _validate_log_path(path):
        logger.warning(f"Blocked path traversal attempt: {path}")
        return jsonify({"error": "Access denied — path outside allowed directories"}), 403
    try:
        evts = ingest_log_file(path)
        return jsonify({"count": len(evts), "events": evts[:100]})
    except Exception as exc:
        logger.exception("Event ingestion failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/baseline", methods=["POST"])
@require_auth
def baseline():
    data = request.get_json() or {}
    path = data.get("path", "")
    entity_key = data.get("entity_key", "hostname")
    if not path:
        return jsonify({"error": "path required"}), 400
    if not _validate_log_path(path):
        return jsonify({"error": "Access denied — path outside allowed directories"}), 403
    try:
        evts = ingest_log_file(path)
        # Per-request detector instance — no global state sharing
        det = AnomalyDetector()
        det.train_baseline(evts, entity_key)
        return jsonify({"entities": len(det.baselines), "status": "baseline built"})
    except Exception as exc:
        logger.exception("Baseline build failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/score", methods=["POST"])
@require_auth
def score():
    data = request.get_json() or {}
    entity = data.get("entity", "")
    recent = data.get("events", [])
    if not entity:
        return jsonify({"error": "entity required"}), 400
    try:
        det = AnomalyDetector()
        det.baselines = {entity: {"total_events": 100, "event_ids": {}, "unique_event_types": 0, "last_seen": ""}}
        s = det.score_entity(entity, recent)
        return jsonify({"entity": entity, "anomaly_score": s, "anomalous": s > 50})
    except Exception as exc:
        logger.exception("Score failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/")
def index():
    return jsonify({
        "tool": "ThreatLens",
        "version": __version__,
        "auth_enabled": bool(API_KEY),
        "endpoints": ["/api/detect", "/api/rules", "/api/events", "/api/baseline", "/api/score"],
    })


def main():
    port = int(os.environ.get("PORT", 5150))
    logger.info("ThreatLens v%s starting on port %d (auth=%s)", __version__, port, bool(API_KEY))
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    main()
