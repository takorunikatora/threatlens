"""ThreatLens — Flask API server."""
import os
import json
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from .engine import ingest_log_file, run_all_detections, AnomalyDetector, DETECTION_RULES
from . import __version__

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)
detector = AnomalyDetector()

# ─── API ─────────────────────────────────────────────────────

@app.route("/api/status")
def status():
    return jsonify({
        "version": __version__,
        "rules_loaded": len(DETECTION_RULES),
    })

@app.route("/api/detect", methods=["POST"])
def detect():
    """Upload log file, run detection, return alerts."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    tmp = f"/tmp/threatlens_{os.urandom(8).hex()}.log"
    f.save(tmp)

    events = ingest_log_file(tmp)
    alerts = run_all_detections(events)
    os.remove(tmp)

    return jsonify({
        "events": len(events),
        "alerts": len(alerts),
        "results": [a.to_dict() for a in alerts],
    })

@app.route("/api/rules")
def rules():
    return jsonify([{
        "id": r[0], "name": r[1], "severity": r[2],
        "description": r[3], "mitre": r[4]
    } for r in DETECTION_RULES])

@app.route("/api/events")
def events():
    """Ingest from log path and return parsed events."""
    path = request.args.get("path", "")
    if not path:
        return jsonify({"error": "path parameter required"}), 400
    evts = ingest_log_file(path)
    return jsonify({"count": len(evts), "events": evts[:100]})

@app.route("/api/baseline", methods=["POST"])
def baseline():
    data = request.get_json() or {}
    path = data.get("path", "")
    entity_key = data.get("entity_key", "hostname")
    if not path:
        return jsonify({"error": "path required"}), 400
    evts = ingest_log_file(path)
    detector.train_baseline(evts, entity_key)
    return jsonify({"entities": len(detector.baselines), "status": "baseline built"})

@app.route("/api/score", methods=["POST"])
def score():
    data = request.get_json() or {}
    entity = data.get("entity", "")
    recent = data.get("events", [])
    if not entity:
        return jsonify({"error": "entity required"}), 400
    s = detector.score_entity(entity, recent)
    return jsonify({"entity": entity, "anomaly_score": s, "anomalous": s > 50})

@app.route("/")
def index():
    return jsonify({
        "tool": "ThreatLens",
        "version": __version__,
        "endpoints": ["/api/detect", "/api/rules", "/api/events", "/api/baseline", "/api/score"],
    })

def main():
    port = int(os.environ.get("PORT", 5150))
    print(f"🔴 ThreatLens v{__version__} — http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)

if __name__ == "__main__":
    main()
