"""ThreatLens — Flask API server (multi-tenant, alerting, syslog receiver)."""
import os
import json
import secrets
import sqlite3
import socketserver
import threading
import logging
import requests
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS

from .engine import ingest_log_file, run_all_detections, AnomalyDetector, DETECTION_RULES, parse_syslog
from . import __version__

# ─── Security Config ─────────────────────────────────────────
ALLOWED_LOG_DIRS = [
    "/tmp",
    "/var/log",
    str(Path.home() / "logs"),
]
CORS_ORIGINS = os.environ.get("THREATLENS_CORS", "http://localhost:5173,http://localhost:3000").split(",")
DB_PATH = os.environ.get("THREATLENS_DB", str(Path.home() / ".config" / "threatlens" / "threatlens.db"))
DEFAULT_TENANT = "default"

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app, origins=[o.strip() for o in CORS_ORIGINS if o.strip()])

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("threatlens")

# ─── Auth (multi-key, RBAC) ──────────────────────────────────

def _get_tenant_from_key(key: str) -> tuple[str | None, str | None]:
    """Look up API key → (tenant_id, role). Returns (None, None) if invalid."""
    db = _get_db()
    row = db.execute(
        "SELECT tenant_id, role FROM api_keys WHERE key_hash = ? AND enabled = 1",
        (key,)
    ).fetchone()
    return (row["tenant_id"], row["role"]) if row else (None, None)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        key = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
        if not key:
            key = request.args.get("api_key", "")
        tenant_id, role = _get_tenant_from_key(key) if key else (None, None)
        if not tenant_id:
            # Fallback: check legacy single key
            legacy = _get_legacy_key()
            if legacy and secrets.compare_digest(key, legacy):
                tenant_id, role = DEFAULT_TENANT, "admin"
            else:
                logger.warning(f"Unauthorized request from {request.remote_addr}")
                return jsonify({"error": "Unauthorized — invalid or missing API key"}), 401
        g.tenant_id = tenant_id
        g.role = role
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.get("role") != "admin":
            return jsonify({"error": "Forbidden — admin role required"}), 403
        return f(*args, **kwargs)
    return decorated


def _resolve_tenant() -> str:
    """Get tenant from: URL param > header > default."""
    tid = request.args.get("tenant_id") or request.headers.get("X-Tenant-ID")
    if tid and g.get("role") == "admin":
        return tid  # admins can query cross-tenant
    return g.get("tenant_id", DEFAULT_TENANT)


def _get_legacy_key() -> str:
    """Legacy single-key fallback."""
    import os as _os
    key = _os.environ.get("THREATLENS_API_KEY", "")
    if not key:
        try:
            cfg = json.loads(Path.home().joinpath(".config", "threatlens", "config.json").read_text())
            key = cfg.get("api_key", "")
        except Exception:
            pass
    return key


# ─── Persistence ─────────────────────────────────────────────

def _get_db():
    if "db" not in g:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        _init_schema(g.db)
    return g.db


def _init_schema(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created TEXT DEFAULT (datetime('now')),
        settings TEXT DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS api_keys (
        key_hash TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(id),
        name TEXT DEFAULT '',
        role TEXT DEFAULT 'readonly',
        enabled INTEGER DEFAULT 1,
        created TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS baselines (
        tenant_id TEXT NOT NULL,
        entity TEXT NOT NULL,
        event_id INTEGER NOT NULL,
        count INTEGER DEFAULT 0,
        PRIMARY KEY (tenant_id, entity, event_id)
    );
    CREATE TABLE IF NOT EXISTS baseline_meta (
        tenant_id TEXT NOT NULL,
        entity TEXT NOT NULL,
        total_events INTEGER DEFAULT 0,
        last_seen TEXT DEFAULT '',
        PRIMARY KEY (tenant_id, entity)
    );
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        mitre TEXT,
        evidence TEXT,
        matched_count INTEGER DEFAULT 0,
        created TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS alert_config (
        tenant_id TEXT PRIMARY KEY,
        webhook_url TEXT DEFAULT '',
        slack_webhook TEXT DEFAULT '',
        min_severity TEXT DEFAULT 'HIGH',
        enabled INTEGER DEFAULT 0
    );
    INSERT OR IGNORE INTO tenants (id, name) VALUES ('default', 'Default Tenant');
    """)
    db.commit()


def _save_baseline(detector, entity_key, tenant_id: str):
    db = _get_db()
    for entity, stats in detector.baselines.items():
        db.execute(
            "INSERT OR REPLACE INTO baseline_meta (tenant_id, entity, total_events, last_seen) VALUES (?, ?, ?, ?)",
            (tenant_id, entity, stats["total_events"], stats.get("last_seen", ""))
        )
        for eid, count in stats["event_ids"].items():
            db.execute(
                "INSERT OR REPLACE INTO baselines (tenant_id, entity, event_id, count) VALUES (?, ?, ?, ?)",
                (tenant_id, entity, int(eid), count)
            )
    db.commit()


def _load_baseline(detector, entity: str, tenant_id: str) -> bool:
    db = _get_db()
    meta = db.execute(
        "SELECT total_events, last_seen FROM baseline_meta WHERE tenant_id = ? AND entity = ?",
        (tenant_id, entity)
    ).fetchone()
    if not meta:
        return False
    rows = db.execute(
        "SELECT event_id, count FROM baselines WHERE tenant_id = ? AND entity = ?",
        (tenant_id, entity)
    ).fetchall()
    detector.baselines[entity] = {
        "total_events": meta["total_events"],
        "event_ids": {row["event_id"]: row["count"] for row in rows},
        "unique_event_types": len(rows),
        "last_seen": meta["last_seen"],
    }
    return True


def _save_alerts(tenant_id: str, alerts: list):
    db = _get_db()
    for a in alerts:
        db.execute(
            "INSERT INTO alerts (tenant_id, rule_id, severity, name, description, mitre, evidence, matched_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, a.rule_id, a.severity, a.name, a.description[:500],
             a.mitre_technique, a.evidence[:500], len(a.matched_events))
        )
    db.commit()


def _teardown_db(exc=None):
    db = g.pop("db", None)
    if db:
        db.close()

app.teardown_appcontext(_teardown_db)


# ─── Alerting / Notification ─────────────────────────────────

def _send_alerts(tenant_id: str, alerts: list):
    """Fire notifications for alerts above configured threshold."""
    db = _get_db()
    row = db.execute(
        "SELECT webhook_url, slack_webhook, min_severity, enabled FROM alert_config WHERE tenant_id = ?",
        (tenant_id,)
    ).fetchone()
    if not row or not row["enabled"]:
        return
    sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_sev = sev_order.get(row["min_severity"], 2)
    significant = [a for a in alerts if sev_order.get(a.severity, 0) >= min_sev]
    if not significant:
        return

    payload = {
        "tenant": tenant_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_count": len(significant),
        "alerts": [a.to_dict() for a in significant[:10]],
    }

    # Generic webhook
    if row["webhook_url"]:
        try:
            requests.post(row["webhook_url"], json=payload, timeout=5)
        except Exception:
            pass

    # Slack webhook
    if row["slack_webhook"]:
        try:
            colors = {"CRITICAL": "#ff1744", "HIGH": "#ff6d00", "MEDIUM": "#ffea00", "LOW": "#00e5a0"}
            blocks = [{
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"🔴 *ThreatLens Alert* — {len(significant)} new detections"}
            }]
            for a in significant[:5]:
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn",
                             "text": f"`{a.severity}` *{a.name}*\n{a.description[:200]}"}
                })
            requests.post(row["slack_webhook"], json={
                "attachments": [{"color": colors.get(significant[0].severity, "#cccccc"), "blocks": blocks}]
            }, timeout=5)
        except Exception:
            pass


# ─── Syslog Receiver (UDP) ───────────────────────────────────

class _SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        try:
            line = data.decode("utf-8", errors="replace")
            event = parse_syslog(line)
            if event:
                app.syslog_buffer.append(event)
        except Exception:
            pass


def _start_syslog_receiver(port: int = 5514):
    """Start UDP syslog listener in a background thread."""
    app.syslog_buffer = []
    server = socketserver.UDPServer(("0.0.0.0", port), _SyslogHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    logger.info("Syslog receiver listening on UDP %d", port)
    return server


# ─── API ─────────────────────────────────────────────────────

@app.route("/api/status")
def status():
    return jsonify({
        "version": __version__,
        "rules_loaded": len(DETECTION_RULES),
        "auth_enabled": True,
        "multi_tenant": True,
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "healthy", "version": __version__})


# ─── Detection ───────────────────────────────────────────────

@app.route("/api/detect", methods=["POST"])
@require_auth
def detect():
    tid = _resolve_tenant()
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    tmp = f"/tmp/threatlens_{secrets.token_hex(8)}.log"
    try:
        f.save(tmp)
        events = ingest_log_file(tmp)
        alerts = run_all_detections(events)
        _save_alerts(tid, alerts)
        _send_alerts(tid, alerts)
        return jsonify({
            "tenant_id": tid,
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
    path = request.args.get("path", "")
    if not path:
        return jsonify({"error": "path parameter required"}), 400
    if not _validate_log_path(path):
        return jsonify({"error": "Access denied"}), 403
    try:
        evts = ingest_log_file(path)
        return jsonify({"count": len(evts), "events": evts[:100]})
    except Exception as exc:
        logger.exception("Event ingestion failed")
        return jsonify({"error": str(exc)}), 500


# ─── Baseline (per-tenant) ───────────────────────────────────

@app.route("/api/baseline", methods=["POST"])
@require_auth
def baseline():
    tid = _resolve_tenant()
    data = request.get_json() or {}
    path = data.get("path", "")
    entity_key = data.get("entity_key", "hostname")
    if not path:
        return jsonify({"error": "path required"}), 400
    if not _validate_log_path(path):
        return jsonify({"error": "Access denied"}), 403
    try:
        evts = ingest_log_file(path)
        det = AnomalyDetector()
        det.train_baseline(evts, entity_key)
        _save_baseline(det, entity_key, tid)
        return jsonify({
            "tenant_id": tid,
            "entities": len(det.baselines),
            "status": "baseline built and persisted"
        })
    except Exception as exc:
        logger.exception("Baseline build failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/score", methods=["POST"])
@require_auth
def score():
    tid = _resolve_tenant()
    data = request.get_json() or {}
    entity = data.get("entity", "")
    recent = data.get("events", [])
    if not entity:
        return jsonify({"error": "entity required"}), 400
    try:
        det = AnomalyDetector()
        if not _load_baseline(det, entity, tid):
            return jsonify({"error": f"No baseline for entity '{entity}' in tenant '{tid}'"}), 404
        s = det.score_entity(entity, recent)
        return jsonify({"tenant_id": tid, "entity": entity, "anomaly_score": s, "anomalous": s > 50})
    except Exception as exc:
        logger.exception("Score failed")
        return jsonify({"error": str(exc)}), 500


# ─── Alerts history (per-tenant) ─────────────────────────────

@app.route("/api/alerts")
@require_auth
def list_alerts():
    tid = _resolve_tenant()
    limit = min(int(request.args.get("limit", 50)), 500)
    sev = request.args.get("severity", "")
    db = _get_db()
    q = "SELECT * FROM alerts WHERE tenant_id = ?"
    params = [tid]
    if sev:
        q += " AND severity = ?"
        params.append(sev.upper())
    q += " ORDER BY created DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(q, params).fetchall()
    return jsonify([dict(r) for r in rows])


# ─── Syslog receiver control ─────────────────────────────────

@app.route("/api/syslog/flush", methods=["POST"])
@require_auth
def syslog_flush():
    """Process buffered syslog events and return detections."""
    tid = _resolve_tenant()
    buf = getattr(app, "syslog_buffer", [])
    count = len(buf)
    if not buf:
        return jsonify({"tenant_id": tid, "events": 0, "alerts": 0, "results": []})
    alerts = run_all_detections(buf)
    _save_alerts(tid, alerts)
    _send_alerts(tid, alerts)
    app.syslog_buffer = []
    return jsonify({
        "tenant_id": tid,
        "events": count,
        "alerts": len(alerts),
        "results": [a.to_dict() for a in alerts],
    })


# ─── Alert config (webhook per tenant) ───────────────────────

@app.route("/api/alert-config", methods=["GET", "PUT"])
@require_auth
@require_admin
def alert_config():
    tid = _resolve_tenant()
    db = _get_db()
    if request.method == "GET":
        row = db.execute("SELECT * FROM alert_config WHERE tenant_id = ?", (tid,)).fetchone()
        return jsonify(dict(row) if row else {"tenant_id": tid, "enabled": False})
    data = request.get_json() or {}
    db.execute(
        "INSERT OR REPLACE INTO alert_config (tenant_id, webhook_url, slack_webhook, min_severity, enabled) "
        "VALUES (?, ?, ?, ?, ?)",
        (tid, data.get("webhook_url", ""), data.get("slack_webhook", ""),
         data.get("min_severity", "HIGH"), int(data.get("enabled", 0)))
    )
    db.commit()
    return jsonify({"status": "saved"})


# ─── Tenant management ───────────────────────────────────────

@app.route("/api/tenants", methods=["GET", "POST"])
@require_auth
@require_admin
def tenants():
    db = _get_db()
    if request.method == "GET":
        rows = db.execute("SELECT * FROM tenants ORDER BY created").fetchall()
        return jsonify([dict(r) for r in rows])
    data = request.get_json() or {}
    tid = data.get("id", secrets.token_hex(6))
    name = data.get("name", tid)
    db.execute("INSERT OR IGNORE INTO tenants (id, name) VALUES (?, ?)", (tid, name))
    db.commit()
    return jsonify({"tenant_id": tid, "name": name, "status": "created"})


@app.route("/api/tenants/<tid>/keys", methods=["GET", "POST"])
@require_auth
@require_admin
def tenant_keys(tid):
    db = _get_db()
    if request.method == "GET":
        rows = db.execute(
            "SELECT name, role, enabled, created FROM api_keys WHERE tenant_id = ?", (tid,)
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    data = request.get_json() or {}
    key = secrets.token_hex(32)
    name = data.get("name", "api-key")
    role = data.get("role", "readonly")
    db.execute(
        "INSERT INTO api_keys (key_hash, tenant_id, name, role) VALUES (?, ?, ?, ?)",
        (key, tid, name, role)
    )
    db.commit()
    return jsonify({"key": key, "tenant_id": tid, "name": name, "role": role, "status": "created"}), 201


# ─── Compliance reporting ────────────────────────────────────

COMPLIANCE_MAP = {
    "PCI DSS": {
        "requirements": [
            ("Req 10", "Track and monitor access to network resources and cardholder data",
             ["TL-001", "TL-002", "TL-011", "TL-018", "TL-026"]),
            ("Req 6", "Develop and maintain secure systems and applications",
             ["TL-005", "TL-007", "TL-008", "TL-009", "TL-030"]),
            ("Req 7", "Restrict access to cardholder data by business need-to-know",
             ["TL-003", "TL-004", "TL-014", "TL-015", "TL-016"]),
            ("Req 11", "Regularly test security systems and processes",
             ["TL-021", "TL-022", "TL-027", "TL-028", "TL-029"]),
            ("Req 5", "Protect all systems against malware",
             ["TL-019", "TL-020", "TL-023", "TL-024", "TL-025"]),
        ]
    },
    "HIPAA": {
        "requirements": [
            ("164.312(b)", "Audit Controls — record and examine activity in information systems",
             ["TL-001", "TL-011", "TL-018", "TL-026"]),
            ("164.312(a)", "Access Control — unique user identification, emergency access",
             ["TL-002", "TL-003", "TL-004", "TL-015", "TL-017"]),
            ("164.312(c)", "Integrity Controls — protect ePHI from improper alteration",
             ["TL-007", "TL-008", "TL-009", "TL-029"]),
            ("164.312(e)", "Transmission Security — guard against unauthorized access to ePHI",
             ["TL-019", "TL-020", "TL-023", "TL-024"]),
            ("164.308(a)", "Security Management Process — risk analysis and management",
             ["TL-005", "TL-010", "TL-021", "TL-027", "TL-028"]),
        ]
    },
    "SOC 2": {
        "requirements": [
            ("CC6.1", "Logical and Physical Access Controls",
             ["TL-001", "TL-002", "TL-003", "TL-004", "TL-011", "TL-018"]),
            ("CC6.6", "External Communication Threats",
             ["TL-019", "TL-020", "TL-023", "TL-024", "TL-025"]),
            ("CC7.1", "System Monitoring and Detection",
             ["TL-006", "TL-007", "TL-008", "TL-009", "TL-026"]),
            ("CC7.2", "Response to Security Events",
             ["TL-014", "TL-015", "TL-016", "TL-017", "TL-028"]),
            ("CC8.1", "Change Management",
             ["TL-005", "TL-029", "TL-030", "TL-031", "TL-032"]),
        ]
    },
}


@app.route("/api/compliance")
@require_auth
def compliance_report():
    tid = _resolve_tenant()
    framework = request.args.get("framework", "PCI DSS")
    if framework not in COMPLIANCE_MAP:
        return jsonify({"error": f"Unknown framework. Available: {list(COMPLIANCE_MAP.keys())}"}), 400

    db = _get_db()
    # Get all alerts for this tenant
    rows = db.execute(
        "SELECT rule_id, severity, COUNT(*) as cnt FROM alerts "
        "WHERE tenant_id = ? GROUP BY rule_id", (tid,)
    ).fetchall()
    alert_counts = {r["rule_id"]: r["cnt"] for r in rows}
    total_alerts = sum(alert_counts.values())

    report = {
        "framework": framework,
        "tenant_id": tid,
        "generated": datetime.now(timezone.utc).isoformat(),
        "total_alerts": total_alerts,
        "requirements": [],
    }
    for req_id, desc, rule_ids in COMPLIANCE_MAP[framework]["requirements"]:
        covered = sum(alert_counts.get(rid, 0) for rid in rule_ids)
        found_alerts = [rid for rid in rule_ids if rid in alert_counts]
        status = "compliant" if covered == 0 else "attention_required"
        report["requirements"].append({
            "id": req_id,
            "description": desc,
            "status": status,
            "covered_rules": len(rule_ids),
            "alert_count": covered,
            "triggered_rules": found_alerts,
        })
    report["compliant_count"] = sum(1 for r in report["requirements"] if r["status"] == "compliant")
    report["total_requirements"] = len(report["requirements"])
    report["compliance_score"] = round(
        report["compliant_count"] / max(report["total_requirements"], 1) * 100
    )
    return jsonify(report)


@app.route("/api/compliance/report", methods=["GET"])
@require_auth
def compliance_report_download():
    framework = request.args.get("framework", "PCI DSS")
    fmt = request.args.get("format", "json")
    # Reuse compliance logic
    data = compliance_report().get_json()
    if fmt == "text":
        lines = [
            f"THREATLENS COMPLIANCE REPORT",
            f"Framework: {framework}",
            f"Generated: {data['generated']}",
            f"Compliance Score: {data['compliance_score']}%",
            f"",
        ]
        for req in data["requirements"]:
            icon = "✅" if req["status"] == "compliant" else "⚠️"
            lines.append(f"{icon} {req['id']}: {req['description']}")
            lines.append(f"   Status: {req['status']}  |  Alerts: {req['alert_count']}  |  Rules: {req['covered_rules']}")
        return "\n".join(lines), 200, {"Content-Type": "text/plain"}
    return jsonify(data)


# ─── Root ─────────────────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({
        "tool": "ThreatLens",
        "version": __version__,
        "multi_tenant": True,
        "endpoints": [
            "/api/status", "/api/health",
            "/api/detect", "/api/rules", "/api/events",
            "/api/baseline", "/api/score",
            "/api/alerts", "/api/syslog/flush",
            "/api/alert-config", "/api/tenants", "/api/tenants/<id>/keys",
            "/api/compliance", "/api/compliance/report",
        ],
    })


# ─── Main ────────────────────────────────────────────────────

_syslog_server = None


def main():
    global _syslog_server
    port = int(os.environ.get("PORT", 5150))
    syslog_port = int(os.environ.get("THREATLENS_SYSLOG_PORT", "5514"))

    # Init DB outside app context
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    init_db = sqlite3.connect(DB_PATH)
    init_db.row_factory = sqlite3.Row
    _init_schema(init_db)
    key_count = init_db.execute("SELECT COUNT(*) as c FROM api_keys WHERE enabled = 1").fetchone()["c"]

    # Bootstrap: always generate key if none in DB
    if key_count == 0:
        bootstrap = secrets.token_hex(32)
        init_db.execute(
            "INSERT INTO api_keys (key_hash, tenant_id, name, role) VALUES (?, 'default', 'bootstrap', 'admin')",
            (bootstrap,)
        )
        # Also insert legacy GUI key
        legacy = _get_legacy_key()
        if legacy:
            try:
                init_db.execute(
                    "INSERT OR IGNORE INTO api_keys (key_hash, tenant_id, name, role) VALUES (?, 'default', 'legacy-gui', 'admin')",
                    (legacy,)
                )
            except Exception:
                pass
        init_db.commit()
        logger.warning(
            "⚠️  Bootstrap admin key: %s  —  save this!", bootstrap
        )
        os.environ["THREATLENS_API_KEY"] = bootstrap
    init_db.close()

    # Start syslog receiver
    _syslog_server = _start_syslog_receiver(syslog_port)

    logger.info("ThreatLens v%s — multi-tenant — port %d — syslog UDP %d",
                __version__, port, syslog_port)
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    main()
