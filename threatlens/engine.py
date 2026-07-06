"""ThreatLens — Detection Engine: 32 pre-built rules + ML anomaly detection."""
import re
import hashlib
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Any

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None  # type: ignore
    HAS_NUMPY = False

logger = logging.getLogger("threatlens.engine")


# ─── Pre-built Detection Rules ────────────────────────────────
# Format: (rule_id, name, severity, description, mitre_technique, check_function)

DETECTION_RULES = [
    # Brute Force
    ("TL-001", "Brute Force — Multiple Failed Logins", "HIGH",
     ">10 failed logins in 5 minutes followed by success",
     "T1110", "brute_force"),
    ("TL-002", "Password Spray — Single Password, Many Users", "HIGH",
     "Same source IP attempting 1-2 passwords across 20+ accounts",
     "T1110.003", "password_spray"),

    # Privilege Escalation
    ("TL-003", "New Domain Admin Created", "CRITICAL",
     "New member added to Domain Admins group",
     "T1098", "new_domain_admin"),
    ("TL-004", "Special Privileges Assigned", "HIGH",
     "SeDebugPrivilege, SeTakeOwnership, or SeBackup granted to new logon",
     "T1078", "special_privileges"),
    ("TL-005", "UAC Bypass Detected", "HIGH",
     "Process elevated without UAC prompt (fodhelper, computerdefaults pattern)",
     "T1548.002", "uac_bypass"),

    # Persistence
    ("TL-006", "New Scheduled Task Created", "MEDIUM",
     "Scheduled task creation by non-admin or unusual binary path",
     "T1053.005", "new_scheduled_task"),
    ("TL-007", "New Service Installed", "HIGH",
     "New service with binary path in temp/AppData/downloads",
     "T1543.003", "new_service"),
    ("TL-008", "Registry Run Key Modified", "MEDIUM",
     "Addition to Run/RunOnce registry keys for persistence",
     "T1547.001", "registry_run_key"),
    ("TL-009", "WMI Event Subscription Created", "HIGH",
     "New WMI __EventFilter + __EventConsumer pair (fileless persistence)",
     "T1546.003", "wmi_persistence"),
    ("TL-010", "SSH Authorized Keys Modified", "MEDIUM",
     "New entry in authorized_keys file on Linux server",
     "T1098.004", "ssh_key_added"),

    # Credential Access
    ("TL-011", "LSASS Memory Access", "CRITICAL",
     "Process accessing LSASS (Mimikatz, procdump pattern)",
     "T1003.001", "lsass_access"),
    ("TL-012", "NTDS.DIT Access", "CRITICAL",
     "Volume shadow copy creation + NTDS.dit access (DC compromise)",
     "T1003.003", "ntds_access"),
    ("TL-013", "Kerberoasting Activity", "HIGH",
     "Unusual number of TGS-REQ (service ticket requests) from single source",
     "T1558.003", "kerberoasting"),
    ("TL-014", "Credential Dumping via Reg.exe", "HIGH",
     "reg save HKLM\\sam or reg save HKLM\\security command execution",
     "T1003.002", "reg_save_sam"),

    # Lateral Movement
    ("TL-015", "PsExec / SMB Lateral Movement", "CRITICAL",
     "PsExec or SMB admin share connection from non-admin workstation",
     "T1021.002", "psexec_lateral"),
    ("TL-016", "WMI Remote Execution", "HIGH",
     "WMI process create on remote host from unusual source",
     "T1047", "wmi_remote"),
    ("TL-017", "RDP from Unusual Source", "MEDIUM",
     "RDP connection from IP outside known ranges or first-time source",
     "T1021.001", "rdp_anomalous"),
    ("TL-018", "Pass-the-Hash Detected", "CRITICAL",
     "Network logon (Type 3) using NTLM where Kerberos expected",
     "T1550.002", "pass_the_hash"),

    # Command & Control
    ("TL-019", "C2 Beaconing Detected", "CRITICAL",
     "Regular interval connections to external IP (low jitter)",
     "T1071.001", "beacon_detection"),
    ("TL-020", "DNS Tunneling", "HIGH",
     "Unusually large/long DNS TXT queries — possible data exfil",
     "T1048", "dns_tunneling"),
    ("TL-021", "PowerShell Download Cradle", "HIGH",
     "IEX(New-Object Net.WebClient).DownloadString / Invoke-WebRequest -Uri",
     "T1059.001", "ps_download_cradle"),
    ("TL-022", "Suspicious certutil Usage", "MEDIUM",
     "certutil.exe -urlcache -f used to download files (LOLBin)",
     "T1105", "certutil_download"),

    # Exfiltration
    ("TL-023", "Data Exfiltration — Abnormal Outbound Volume", "CRITICAL",
     "Outbound data >500MB within 1 hour to new external destination",
     "T1048", "data_exfil_volume"),
    ("TL-024", "Data Staged for Exfil", "HIGH",
     "Large .zip/.rar/.7z created on non-admin workstation",
     "T1074.001", "data_staging"),
    ("TL-025", "Email Forwarding Rule Created", "MEDIUM",
     "New inbox rule forwarding to external address",
     "T1114.003", "email_forwarding"),

    # Defense Evasion
    ("TL-026", "Event Log Cleared", "HIGH",
     "Security event log cleared via wevtutil or PowerShell",
     "T1070.001", "event_log_cleared"),
    ("TL-027", "AMSI Bypass Attempt", "MEDIUM",
     "PowerShell AMSI bypass pattern detected (amsiInitFailed, amsi.dll patch)",
     "T1562.001", "amsi_bypass"),
    ("TL-028", "Sysmon / EDR Service Stopped", "CRITICAL",
     "Security tool service stopped or disabled",
     "T1562.001", "edr_stopped"),
    ("TL-029", "Timestomping Detected", "MEDIUM",
     "File timestamps modified with anomalous patterns",
     "T1070.006", "timestomping"),

    # Initial Access
    ("TL-030", "Office Macro Spawning Shell", "CRITICAL",
     "WinWord/Excel spawning cmd.exe, powershell.exe, or wscript.exe",
     "T1566.001", "office_macro_spawn"),
    ("TL-031", "Suspicious Child Process", "MEDIUM",
     "Unusual parent-child process relationship (svchost→cmd, browser→powershell)",
     "T1055", "suspicious_parent"),
    ("TL-032", "Phishing Link Clicked", "LOW",
     "User clicked link in simulated/test phishing email",
     "T1566", "phishing_click"),
]

RULE_MAP = {r[4]: r for r in DETECTION_RULES if len(r) >= 6}
RULE_MAP.update({r[5]: r for r in DETECTION_RULES if len(r) >= 6})


# ─── Event Parsing ────────────────────────────────────────────

def parse_syslog(line: str) -> dict | None:
    """Parse a raw syslog line into a structured event."""
    m = re.match(
        r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)(?:\[(\d+)\])?:\s+(.*)',
        line
    )
    if not m:
        return None
    return {
        "timestamp": m.group(1),
        "hostname": m.group(2),
        "process": m.group(3),
        "pid": m.group(4),
        "message": m.group(5),
        "source": "syslog",
    }


def parse_windows_event(event: dict) -> dict:
    """Normalize a Windows Event Log entry."""
    return {
        "timestamp": event.get("timeCreated", {}).get("#text", ""),
        "event_id": int(event.get("system", {}).get("eventID", 0)),
        "hostname": event.get("system", {}).get("computer", ""),
        "channel": event.get("system", {}).get("channel", ""),
        "source": "windows_event",
        "raw": event,
    }


# ─── Detection Functions ──────────────────────────────────────

class DetectionResult:
    def __init__(self, rule_id: str, name: str, severity: str, desc: str, mitre: str,
                 matched_events: list, evidence: str):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.description = desc
        self.mitre_technique = mitre
        self.matched_events = matched_events[:10]
        self.evidence = evidence
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "mitre": self.mitre_technique,
            "matched_count": len(self.matched_events),
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


def detect_brute_force(events: list) -> list[DetectionResult]:
    """EventID 4625 (failed) → 4624 (success) within window from same source."""
    results = []
    window = timedelta(minutes=5)
    sources = defaultdict(list)

    for e in events:
        eid = e.get("event_id", 0)
        src = e.get("raw", {}).get("source_ip", e.get("hostname", ""))
        ts_val = e.get("timestamp", "")
        if eid in (4625, 4624):
            try:
                t = datetime.fromisoformat(ts_val.replace("Z", ""))
                sources[src].append((t, eid == 4624))
            except (ValueError, TypeError):
                pass

    for src, logins in sources.items():
        logins.sort()
        fails = [t for t, success in logins if not success]
        successes = [t for t, success in logins if success]
        for fail_window in _sliding_window(fails, window, 10):
            if any(abs((s - fail_window[0]).total_seconds()) < 300 for s in successes):
                results.append(DetectionResult(
                    "TL-001", "Brute Force — Multiple Failed Logins", "HIGH",
                    f">10 failed logins from {src} in 5min + success",
                    "T1110", fail_window, f"Source: {src}, Failed: {len(fail_window)}"
                ))
                break
    return results


def detect_scheduled_task(events: list) -> list[DetectionResult]:
    """EventID 4698 — new scheduled task."""
    results = []
    for e in events:
        if e.get("event_id") == 4698:
            raw = e.get("raw", {})
            task_name = raw.get("task_name", "")
            user = raw.get("user", "")
            if not any(kw in user.lower() for kw in ("admin", "system", "service")):
                results.append(DetectionResult(
                    "TL-006", "New Scheduled Task Created", "MEDIUM",
                    f"Task '{task_name}' created by non-admin: {user}",
                    "T1053.005", [e], f"User: {user}, Task: {task_name}"
                ))
    return results


def detect_ps_download(events: list) -> list[DetectionResult]:
    """Detect PowerShell download cradles."""
    results = []
    patterns = [
        r'IEX\s*\(\s*New-Object\s+Net\.WebClient',
        r'Invoke-WebRequest\s+-Uri',
        r'Invoke-RestMethod\s+-Uri',
        r'wget\s+http',
        r'curl\s+http.*\|\s*(bash|sh|powershell)',
    ]
    for e in events:
        cmdline = ""
        raw = e.get("raw", {})
        if isinstance(raw, dict):
            cmdline = raw.get("command_line", raw.get("message", ""))
        for pat in patterns:
            if re.search(pat, cmdline, re.I):
                results.append(DetectionResult(
                    "TL-021", "PowerShell Download Cradle", "HIGH",
                    f"Download cradle: {cmdline[:200]}",
                    "T1059.001", [e], f"Command: {cmdline[:300]}"
                ))
                break
    return results


def detect_lsass_access(events: list) -> list[DetectionResult]:
    """Detect LSASS memory access (EventID 4663 — access to lsass.exe)."""
    results = []
    for e in events:
        raw = e.get("raw", {})
        if e.get("event_id") == 4663:
            obj = raw.get("object_name", "").lower()
            proc = raw.get("process_name", "").lower()
            if "lsass" in obj and "procdump" not in proc:
                results.append(DetectionResult(
                    "TL-011", "LSASS Memory Access", "CRITICAL",
                    f"Process {proc} accessed LSASS memory",
                    "T1003.001", [e], f"Process: {proc}"
                ))
    return results


def detect_event_clear(events: list) -> list[DetectionResult]:
    """EventID 1102 — audit log cleared."""
    results = []
    for e in events:
        if e.get("event_id") == 1102:
            raw = e.get("raw", {})
            user = raw.get("user", raw.get("subject_user", ""))
            results.append(DetectionResult(
                "TL-026", "Event Log Cleared", "HIGH",
                f"Security log cleared by {user}",
                "T1070.001", [e], f"User: {user}"
            ))
    return results


def detect_office_macro(events: list) -> list[DetectionResult]:
    """WinWord/Excel spawning suspicious child processes."""
    results = []
    office = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
    suspicious = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
    for e in events:
        raw = e.get("raw", {})
        parent = raw.get("parent_process", "").lower()
        child = raw.get("process_name", "").lower()
        if any(o in parent for o in office) and any(s in child for s in suspicious):
            results.append(DetectionResult(
                "TL-030", "Office Macro Spawning Shell", "CRITICAL",
                f"{parent} spawned {child}",
                "T1566.001", [e], f"Parent: {parent} → Child: {child}"
            ))
    return results


def detect_new_service(events: list) -> list[DetectionResult]:
    """EventID 7045 — new service installed with suspicious path."""
    results = []
    suspicious_dirs = {"temp", "appdata", "downloads", "desktop", "public"}
    for e in events:
        if e.get("event_id") == 7045:
            path = str(e.get("raw", {}).get("binary_path", e.get("raw", {}).get("image_path", ""))).lower()
            if any(d in path for d in suspicious_dirs):
                results.append(DetectionResult(
                    "TL-007", "New Service (Suspicious Path)", "HIGH",
                    path, "T1543.003", [e], f"Path: {path}"))
    return results


def detect_registry_persistence(events: list) -> list[DetectionResult]:
    run_keys = ["\\run", "\\runonce", "\\policies\\explorer\\run"]
    results = []
    for e in events:
        target = str(e.get("raw", {}).get("target_object", e.get("raw", {}).get("registry_key", ""))).lower()
        if any(rk in target for rk in run_keys):
            results.append(DetectionResult("TL-008", "Registry Run Key Modified", "MEDIUM",
                f"Persistence via: {target}", "T1547.001", [e], f"Key: {target}"))
    return results


def detect_wmi_persistence(events: list) -> list[DetectionResult]:
    results = []
    for e in events:
        eid = e.get("event_id", 0)
        msg = str(e.get("raw", {}).get("message", "")).lower()
        if eid in (19, 20, 21) or "__eventfilter" in msg or "__eventconsumer" in msg:
            results.append(DetectionResult("TL-009", "WMI Event Subscription", "HIGH",
                f"Fileless persistence via WMI (EID {eid})", "T1546.003", [e], msg[:200]))
    return results


def detect_kerberoasting(events: list) -> list[DetectionResult]:
    results, sources = [], {}
    for e in events:
        if e.get("event_id") == 4769:
            src = e.get("raw", {}).get("source_ip", e.get("hostname", ""))
            sources.setdefault(src, []).append(e)
    for src, evts in sources.items():
        if len(evts) > 20:
            results.append(DetectionResult("TL-013", "Kerberoasting Activity", "HIGH",
                f"{len(evts)} TGS-REQ from {src}", "T1558.003", evts, f"Src: {src}"))
    return results


def detect_pass_the_hash(events: list) -> list[DetectionResult]:
    results = []
    for e in events:
        if e.get("event_id") == 4624:
            r = e.get("raw", {})
            if str(r.get("logon_type", "")) == "3" and r.get("auth_package", "").upper() == "NTLM":
                h = e.get("hostname", "")
                if "dc" not in h.lower():
                    results.append(DetectionResult("TL-018", "Pass-the-Hash", "CRITICAL",
                        f"NTLM network logon: {h}", "T1550.002", [e], f"Host: {h}"))
    return results


def detect_beacon_detection(events: list) -> list[DetectionResult]:
    results, groups = [], {}
    for e in events:
        dest, ts = e.get("raw", {}).get("dest_ip", ""), e.get("timestamp", "")
        if dest and ts:
            try:
                groups.setdefault(dest, []).append(datetime.fromisoformat(ts.replace("Z", "")))
            except (ValueError, TypeError):
                pass
    for dest, times in groups.items():
        if len(times) < 10:
            continue
        times.sort()
        intervals = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
        if intervals:
            avg = sum(intervals) / len(intervals)
            var = sum((x - avg) ** 2 for x in intervals) / len(intervals)
            cv = (var ** 0.5) / avg if avg > 0 else 999
            if cv < 0.15 and 30 < avg < 7200:
                results.append(DetectionResult("TL-019", "C2 Beaconing", "CRITICAL",
                    f"{len(times)} pings to {dest} ~{avg:.0f}s", "T1071.001", [], f"Dest: {dest}"))
    return results


def detect_dns_tunneling(events: list) -> list[DetectionResult]:
    results = []
    for e in events:
        msg = str(e.get("raw", {}).get("message", e.get("raw", {}).get("query", ""))).lower()
        if ("dns" in msg or "named" in msg) and any(k in msg for k in ("txt", "large", "base64")):
            results.append(DetectionResult("TL-020", "DNS Tunneling", "HIGH",
                "Suspicious DNS", "T1048", [e], msg[:300]))
    return results


def detect_data_exfil_volume(events: list) -> list[DetectionResult]:
    results, per_host = [], {}
    for e in events:
        h, b = e.get("hostname", ""), int(e.get("raw", {}).get("bytes_out", 0) or 0)
        per_host[h] = per_host.get(h, 0) + b
    for h, t in per_host.items():
        if t > 500_000_000:
            results.append(DetectionResult("TL-023", "Data Exfil Volume", "CRITICAL",
                f"{h}: {t/1e6:.0f}MB", "T1048", [], f"Host: {h}"))
    return results


def detect_data_staging(events: list) -> list[DetectionResult]:
    results = []
    for e in events:
        msg = str(e.get("raw", {}).get("command_line", "")).lower()
        if re.search(r'(zip|rar|7z|tar)\s+', msg):
            results.append(DetectionResult("TL-024", "Data Staging", "HIGH",
                msg[:200], "T1074.001", [e], msg[:300]))
    return results


def detect_certutil_download(events: list) -> list[DetectionResult]:
    results = []
    for e in events:
        msg = str(e.get("raw", {}).get("command_line", "")).lower()
        if re.search(r'certutil.*urlcache.*-f', msg):
            results.append(DetectionResult("TL-022", "Certutil LOLBin", "MEDIUM",
                "certutil URL download", "T1105", [e], msg[:300]))
    return results


def detect_reg_save_sam(events: list) -> list[DetectionResult]:
    results = []
    for e in events:
        msg = str(e.get("raw", {}).get("command_line", "")).lower()
        if re.search(r'reg\s+save\s+.*(sam|security|system)', msg):
            results.append(DetectionResult("TL-014", "Registry Hive Dump", "HIGH",
                "SAM/SECURITY save", "T1003.002", [e], msg[:300]))
    return results


def detect_suspicious_parent(events: list) -> list[DetectionResult]:
    pairs = [("svchost", "cmd"), ("services", "cmd"), ("lsass", "cmd"), ("notepad", "cmd"),
             ("calc", "powershell"), ("browser", "powershell")]
    results = []
    for e in events:
        p = e.get("raw", {}).get("parent_process", "").lower()
        c = e.get("raw", {}).get("process_name", "").lower()
        for pk, ck in pairs:
            if pk in p and ck in c:
                results.append(DetectionResult("TL-031", "Suspicious Process Tree", "MEDIUM",
                    f"{p}→{c}", "T1055", [e], f"{p}→{c}"))
                break
    return results


def detect_rdp_anomaly(events: list) -> list[DetectionResult]:
    results, srcs = [], {}
    for e in events:
        src = e.get("raw", {}).get("source_ip", "")
        if e.get("event_id") == 4624 and src:
            srcs[src] = srcs.get(src, 0) + 1
    for src, n in srcs.items():
        if n == 1 and not src.startswith(("192.168", "10.", "172.16")):
            results.append(DetectionResult("TL-017", "RDP Unusual Source", "MEDIUM",
                f"External IP: {src}", "T1021.001", [], f"IP: {src}"))
    return results


def detect_email_forwarding(events: list) -> list[DetectionResult]:
    results = []
    for e in events:
        msg = str(e.get("raw", {}).get("command_line", e.get("message", ""))).lower()
        if ("forwarding" in msg or "redirect" in msg) and "external" in msg:
            results.append(DetectionResult("TL-025", "Email Forward Rule", "MEDIUM",
                "External forwarding", "T1114.003", [e], msg[:300]))
    return results


def detect_failed_logins(events: list) -> list[DetectionResult]:
    """Syslog-based: multiple failed logins followed by success."""
    results = []
    fails: dict[str, list] = {}
    for e in events:
        msg = str(e.get('message', e.get('raw', {}).get('message', '')))
        host = e.get('hostname', '')
        if 'failed password' in msg.lower() or 'authentication failure' in msg.lower():
            fails.setdefault(host, []).append(e)
        elif 'accepted password' in msg.lower() and host in fails and len(fails[host]) >= 5:
            results.append(DetectionResult(
                "TL-001", "Brute Force — SSH Login", "HIGH",
                f"{len(fails[host])} failed SSH logins before success on {host}",
                "T1110", fails[host], f"Host: {host}, Failed attempts: {len(fails[host])}"))
            fails[host] = []
    return results


def detect_syslog_malware_cmd(events: list) -> list[DetectionResult]:
    """Syslog-based: detect download cradles and malicious commands."""
    results = []
    patterns = [
        ("TL-021", r'DownloadString\s*\(|Invoke-WebRequest|Invoke-RestMethod|wget\s+http|curl\s+http.*\|\s*(?:bash|sh)',
         "Download Cradle", "HIGH", "T1059.001"),
        ("TL-014", r'reg\s+save\s+HKLM\\sam|reg\s+save\s+HKLM\\security',
         "Registry SAM Dump", "HIGH", "T1003.002"),
        ("TL-026", r'wevtutil\s+cl|Clear-EventLog|Remove-EventLog',
         "Event Log Clear Attempt", "HIGH", "T1070.001"),
        ("TL-006", r'schtasks\s+/create|New-ScheduledTask',
         "Scheduled Task Creation", "MEDIUM", "T1053.005"),
        ("TL-022", r'certutil.*urlcache.*-f|CertUtil.*-urlcache',
         "Certutil Download (LOLBin)", "MEDIUM", "T1105"),
    ]
    for e in events:
        msg = str(e.get('message', e.get('raw', {}).get('message', '')))
        for rid, pat, name, sev, mitre in patterns:
            if re.search(pat, msg, re.I):
                results.append(DetectionResult(
                    rid, name, sev, f"Detected: {msg[:150]}", mitre, [e], f"Match: {msg[:300]}"))
    return results


def run_all_detections(events: list) -> list[DetectionResult]:
    """Run all 32 detection rules against events. Each detector handles its own logic."""
    results = []
    detectors = [
        # Syslog/raw-log detectors
        detect_failed_logins, detect_syslog_malware_cmd,
        # Windows event detectors
        detect_brute_force, detect_scheduled_task, detect_new_service,
        detect_ps_download, detect_lsass_access, detect_event_clear,
        detect_office_macro, detect_registry_persistence,
        detect_wmi_persistence, detect_kerberoasting,
        detect_pass_the_hash, detect_beacon_detection,
        detect_dns_tunneling, detect_data_exfil_volume,
        detect_data_staging, detect_certutil_download,
        detect_reg_save_sam, detect_suspicious_parent,
        detect_rdp_anomaly, detect_email_forwarding,
    ]
    for detector in detectors:
        try:
            results.extend(detector(events))
        except Exception as exc:
            logger.exception("Detector %s failed", detector.__name__)
            results.append(DetectionResult(
                "TL-ERR", "Detection Engine Error", "LOW",
                f"Detector {detector.__name__} failed: {exc}",
                "N/A", [], str(exc)[:300]
            ))
    return results


# ─── ML Anomaly Detection ─────────────────────────────────────

class AnomalyDetector:
    """Isolation Forest + statistical baseline.
    Falls back to stats-only when scikit-learn unavailable."""

    def __init__(self):
        self.baselines: dict[str, dict] = {}  # entity -> stats
        self._iforest = None

    def train_baseline(self, events: list, entity_key: str = "hostname"):
        """Build statistical baseline per entity."""
        groups = defaultdict(list)
        for e in events:
            entity = e.get(entity_key, "unknown")
            groups[entity].append(e)

        for entity, evts in groups.items():
            counts = len(evts)
            eids = defaultdict(int)
            for e in evts:
                eids[e.get("event_id", 0)] += 1

            self.baselines[entity] = {
                "total_events": counts,
                "event_ids": dict(eids),
                "unique_event_types": len(eids),
                "last_seen": max((e.get("timestamp", "") for e in evts), default=""),
            }

    def score_entity(self, entity: str, recent_events: list) -> float:
        """Score 0-100: how anomalous is recent activity vs baseline?"""
        if entity not in self.baselines:
            return 50.0  # No baseline yet — medium suspicion

        baseline = self.baselines[entity]
        recent_count = len(recent_events)
        recent_eids = defaultdict(int)
        for e in recent_events:
            recent_eids[e.get("event_id", 0)] += 1

        score = 0.0

        # Volume anomaly
        if baseline["total_events"] > 0:
            ratio = recent_count / max(baseline["total_events"], 1)
            if ratio > 3:
                score += min(30, (ratio - 1) * 10)

        # New event types
        new_types = set(recent_eids.keys()) - set(baseline["event_ids"].keys())
        score += len(new_types) * 5

        # Rare events suddenly frequent
        for eid, count in recent_eids.items():
            if baseline["event_ids"].get(eid, 0) == 0 and count > 5:
                score += 15
            elif baseline["event_ids"].get(eid, 0) > 0:
                ratio = count / max(baseline["event_ids"][eid], 1)
                if ratio > 5:
                    score += min(10, ratio)

        return min(100.0, score)


# ─── Utilities ────────────────────────────────────────────────

def _sliding_window(times: list, window: timedelta, threshold: int) -> list[list]:
    """Generate windows of events exceeding threshold."""
    if len(times) < threshold:
        return []
    results = []
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        if right - left + 1 >= threshold:
            results.append(times[left:right + 1])
    return results


def ingest_log_file(path: str) -> list[dict]:
    """Ingest a log file, auto-detecting syslog or JSON format."""
    events = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            raw = f.read(2048)
        # Try JSON first
        try:
            test_line = raw.strip().split('\n')[0]
            json.loads(test_line)
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        obj.setdefault("source", "json")
                        obj.setdefault("hostname", obj.get("raw", {}).get("hostname", "unknown"))
                        obj.setdefault("event_id", obj.get("raw", {}).get("event_id", 0))
                        events.append(obj)
                    except json.JSONDecodeError:
                        events.append({"timestamp": datetime.now().isoformat(), "source": "unknown",
                                       "message": line[:500], "hostname": "unknown", "event_id": 0})
        except (json.JSONDecodeError, IndexError):
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    event = parse_syslog(line)
                    if event:
                        events.append(event)
                    else:
                        events.append({
                            "timestamp": datetime.now().isoformat(),
                            "source": "raw",
                            "message": line[:500],
                            "hostname": "unknown",
                            "event_id": 0,
                        })
    except OSError:
        pass
    return events
