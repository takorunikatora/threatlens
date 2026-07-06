"""ThreatLens GUI — Neon Red + Jadeite + Electric Blue Gradient Theme."""
import os
import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime

from .engine import (
    ingest_log_file, run_all_detections, AnomalyDetector,
    DETECTION_RULES, DetectionResult
)

# ─── Theme: Blood Moon + Jadeite + Blue Neon ─────────────────
BG_DEEP = "#0a0008"       # near-black crimson
BG_MID = "#140010"        # deep blood
BG_CARD = "#1a0018"       # dark plum
BLOOD = "#ff1744"         # neon red
BLOOD_DIM = "#b2102f"     # dim red
JADE = "#00e5a0"          # jadeite green
JADE_DIM = "#008060"      # dim jade
BLUE = "#00b0ff"          # electric blue neon
BLUE_DIM = "#0060aa"      # dim blue
PURPLE = "#7c4dff"        # accent purple
ORANGE = "#ff6d00"        # warning
YELLOW = "#ffea00"        # info
FG = "#e8d0f0"            # light text
FG_DIM = "#9070a0"        # dim text
BORDER = "#3a1040"        # border
INPUT_BG = "#0d0010"      # input background
HIGHLIGHT = "#2a0050"     # selection


class ThreatLensApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ThreatLens — Lightweight SIEM")
        self.root.geometry("1280x800")
        self.root.configure(bg=BG_DEEP)
        self.root.minsize(1050, 600)

        self.events: list[dict] = []
        self.alerts: list[DetectionResult] = []
        self.detector = AnomalyDetector()
        self.busy = False

        self._build_ui()

    # ─── UI Construction ──────────────────────────────────────

    def _build_ui(self):
        # Gradient canvas: crimson → blue → green
        h = tk.Canvas(self.root, height=80, bg=BG_DEEP, highlightthickness=0)
        h.pack(fill=tk.X)
        for i in range(80):
            t = i / 79
            if t < 0.5:
                # Crimson → Blue
                r = int(0xff * (1 - t * 2) + 0x00 * (t * 2))
                g = int(0x17 * (1 - t * 2) + 0xb0 * (t * 2))
                b = int(0x44 * (1 - t * 2) + 0xff * (t * 2))
            else:
                # Blue → Jade
                t2 = (t - 0.5) * 2
                r = int(0x00 * (1 - t2))
                g = int(0xb0 * (1 - t2) + 0xe5 * t2)
                b = int(0xff * (1 - t2) + 0xa0 * t2)
            h.create_line(0, i, 1280, i, fill=f"#{r:02x}{g:02x}{b:02x}")
        h.create_text(640, 24, text="🔴  THREATLENS", font=("DejaVu Sans Mono", 26, "bold"), fill=BLOOD)
        h.create_text(640, 52, text="Lightweight SIEM — Detect · Hunt · Respond", font=("DejaVu Sans Mono", 9), fill=BLUE_DIM)

        # Controls
        ctrl = tk.Frame(self.root, bg=BG_CARD, padx=15, pady=10)
        ctrl.pack(fill=tk.X, padx=15, pady=(10, 5))

        r1 = tk.Frame(ctrl, bg=BG_CARD)
        r1.pack(fill=tk.X, pady=3)

        def _label(parent, text, fg=FG_DIM):
            tk.Label(parent, text=text, fg=fg, bg=BG_CARD, font=("DejaVu Sans Mono", 9)).pack(side=tk.LEFT, padx=(10, 2))

        def _entry(parent, var, width):
            tk.Entry(parent, textvariable=var, font=("DejaVu Sans Mono", 10), fg=FG, bg=INPUT_BG,
                     insertbackground=BLUE, relief=tk.FLAT, bd=0, highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=BLUE, width=width).pack(side=tk.LEFT, padx=4, ipady=5)

        _label(r1, "📂 Log File")
        self.file_var = tk.StringVar(value="")
        _entry(r1, self.file_var, 45)
        self._btn(r1, "Browse", self._browse, BG_CARD, 9, fg=BLUE).pack(side=tk.LEFT, padx=4)

        _label(r1, "🔍 Entity")
        self.entity_var = tk.StringVar(value="hostname")
        tk.OptionMenu(r1, self.entity_var, "hostname", "username", "source_ip",
                       command=lambda _: None).pack(side=tk.LEFT, padx=4)

        r2 = tk.Frame(ctrl, bg=BG_CARD)
        r2.pack(fill=tk.X, pady=(8, 3))

        self.btn_ingest = self._btn(r2, "📥  Ingest Logs", self._ingest, BLOOD, 12, True)
        self.btn_ingest.pack(side=tk.LEFT, padx=(0, 8))
        self.btn_detect = self._btn(r2, "🔍  Run Detection", self._detect, BLUE, 10)
        self.btn_detect.pack(side=tk.LEFT, padx=(0, 8))
        self.btn_baseline = self._btn(r2, "📊  Build Baseline", self._baseline, BORDER, 10)
        self.btn_baseline.pack(side=tk.LEFT, padx=(0, 8))
        self.btn_export = self._btn(r2, "📄  Export Alerts", self._export, BORDER, 10)
        self.btn_export.pack(side=tk.LEFT, padx=(0, 8))
        self._btn(r2, "⚙ Settings", self._open_settings, "#2a1040", 10, fg=JADE).pack(side=tk.RIGHT, padx=(0, 8))
        self._btn(r2, "Clear", self._clear, BG_DEEP, 10, fg="#555").pack(side=tk.RIGHT)

        # Progress bar
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        s = ttk.Style()
        s.theme_use("default")
        s.configure("TProgressbar", troughcolor=BG_DEEP, background=BLOOD, bordercolor=BG_DEEP,
                     lightcolor=BLOOD, darkcolor=BLUE)

        # Main: left alerts + right detail
        main = tk.Frame(self.root, bg=BG_DEEP)
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=(5, 0))

        # Alerts tree
        s.configure("Treeview", background=BG_CARD, foreground=FG, fieldbackground=BG_CARD,
                     borderwidth=0, rowheight=28)
        s.configure("Treeview.Heading", background=BG_MID, foreground=BLUE,
                     font=("DejaVu Sans Mono", 8, "bold"), relief=tk.FLAT)
        s.map("Treeview", background=[("selected", HIGHLIGHT)])

        cols = ("sev", "rule", "count", "desc")
        self.tree = ttk.Treeview(main, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("sev", text="SEV")
        self.tree.heading("rule", text="Rule")
        self.tree.heading("count", text="Hits")
        self.tree.heading("desc", text="Description")
        self.tree.column("sev", width=80, anchor=tk.CENTER)
        self.tree.column("rule", width=250)
        self.tree.column("count", width=60, anchor=tk.CENTER)
        self.tree.column("desc", width=750)

        vsb = ttk.Scrollbar(main, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        main.grid_rowconfigure(0, weight=3)
        main.grid_columnconfigure(0, weight=1)

        # Tags
        for tag, bg, fg in [
            ("CRITICAL", "#2a0020", BLOOD),
            ("HIGH", "#200015", ORANGE),
            ("MEDIUM", "#1a0015", YELLOW),
            ("LOW", "#0a0012", JADE),
        ]:
            self.tree.tag_configure(tag, background=bg, foreground=fg)

        # Detail panel
        self.detail = scrolledtext.ScrolledText(main, height=8, font=("DejaVu Sans Mono", 9),
                                                fg=FG_DIM, bg=INPUT_BG, insertbackground=BLUE,
                                                relief=tk.FLAT, bd=0, highlightthickness=1,
                                                highlightbackground=BORDER, wrap=tk.WORD,
                                                state=tk.DISABLED)
        self.detail.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
        main.grid_rowconfigure(1, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Stats bar
        sb = tk.Frame(self.root, bg=BG_MID, height=28)
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        sb.pack_propagate(False)
        self.stats_var = tk.StringVar(value="Events: 0  |  Alerts: 0  |  Ready")
        tk.Label(sb, textvariable=self.stats_var, font=("DejaVu Sans Mono", 8),
                 fg="#604080", bg=BG_MID, anchor=tk.W, padx=12).pack(fill=tk.X)

    # ─── Widget Helpers ───────────────────────────────────────

    def _btn(self, parent, text, cmd, bg, size, bold=False, fg="#000"):
        w = tk.Button(parent, text=text, command=cmd, font=("DejaVu Sans Mono", size, "bold" if bold else "normal"),
                      fg=fg, bg=bg, relief=tk.FLAT, activebackground=BLUE if bg == BLOOD else BLOOD,
                      activeforeground="#000" if bg == BLOOD else FG, cursor="hand2", padx=14, pady=5,
                      state=tk.DISABLED if bg == BORDER else tk.NORMAL)
        return w

    def _set_busy(self, busy: bool):
        self.busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        self.btn_ingest.configure(state=state, text="⏳  Ingesting..." if busy else "📥  Ingest Logs",
                                  bg=BG_CARD if busy else BLOOD)
        self.btn_detect.configure(state=state)
        self.btn_baseline.configure(state=state)
        if busy:
            self.progress.pack(fill=tk.X, padx=15, pady=2)
            self.progress.start(10)
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def _status(self, msg: str, is_error: bool = False):
        self.root.after(0, lambda: self.stats_var.set(
            f"{'⚠ ' if is_error else ''}{msg}  |  Events: {len(self.events)}  |  Alerts: {len(self.alerts)}"
        ))

    # ─── Operations ───────────────────────────────────────────

    def _browse(self):
        fp = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", "*.log *.txt *.evtx"), ("All files", "*")]
        )
        if fp:
            self.file_var.set(fp)
            self._status(f"📂 Selected: {os.path.basename(fp)}")

    def _ingest(self):
        fp = self.file_var.get()
        if not fp or self.busy:
            return
        self._set_busy(True)

        def _run():
            self.events = ingest_log_file(fp)
            self.root.after(0, lambda: self._on_ingested())

        threading.Thread(target=_run, daemon=True).start()

    def _on_ingested(self):
        self._set_busy(False)
        if not self.events:
            self._status("No events parsed — try a syslog or JSON log file", is_error=True)
            return
        self.btn_detect.configure(state=tk.NORMAL)
        self.btn_baseline.configure(state=tk.NORMAL)
        self._status(f"✓ Ingested {len(self.events)} events")

    def _detect(self):
        if self.busy or not self.events:
            return
        self._set_busy(True)

        def _run():
            self.alerts = run_all_detections(self.events)
            scores = {}
            for alert in self.alerts:
                for e in alert.matched_events:
                    entity = e.get("hostname", e.get("source", "unknown"))
                    if entity not in scores:
                        scores[entity] = self.detector.score_entity(entity, [e])
            self.root.after(0, self._on_detected)

        threading.Thread(target=_run, daemon=True).start()

    def _on_detected(self):
        self._set_busy(False)
        self._populate_tree()
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in self.alerts:
            sev_counts[a.severity] += 1
        self._status(
            f"Detection complete — "
            f"🔴{sev_counts['CRITICAL']} 🟠{sev_counts['HIGH']} 🟡{sev_counts['MEDIUM']} 🟢{sev_counts['LOW']}"
        )
        self.btn_export.configure(state=tk.NORMAL)
        if self.alerts:
            self.tree.selection_set(self.tree.get_children()[0])

    def _baseline(self):
        if self.busy or not self.events:
            return
        self._set_busy(True)

        def _run():
            self.detector.train_baseline(self.events, self.entity_var.get())
            self.root.after(0, lambda: self._on_baselined())

        threading.Thread(target=_run, daemon=True).start()

    def _on_baselined(self):
        self._set_busy(False)
        entities = len(self.detector.baselines)
        self._status(f"✓ Baseline built for {entities} entities")

    def _populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        for a in sorted(self.alerts, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.severity, 4)):
            item = self.tree.insert("", tk.END, values=(
                f"  {a.severity}  ", a.name, str(len(a.matched_events)),
                a.description[:120]
            ), tags=(a.severity,))
            setattr(self, f"_item_{item}", a)

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        a = getattr(self, f"_item_{sel[0]}", None)
        if not a:
            return

        color = {"CRITICAL": BLOOD, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": JADE}.get(a.severity, FG)

        self.detail.configure(state=tk.NORMAL)
        self.detail.delete(1.0, tk.END)

        text = f"""╔══════════════════════════════════════════════════════════════╗
║  {a.severity:8s}  │  {a.name}
╠══════════════════════════════════════════════════════════════╣
║  Rule ID:     {a.rule_id}
║  MITRE:       {a.mitre_technique}
║  Matched:     {len(a.matched_events)} events
║  Time:        {a.timestamp}
╠══════════════════════════════════════════════════════════════╣
║  Description:
║    {a.description}
╠══════════════════════════════════════════════════════════════╣
║  Evidence:
║    {a.evidence[:400]}
╚══════════════════════════════════════════════════════════════╝"""

        self.detail.insert(1.0, text)
        self.detail.configure(state=tk.DISABLED)

    def _export(self):
        if not self.alerts:
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"threatlens_alerts_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        )
        if not fp:
            return
        data = {
            "tool": "ThreatLens",
            "version": "1.0.0",
            "generated": datetime.now().isoformat(),
            "total_events": len(self.events),
            "total_alerts": len(self.alerts),
            "alerts": [a.to_dict() for a in self.alerts],
        }
        with open(fp, "w") as f:
            json.dump(data, f, indent=2)
        self._status(f"✓ Exported {len(self.alerts)} alerts → {fp}")

    def _open_settings(self):
        """Open Settings dialog for API key configuration."""
        win = tk.Toplevel(self.root)
        win.title("ThreatLens Settings")
        win.geometry("500x370")
        win.configure(bg=BG_DEEP)
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        # Key management function
        config_dir = os.path.expanduser("~/.config/threatlens")
        config_path = os.path.join(config_dir, "config.json")

        def _read_existing():
            try:
                with open(config_path) as f:
                    return json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                return {}

        existing = _read_existing()

        # Header
        h = tk.Canvas(win, height=60, bg=BG_DEEP, highlightthickness=0)
        h.pack(fill=tk.X)
        for i in range(60):
            t = i / 59
            r = int(0x0a * (1 - t) + 0x7c * t)
            g = int(0x00 * (1 - t) + 0x4d * t)
            b = int(0x08 * (1 - t) + 0xff * t)
            h.create_line(0, i, 500, i, fill=f"#{r:02x}{g:02x}{b:02x}")
        h.create_text(250, 32, text="⚙  THREATLENS  SETTINGS",
                      font=("DejaVu Sans Mono", 14, "bold"), fill=JADE)

        body = tk.Frame(win, bg=BG_CARD, padx=20, pady=15)
        body.pack(fill=tk.BOTH, expand=True)

        # API Key field
        tk.Label(body, text="🔑  THREATLENS_API_KEY", font=("DejaVu Sans Mono", 10, "bold"),
                 fg=FG, bg=BG_CARD).pack(anchor=tk.W, pady=(10, 4))
        tk.Label(body, text="Used to authenticate API requests. Set as Bearer token.",
                 font=("DejaVu Sans Mono", 8), fg=FG_DIM, bg=BG_CARD).pack(anchor=tk.W)

        key_frame = tk.Frame(body, bg=BG_CARD)
        key_frame.pack(fill=tk.X, pady=(6, 10))

        show_var = tk.BooleanVar(value=False)
        key_var = tk.StringVar(value=existing.get("api_key", os.environ.get("THREATLENS_API_KEY", "")))

        key_entry = tk.Entry(key_frame, textvariable=key_var, font=("DejaVu Sans Mono", 10),
                            fg=JADE, bg=INPUT_BG, insertbackground=JADE, relief=tk.FLAT, bd=0,
                            highlightthickness=1, highlightbackground=BORDER, highlightcolor=JADE,
                            show="●")
        key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)

        def _toggle_show():
            key_entry.configure(show="" if show_var.get() else "●")

        cb = tk.Checkbutton(key_frame, text="Show", variable=show_var, command=_toggle_show,
                            font=("DejaVu Sans Mono", 8), fg=FG_DIM, bg=BG_CARD,
                            selectcolor=BG_DEEP, activebackground=BG_CARD, activeforeground=JADE)
        cb.pack(side=tk.LEFT, padx=(8, 0))

        # Port field
        tk.Label(body, text="🔌  Server Port", font=("DejaVu Sans Mono", 10, "bold"),
                 fg=FG, bg=BG_CARD).pack(anchor=tk.W, pady=(10, 4))
        port_var = tk.StringVar(value=existing.get("port", "5150"))
        port_entry = tk.Entry(body, textvariable=port_var, font=("DejaVu Sans Mono", 10),
                              fg=BLUE, bg=INPUT_BG, insertbackground=BLUE, relief=tk.FLAT, bd=0,
                              highlightthickness=1, highlightbackground=BORDER, highlightcolor=BLUE,
                              width=16)
        port_entry.pack(anchor=tk.W, ipady=5)

        # Status label for feedback
        status_var = tk.StringVar(value="")
        status_lbl = tk.Label(body, textvariable=status_var, font=("DejaVu Sans Mono", 8),
                              fg=JADE, bg=BG_CARD)
        status_lbl.pack(anchor=tk.W, pady=(10, 0))

        # Buttons
        btn_frm = tk.Frame(body, bg=BG_CARD)
        btn_frm.pack(fill=tk.X, pady=(15, 5))

        def _save():
            api_key = key_var.get().strip()
            port = port_var.get().strip()
            cfg = {}
            if api_key:
                cfg["api_key"] = api_key
            if port and port != "5150":
                cfg["port"] = port
            try:
                os.makedirs(config_dir, exist_ok=True)
                # Preserve other keys
                prev = _read_existing()
                prev.update(cfg)
                with open(config_path, "w") as f:
                    json.dump(prev, f, indent=2)
                if api_key:
                    os.environ["THREATLENS_API_KEY"] = api_key
                status_var.set(f"✓ Settings saved to {config_path}")
                self.root.after(1500, win.destroy)
            except OSError as exc:
                status_var.set(f"✗ Failed to save: {exc}")

        def _delete_key():
            key_var.set("")
            try:
                prev = _read_existing()
                prev.pop("api_key", None)
                with open(config_path, "w") as f:
                    json.dump(prev, f, indent=2)
                os.environ.pop("THREATLENS_API_KEY", None)
                status_var.set("✓ API key deleted")
            except OSError as exc:
                status_var.set(f"✗ Failed: {exc}")

        tk.Button(btn_frm, text="Delete Key", command=_delete_key,
                  font=("DejaVu Sans Mono", 9), fg=ORANGE, bg=BG_MID, relief=tk.FLAT,
                  activebackground=BLOOD, activeforeground="#000", cursor="hand2",
                  padx=12, pady=4).pack(side=tk.LEFT)
        tk.Button(btn_frm, text="Save", command=_save,
                  font=("DejaVu Sans Mono", 10, "bold"), fg="#000", bg=JADE, relief=tk.FLAT,
                  activebackground=JADE_DIM, cursor="hand2", padx=20, pady=6).pack(side=tk.RIGHT)
        tk.Button(btn_frm, text="Cancel", command=win.destroy,
                  font=("DejaVu Sans Mono", 10), fg=FG_DIM, bg=BG_MID, relief=tk.FLAT,
                  activebackground=BORDER, cursor="hand2", padx=14, pady=4).pack(side=tk.RIGHT, padx=(0, 10))

    def _clear(self):
        self.events = []
        self.alerts = []
        self.tree.delete(*self.tree.get_children())
        self.detail.configure(state=tk.NORMAL)
        self.detail.delete(1.0, tk.END)
        self.detail.configure(state=tk.DISABLED)
        self.btn_detect.configure(state=tk.DISABLED)
        self.btn_baseline.configure(state=tk.DISABLED)
        self.btn_export.configure(state=tk.DISABLED)
        self._status("Cleared. Ready for new logs.")

    def run(self):
        self.root.mainloop()


def main():
    ThreatLensApp().run()


if __name__ == "__main__":
    main()
