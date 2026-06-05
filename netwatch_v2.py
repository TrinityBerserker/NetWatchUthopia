#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║           NetWatch v2.0                  ║
║   Monitor de Red & Conexiones            ║
║   by TrinityBerserker                    ║
╚══════════════════════════════════════════╝

Dependencias:
    pip install customtkinter psutil requests plyer

Ejecutar:
    python netwatch_v2.py

    En Linux puede requerir sudo para ver todos los procesos:
    sudo python netwatch_v2.py

Empaquetar como .exe / .app (requiere: pip install pyinstaller):
    Windows:
        pyinstaller --onefile --windowed --name NetWatch --icon=icon.ico netwatch_v2.py

    macOS:
        pyinstaller --onefile --windowed --name NetWatch netwatch_v2.py

    Linux:
        pyinstaller --onefile --name NetWatch netwatch_v2.py
"""

import customtkinter as ctk
import psutil
import requests
import threading
import time
import json
import os
import sys
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ─── Configuración ──────────────────────────────────────────────────────────────

REFRESH_INTERVAL     = 10          # segundos entre actualizaciones (menos agresivo)
NOTIF_COOLDOWN       = 300         # segundos entre notificaciones de la misma IP
GEO_WORKERS          = 5           # máx peticiones geo simultáneas
GEO_TIMEOUT          = 3           # segundos timeout por petición geo
CACHE_FILE           = Path.home() / ".netwatch_geo_cache.json"  # cache persistente

# Puertos comunes de minería y proxies sospechosos
SUSPICIOUS_PORTS = {
    3333, 4444, 5555, 7777, 8333, 9999, 14444, 45560,
    3032, 8008, 9050, 9051, 1080,
    14433, 5730, 8080,
    6666, 6667, 6668,
}

# Keywords en organización que indican minería
SUSPICIOUS_ORG_KEYWORDS = {
    "mining", "pool", "nicehash", "f2pool", "antpool",
    "minergate", "nanopool", "ethermine", "2miners",
    "viabtc", "slushpool", "poolin", "luxor", "braiins",
}

PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "::1", "fc", "fd")

# Explicaciones en español simple para usuarios no técnicos
PORT_EXPLANATIONS = {
    3333: "Puerto usado por programas de minería de criptomonedas.",
    4444: "Puerto usado por malware o minería de criptomonedas.",
    9050: "Puerto de Tor (red anónima). Puede ser legítimo o sospechoso.",
    9051: "Puerto de control de Tor.",
    1080: "Puerto de proxy SOCKS. Puede usarse para ocultar tráfico.",
    6666: "Puerto histórico de IRC, usado por botnets.",
    6667: "Puerto IRC, usado por botnets.",
    8080: "Puerto alternativo de web. Generalmente normal.",
}

STATUS_EXPLANATIONS = {
    "ESTABLISHED": "Conexión activa y funcionando.",
    "LISTEN":      "El programa está esperando conexiones entrantes.",
    "TIME_WAIT":   "Conexión cerrándose, es normal.",
    "CLOSE_WAIT":  "El servidor remoto cerró la conexión.",
    "SYN_SENT":    "Intentando conectarse a un servidor remoto.",
    "NONE":        "Estado desconocido.",
}

# ─── Tema de colores ─────────────────────────────────────────────────────────────
C = {
    "bg":        "#080c10",
    "surface":   "#0d1117",
    "surface2":  "#161b22",
    "border":    "#21262d",
    "accent":    "#58a6ff",
    "accent2":   "#1f6feb",
    "danger":    "#f85149",
    "danger_bg": "#2d1116",
    "warning":   "#e3b341",
    "warn_bg":   "#1e1a0e",
    "success":   "#3fb950",
    "text":      "#e6edf3",
    "muted":     "#7d8590",
    "subtle":    "#30363d",
    "low_bg":    "#0d1f0d",
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ─── Notificaciones multiplataforma ──────────────────────────────────────────────
_notif_available = False
try:
    from plyer import notification as _plyer_notif
    _notif_available = True
except ImportError:
    pass

_notif_cooldowns: dict = {}
_notif_lock = threading.Lock()


def send_notification(title: str, message: str, ip: str):
    """Envía notificación del sistema con cooldown por IP."""
    if not _notif_available:
        return
    now = time.time()
    with _notif_lock:
        last = _notif_cooldowns.get(ip, 0)
        if now - last < NOTIF_COOLDOWN:
            return
        _notif_cooldowns[ip] = now
    try:
        _plyer_notif.notify(
            title=title,
            message=message,
            app_name="NetWatch",
            timeout=8,
        )
    except Exception:
        pass


# ─── Cache de Geo (memoria + disco) ─────────────────────────────────────────────
_geo_cache: dict = {}
_geo_lock  = threading.Lock()


def _load_cache_from_disk():
    """Carga cache de geo desde archivo JSON."""
    try:
        if CACHE_FILE.exists():
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                with _geo_lock:
                    _geo_cache.update(data)
    except Exception:
        pass


def _save_cache_to_disk():
    """Guarda cache de geo a archivo JSON (solo IPs no privadas)."""
    try:
        with _geo_lock:
            to_save = {k: v for k, v in _geo_cache.items() if v.get("country") != "Local"}
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(to_save, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def flag_emoji(code: str) -> str:
    if not code or len(code) != 2:
        return "🌐"
    try:
        return chr(0x1F1E6 + ord(code[0].upper()) - 65) + chr(0x1F1E6 + ord(code[1].upper()) - 65)
    except Exception:
        return "🌐"


def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def get_geo(ip: str) -> dict:
    """Consulta geolocalización con cache en memoria y disco."""
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]

    if is_private_ip(ip):
        result = {"country": "Local", "countryCode": "", "org": "Red privada / LAN", "flag": "🏠"}
        with _geo_lock:
            _geo_cache[ip] = result
        return result

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,org,isp",
            timeout=GEO_TIMEOUT
        )
        data = r.json()
        if data.get("status") == "success":
            code = data.get("countryCode", "")
            result = {
                "country":     data.get("country", "?"),
                "countryCode": code,
                "org":         (data.get("org") or data.get("isp") or "?")[:40],
                "flag":        flag_emoji(code),
            }
        else:
            result = {"country": "?", "countryCode": "", "org": "?", "flag": "🌐"}
    except Exception:
        result = {"country": "?", "countryCode": "", "org": "?", "flag": "🌐"}

    with _geo_lock:
        _geo_cache[ip] = result
    return result


def batch_geo(ips: list[str]) -> dict[str, dict]:
    """Consulta geolocalización de múltiples IPs en paralelo."""
    results = {}
    # Solo consultar las IPs que no están en cache
    to_fetch = []
    with _geo_lock:
        for ip in ips:
            if ip in _geo_cache:
                results[ip] = _geo_cache[ip]
            else:
                to_fetch.append(ip)

    if not to_fetch:
        return results

    with ThreadPoolExecutor(max_workers=GEO_WORKERS) as executor:
        futures = {executor.submit(get_geo, ip): ip for ip in to_fetch}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                results[ip] = future.result()
            except Exception:
                results[ip] = {"country": "?", "countryCode": "", "org": "?", "flag": "🌐"}

    return results


def get_process_name(pid) -> str:
    if pid is None:
        return "—"
    try:
        return psutil.Process(pid).name()
    except Exception:
        return f"[{pid}]"


def assess_threat(rport: int, geo: dict) -> tuple[str, str]:
    """
    Retorna (nivel, razón).
    Nivel: "ALTO" | "MEDIO" | "BAJO" | "LOCAL"
    """
    if geo.get("country") == "Local":
        return "LOCAL", "Red privada / LAN"

    if rport in SUSPICIOUS_PORTS:
        reason = PORT_EXPLANATIONS.get(rport, f"Puerto sospechoso: {rport}")
        return "ALTO", reason

    org_lower = geo.get("org", "").lower()
    for kw in SUSPICIOUS_ORG_KEYWORDS:
        if kw in org_lower:
            return "ALTO", f"Organización de minería: {geo['org'][:25]}"

    if geo.get("country") in ("?", ""):
        return "MEDIO", "No se pudo identificar el origen de la IP"

    return "BAJO", "Conexión aparentemente normal"


def fmt_bytes_rate(bps: float) -> str:
    if bps < 1024:
        return f"{bps:.0f} B/s"
    elif bps < 1024 ** 2:
        return f"{bps/1024:.1f} KB/s"
    elif bps < 1024 ** 3:
        return f"{bps/1024**2:.2f} MB/s"
    else:
        return f"{bps/1024**3:.2f} GB/s"


# ─── Ventana principal ───────────────────────────────────────────────────────────

class NetWatch(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("NetWatch — Monitor de Red")
        self.geometry("1300x780")
        self.minsize(950, 520)
        self.configure(fg_color=C["bg"])

        self._running       = True
        self._connections   = []
        self._filter_text   = ""
        self._prev_net      = psutil.net_io_counters(pernic=True)
        self._prev_time     = time.time()
        self._sort_col      = "threat_level"
        self._sort_rev      = True
        self._mode_simple   = False   # False = técnico, True = simple
        self._prev_hash     = ""      # para evitar re-render innecesario
        self._notif_enabled = True

        _load_cache_from_disk()
        self._build_ui()
        self._start_bg_refresh()

    # ── Construcción de UI ──────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        self._build_bandwidth_bar()
        self._build_controls()
        self._build_table()
        self._build_detail_panel()
        self._build_footer()

    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=C["surface"], corner_radius=0, height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        ctk.CTkLabel(
            hdr,
            text="◈  NETWATCH",
            font=ctk.CTkFont("Courier New", 20, "bold"),
            text_color=C["accent"],
        ).pack(side="left", padx=18, pady=10)

        ctk.CTkLabel(
            hdr,
            text="Monitor de Conexiones & Red  v2.0",
            font=ctk.CTkFont("Courier New", 11),
            text_color=C["muted"],
        ).pack(side="left", padx=0, pady=10)

        # Toggle modo simple/técnico
        self.btn_mode = ctk.CTkButton(
            hdr,
            text="👁 Modo Simple",
            width=130,
            height=28,
            fg_color=C["surface2"],
            hover_color=C["border"],
            border_width=1,
            border_color=C["subtle"],
            font=ctk.CTkFont("Courier New", 10),
            text_color=C["accent"],
            command=self._toggle_mode,
        )
        self.btn_mode.pack(side="right", padx=10)

        # Toggle notificaciones
        self.btn_notif = ctk.CTkButton(
            hdr,
            text="🔔 Alertas: ON" if _notif_available else "🔕 Alertas: N/A",
            width=130,
            height=28,
            fg_color=C["surface2"],
            hover_color=C["border"],
            border_width=1,
            border_color=C["subtle"],
            font=ctk.CTkFont("Courier New", 10),
            text_color=C["success"] if _notif_available else C["muted"],
            command=self._toggle_notif,
            state="normal" if _notif_available else "disabled",
        )
        self.btn_notif.pack(side="right", padx=4)

        self.lbl_live = ctk.CTkLabel(
            hdr, text="● INICIANDO",
            font=ctk.CTkFont("Courier New", 11, "bold"),
            text_color=C["warning"],
        )
        self.lbl_live.pack(side="right", padx=18)

        self.lbl_time = ctk.CTkLabel(
            hdr, text="",
            font=ctk.CTkFont("Courier New", 11),
            text_color=C["muted"],
        )
        self.lbl_time.pack(side="right", padx=4)

    def _build_bandwidth_bar(self):
        self.bw_frame = ctk.CTkFrame(self, fg_color=C["surface2"], corner_radius=0, height=34)
        self.bw_frame.pack(fill="x", pady=(1, 0))
        self.bw_frame.pack_propagate(False)

        ctk.CTkLabel(
            self.bw_frame,
            text="INTERFACES :",
            font=ctk.CTkFont("Courier New", 10, "bold"),
            text_color=C["muted"],
        ).pack(side="left", padx=(12, 6), pady=6)

        self._bw_labels: dict[str, ctk.CTkLabel] = {}
        for iface in psutil.net_io_counters(pernic=True):
            lbl = ctk.CTkLabel(
                self.bw_frame,
                text=f"{iface}  ↑ ---  ↓ ---",
                font=ctk.CTkFont("Courier New", 10),
                text_color=C["text"],
            )
            lbl.pack(side="left", padx=14, pady=6)
            self._bw_labels[iface] = lbl

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self, fg_color="transparent")
        ctrl.pack(fill="x", padx=10, pady=(6, 2))

        ctk.CTkLabel(
            ctrl, text="Buscar:",
            font=ctk.CTkFont("Courier New", 11),
            text_color=C["muted"],
        ).pack(side="left", padx=(2, 4))

        self.entry_filter = ctk.CTkEntry(
            ctrl, width=180,
            fg_color=C["surface2"],
            border_color=C["subtle"],
            text_color=C["text"],
            font=ctk.CTkFont("Courier New", 11),
            placeholder_text="proceso o IP...",
        )
        self.entry_filter.pack(side="left", padx=4)
        self.entry_filter.bind("<KeyRelease>", lambda e: self._apply_filter())

        # Filtro de riesgo
        ctk.CTkLabel(
            ctrl, text="Riesgo:",
            font=ctk.CTkFont("Courier New", 11),
            text_color=C["muted"],
        ).pack(side="left", padx=(12, 4))

        self.risk_filter = ctk.CTkOptionMenu(
            ctrl,
            values=["Todos", "ALTO", "MEDIO", "BAJO", "LOCAL"],
            width=100,
            fg_color=C["surface2"],
            button_color=C["subtle"],
            font=ctk.CTkFont("Courier New", 11),
            command=lambda _: self._apply_filter(),
        )
        self.risk_filter.pack(side="left", padx=4)

        # Botón refresh
        ctk.CTkButton(
            ctrl,
            text="↻  Actualizar",
            width=110,
            height=28,
            fg_color=C["accent2"],
            hover_color=C["accent"],
            font=ctk.CTkFont("Courier New", 11, "bold"),
            command=self._force_refresh,
        ).pack(side="left", padx=8)

        # Botón limpiar cache
        ctk.CTkButton(
            ctrl,
            text="🗑 Limpiar caché",
            width=130,
            height=28,
            fg_color=C["surface2"],
            hover_color=C["border"],
            border_width=1,
            border_color=C["subtle"],
            font=ctk.CTkFont("Courier New", 11),
            text_color=C["muted"],
            command=self._clear_geo_cache,
        ).pack(side="left", padx=4)

        self.lbl_counts = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont("Courier New", 11),
            text_color=C["muted"],
        )
        self.lbl_counts.pack(side="right", padx=8)

    def _build_table(self):
        # Columnas técnicas
        self.COLS_TECH = [
            ("pid",         "PID",           55),
            ("proc",        "Proceso",       140),
            ("laddr",       "IP Local",      150),
            ("raddr",       "IP Remota",     165),
            ("country",     "País",          110),
            ("org",         "Organización",  190),
            ("status",      "Estado",        90),
            ("threat_level","Riesgo",        70),
        ]

        # Columnas modo simple
        self.COLS_SIMPLE = [
            ("proc",        "¿Qué programa?", 170),
            ("raddr",       "Conectado a",    185),
            ("country",     "País",           120),
            ("org",         "Empresa / ISP",  210),
            ("threat_level","¿Es seguro?",    90),
            ("status",      "Estado",         110),
        ]

        self.th_frame = ctk.CTkFrame(self, fg_color=C["subtle"], corner_radius=0, height=26)
        self.th_frame.pack(fill="x", padx=10, pady=(4, 0))
        self.th_frame.pack_propagate(False)

        self._build_table_headers()

        self.scroll_frame = ctk.CTkScrollableFrame(
            self,
            fg_color=C["bg"],
            scrollbar_button_color=C["subtle"],
            scrollbar_button_hover_color=C["border"],
            corner_radius=0,
        )
        self.scroll_frame.pack(fill="both", expand=True, padx=10, pady=(0, 2))

    def _build_table_headers(self):
        for w in self.th_frame.winfo_children():
            w.destroy()

        cols = self.COLS_SIMPLE if self._mode_simple else self.COLS_TECH
        for col_id, label, width in cols:
            btn = ctk.CTkButton(
                self.th_frame,
                text=label,
                width=width,
                height=24,
                fg_color="transparent",
                hover_color=C["border"],
                text_color=C["muted"],
                font=ctk.CTkFont("Courier New", 9, "bold"),
                anchor="w",
                command=lambda c=col_id: self._sort_by(c),
            )
            btn.pack(side="left", padx=2, pady=1)

    def _build_detail_panel(self):
        self.detail_frame = ctk.CTkFrame(self, fg_color=C["surface2"], corner_radius=0, height=70)
        self.detail_frame.pack(fill="x", padx=10, pady=(0, 2))
        self.detail_frame.pack_propagate(False)

        top_row = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        top_row.pack(fill="x", padx=10, pady=(6, 0))

        ctk.CTkLabel(
            top_row,
            text="DETALLE :",
            font=ctk.CTkFont("Courier New", 10, "bold"),
            text_color=C["muted"],
        ).pack(side="left", padx=(2, 8))

        self.lbl_detail = ctk.CTkLabel(
            top_row,
            text="Haz clic en una conexión para ver más información",
            font=ctk.CTkFont("Courier New", 10),
            text_color=C["muted"],
            wraplength=950,
            justify="left",
        )
        self.lbl_detail.pack(side="left")

        self.lbl_explain = ctk.CTkLabel(
            self.detail_frame,
            text="",
            font=ctk.CTkFont("Courier New", 10),
            text_color=C["warning"],
            wraplength=1100,
            justify="left",
        )
        self.lbl_explain.pack(fill="x", padx=12, pady=(2, 6))

    def _build_footer(self):
        ft = ctk.CTkFrame(self, fg_color=C["surface"], corner_radius=0, height=22)
        ft.pack(fill="x", side="bottom")
        ft.pack_propagate(False)

        for color, text in [
            (C["danger"],  "■ Riesgo ALTO"),
            (C["warning"], "■ Riesgo MEDIO"),
            (C["success"], "■ Riesgo BAJO"),
            (C["muted"],   "■ LOCAL / LAN"),
        ]:
            ctk.CTkLabel(
                ft, text=text,
                font=ctk.CTkFont("Courier New", 9),
                text_color=color,
            ).pack(side="left", padx=10)

        ctk.CTkLabel(
            ft,
            text="NetWatch v2.0 — TrinityBerserker",
            font=ctk.CTkFont("Courier New", 9),
            text_color=C["muted"],
        ).pack(side="right", padx=12)

    # ── Lógica de datos ─────────────────────────────────────────────────────────

    def _fetch_connections(self) -> list[dict]:
        results = []
        try:
            raw = psutil.net_connections(kind="inet")
        except PermissionError:
            self.after(0, lambda: self.lbl_detail.configure(
                text="⚠ Permisos insuficientes. Ejecuta con sudo (Linux/Mac) o como Administrador (Windows).",
                text_color=C["warning"]
            ))
            return results
        except Exception as e:
            print(f"[!] Error obteniendo conexiones: {e}")
            return results

        # Recopilar IPs únicas para batch geo
        unique_ips = list({conn.raddr.ip for conn in raw if conn.raddr})
        geo_map = batch_geo(unique_ips)

        for conn in raw:
            if not conn.raddr:
                continue

            rip   = conn.raddr.ip
            rport = conn.raddr.port
            geo   = geo_map.get(rip, {"country": "?", "countryCode": "", "org": "?", "flag": "🌐"})
            proc  = get_process_name(conn.pid)
            level, reason = assess_threat(rport, geo)

            # Notificar si es ALTO riesgo
            if level == "ALTO" and self._notif_enabled:
                threading.Thread(
                    target=send_notification,
                    args=(
                        "⚠ NetWatch — Conexión sospechosa",
                        f"Proceso: {proc}\nIP: {rip}:{rport}\n{reason}",
                        rip,
                    ),
                    daemon=True,
                ).start()

            # Estado en español simple
            raw_status = conn.status or "NONE"
            status_es  = STATUS_EXPLANATIONS.get(raw_status, raw_status)

            results.append({
                "pid":         conn.pid,
                "proc":        proc,
                "laddr":       f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—",
                "raddr":       f"{rip}:{rport}",
                "rip":         rip,
                "rport":       rport,
                "country":     geo.get("country", "?"),
                "flag":        geo.get("flag", "🌐"),
                "org":         geo.get("org", "?"),
                "status":      raw_status,
                "status_es":   status_es,
                "threat_level":level,
                "reason":      reason,
                "geo":         geo,
            })

        # Ordenar
        order_map = {"ALTO": 0, "MEDIO": 1, "BAJO": 2, "LOCAL": 3}
        if self._sort_col == "threat_level":
            results.sort(
                key=lambda x: order_map.get(x.get("threat_level", "BAJO"), 2),
                reverse=self._sort_rev,
            )
        else:
            try:
                results.sort(
                    key=lambda x: str(x.get(self._sort_col, "")).lower(),
                    reverse=self._sort_rev,
                )
            except Exception:
                pass

        return results

    def _update_bandwidth(self):
        now = time.time()
        current = psutil.net_io_counters(pernic=True)
        dt = now - self._prev_time
        if dt <= 0:
            return

        for iface, lbl in self._bw_labels.items():
            if iface in current and iface in self._prev_net:
                up   = (current[iface].bytes_sent - self._prev_net[iface].bytes_sent) / dt
                down = (current[iface].bytes_recv - self._prev_net[iface].bytes_recv) / dt
                lbl.configure(
                    text=f"{iface}  ↑ {fmt_bytes_rate(up)}  ↓ {fmt_bytes_rate(down)}"
                )

        self._prev_net  = current
        self._prev_time = now

    # ── Render de filas ─────────────────────────────────────────────────────────

    def _render_rows(self, connections: list[dict]):
        # Evitar re-render si no hay cambios
        snap = str([(c["raddr"], c["threat_level"], c["proc"]) for c in connections])
        if snap == self._prev_hash:
            return
        self._prev_hash = snap

        for w in self.scroll_frame.winfo_children():
            w.destroy()

        filt      = self._filter_text.lower()
        risk_filt = self.risk_filter.get() if hasattr(self, "risk_filter") else "Todos"
        shown = alto = medio = bajo = local_c = 0

        cols = self.COLS_SIMPLE if self._mode_simple else self.COLS_TECH

        for conn in connections:
            proc  = conn.get("proc", "?")
            level = conn.get("threat_level", "BAJO")

            # Filtros
            if filt and filt not in proc.lower() and filt not in conn.get("rip", "").lower():
                continue
            if risk_filt != "Todos" and level != risk_filt:
                continue

            # Color según riesgo
            if level == "ALTO":
                row_bg = C["danger_bg"]; txt_color = C["danger"]; alto += 1
            elif level == "MEDIO":
                row_bg = C["warn_bg"];   txt_color = C["warning"]; medio += 1
            elif level == "LOCAL":
                row_bg = C["surface"];   txt_color = C["muted"];   local_c += 1
            else:
                row_bg = C["low_bg"];    txt_color = C["success"]; bajo += 1

            row = ctk.CTkFrame(
                self.scroll_frame,
                fg_color=row_bg,
                corner_radius=3,
                height=24,
                cursor="hand2",
            )
            row.pack(fill="x", pady=1)
            row.pack_propagate(False)

            # Construir celdas según modo
            if self._mode_simple:
                risk_txt = {
                    "ALTO":  "⚠ SOSPECHOSO",
                    "MEDIO": "⚡ REVISAR",
                    "BAJO":  "✓ NORMAL",
                    "LOCAL": "🏠 LOCAL",
                }.get(level, level)

                status_display = conn.get("status_es", conn.get("status", "—"))

                cells = [
                    (proc[:22],                                          170),
                    (conn.get("raddr", "—")[:25],                       185),
                    (f"{conn.get('flag','🌐')} {conn.get('country','?')[:10]}", 120),
                    (conn.get("org", "?")[:28],                         210),
                    (risk_txt,                                           90),
                    (status_display[:18],                                110),
                ]
            else:
                risk_color_map = {
                    "ALTO": C["danger"], "MEDIO": C["warning"],
                    "BAJO": C["success"], "LOCAL": C["muted"],
                }
                cells = [
                    (str(conn.get("pid") or "—"),                        55),
                    (proc[:17],                                          140),
                    (conn.get("laddr", "—")[:20],                       150),
                    (conn.get("raddr", "—")[:22],                       165),
                    (f"{conn.get('flag','🌐')} {conn.get('country','?')[:10]}", 110),
                    (conn.get("org", "?")[:26],                         190),
                    (conn.get("status", "—"),                           90),
                    (level,                                              70),
                ]

            for i, (val, w) in enumerate(cells):
                # En modo técnico, colorear columna de riesgo
                if not self._mode_simple and i == 7:
                    lbl_color = {
                        "ALTO": C["danger"], "MEDIO": C["warning"],
                        "BAJO": C["success"], "LOCAL": C["muted"],
                    }.get(level, txt_color)
                else:
                    lbl_color = txt_color

                ctk.CTkLabel(
                    row,
                    text=val,
                    width=w,
                    font=ctk.CTkFont("Courier New", 10),
                    text_color=lbl_color,
                    anchor="w",
                ).pack(side="left", padx=3)

            conn_snap = dict(conn)
            row.bind("<Button-1>", lambda e, c=conn_snap: self._show_detail(c))
            for child in row.winfo_children():
                child.bind("<Button-1>", lambda e, c=conn_snap: self._show_detail(c))

            shown += 1

        # Actualizar contadores
        self.lbl_counts.configure(
            text=f"Total: {shown}  |  ⚠ Alto: {alto}  |  ⚡ Medio: {medio}  |  ✓ Bajo: {bajo}  |  🏠 Local: {local_c}"
        )

    def _show_detail(self, conn: dict):
        if self._mode_simple:
            # Explicación amigable
            proc    = conn.get("proc", "?")
            country = conn.get("country", "?")
            org     = conn.get("org", "?")
            raddr   = conn.get("raddr", "?")
            level   = conn.get("threat_level", "BAJO")
            reason  = conn.get("reason", "")
            status_es = conn.get("status_es", conn.get("status", ""))

            detail = (
                f"El programa '{proc}' está conectado a {raddr} "
                f"({conn.get('flag','')} {country} — {org}).  "
                f"Estado: {status_es}"
            )
            explain = f"{'⚠ ' if level == 'ALTO' else ''}{reason}" if reason else ""
        else:
            reason_txt = f"  ⚠ {conn['reason']}" if conn.get("reason") else ""
            detail = (
                f"PID {conn.get('pid','?')}  |  Proceso: {conn.get('proc','?')}  |  "
                f"Local: {conn.get('laddr','?')}  →  Remoto: {conn.get('raddr','?')}  |  "
                f"País: {conn.get('flag','')} {conn.get('country','?')}  |  "
                f"Org: {conn.get('org','?')}  |  Estado: {conn.get('status','?')}"
                f"{reason_txt}"
            )
            explain = conn.get("status_es", "")

        level = conn.get("threat_level", "BAJO")
        color_map = {
            "ALTO": C["danger"], "MEDIO": C["warning"],
            "BAJO": C["text"],   "LOCAL": C["muted"],
        }
        self.lbl_detail.configure(text=detail, text_color=color_map.get(level, C["text"]))
        self.lbl_explain.configure(text=explain, text_color=C["warning"] if level in ("ALTO", "MEDIO") else C["muted"])

    # ── Interacciones ────────────────────────────────────────────────────────────

    def _apply_filter(self):
        self._filter_text = self.entry_filter.get().strip()
        self._prev_hash   = ""  # forzar re-render
        self._render_rows(self._connections)

    def _sort_by(self, col_id: str):
        if self._sort_col == col_id:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col_id
            self._sort_rev = False
        self._prev_hash = ""
        self._render_rows(self._connections)

    def _force_refresh(self):
        self._prev_hash = ""
        self.lbl_live.configure(text="● ACTUALIZANDO", text_color=C["warning"])
        threading.Thread(target=self._do_refresh, daemon=True).start()

    def _clear_geo_cache(self):
        with _geo_lock:
            _geo_cache.clear()
        try:
            CACHE_FILE.unlink(missing_ok=True)
        except Exception:
            pass
        self._force_refresh()

    def _toggle_mode(self):
        self._mode_simple = not self._mode_simple
        label = "🖥 Modo Técnico" if self._mode_simple else "👁 Modo Simple"
        self.btn_mode.configure(text=label)
        self._build_table_headers()
        self._prev_hash = ""
        self._render_rows(self._connections)

    def _toggle_notif(self):
        self._notif_enabled = not self._notif_enabled
        label = "🔔 Alertas: ON" if self._notif_enabled else "🔕 Alertas: OFF"
        color = C["success"] if self._notif_enabled else C["muted"]
        self.btn_notif.configure(text=label, text_color=color)

    # ── Loop de actualización ────────────────────────────────────────────────────

    def _do_refresh(self):
        conns = self._fetch_connections()
        self._connections = conns
        self.after(0, self._render_rows, conns)
        self.after(0, self._update_bandwidth)
        self.after(0, self._tick_status)
        _save_cache_to_disk()

    def _bg_loop(self):
        while self._running:
            self._do_refresh()
            time.sleep(REFRESH_INTERVAL)

    def _start_bg_refresh(self):
        threading.Thread(target=self._bg_loop, daemon=True).start()

    def _tick_status(self):
        now = datetime.now().strftime("%H:%M:%S")
        self.lbl_time.configure(text=now)
        self.lbl_live.configure(text="● LIVE", text_color=C["success"])

    # ── Cierre ───────────────────────────────────────────────────────────────────

    def on_closing(self):
        self._running = False
        _save_cache_to_disk()
        self.destroy()


# ─── Entry point ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = NetWatch()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
