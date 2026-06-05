#!/usr/bin/env python3
"""
╔═══════════════════════════════════════╗
║         NetWatch v1.0                 ║
║   Monitor de Red & Conexiones         ║
║   by TrinityBerserker                 ║
╚═══════════════════════════════════════╝

Dependencias:
    pip install customtkinter psutil requests

Ejecutar:
    python netwatch.py
    
    En Linux puede requerir sudo para ver todos los procesos:
    sudo python netwatch.py
"""

import customtkinter as ctk
import psutil
import requests
import threading
import time
import socket
from datetime import datetime
from collections import defaultdict

# ─── Configuración ─────────────────────────────────────────────────────────────

REFRESH_INTERVAL = 5  # segundos entre actualizaciones automáticas

# Puertos comunes de minería de crypto y proxies sospechosos
SUSPICIOUS_PORTS = {
    3333, 4444, 5555, 7777, 8333, 9999, 14444, 45560,
    3032, 8008, 9050, 9051, 1080,   # Tor / SOCKS
    14433, 5730, 8080,               # pools alternativos
    6666, 6667, 6668,                # IRC (usados por botnets)
}

# Keywords en nombre de organización que indican minería
SUSPICIOUS_ORG_KEYWORDS = {
    "mining", "pool", "nicehash", "f2pool", "antpool",
    "minergate", "nanopool", "ethermine", "2miners",
    "viabtc", "slushpool", "poolin", "luxor", "braiins",
}

# IPs privadas / localhost
PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "::1", "fc", "fd")

# ─── Cache de Geo ───────────────────────────────────────────────────────────────
_geo_cache: dict = {}
_geo_lock = threading.Lock()

# ─── Tema de colores ────────────────────────────────────────────────────────────
C = {
    "bg":       "#080c10",
    "surface":  "#0d1117",
    "surface2": "#161b22",
    "border":   "#21262d",
    "accent":   "#58a6ff",
    "accent2":  "#1f6feb",
    "danger":   "#f85149",
    "danger_bg":"#2d1116",
    "warning":  "#e3b341",
    "warn_bg":  "#1e1a0e",
    "success":  "#3fb950",
    "text":     "#e6edf3",
    "muted":    "#7d8590",
    "subtle":   "#30363d",
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ─── Helpers ────────────────────────────────────────────────────────────────────

def flag_emoji(code: str) -> str:
    """Convierte código de país a emoji de bandera."""
    if not code or len(code) != 2:
        return "🌐"
    try:
        return chr(0x1F1E6 + ord(code[0].upper()) - 65) + chr(0x1F1E6 + ord(code[1].upper()) - 65)
    except Exception:
        return "🌐"


def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def get_geo(ip: str) -> dict:
    """Consulta geolocalización de IP con cache."""
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
            timeout=3
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


def get_process_name(pid) -> str:
    if pid is None:
        return "—"
    try:
        return psutil.Process(pid).name()
    except Exception:
        return f"[{pid}]"


def assess_threat(rport: int, geo: dict) -> tuple[bool, str]:
    """Retorna (es_sospechoso, razón)."""
    if rport in SUSPICIOUS_PORTS:
        return True, f"Puerto sospechoso: {rport}"
    org_lower = geo.get("org", "").lower()
    for kw in SUSPICIOUS_ORG_KEYWORDS:
        if kw in org_lower:
            return True, f"Org minería: {geo['org'][:25]}"
    return False, ""


def fmt_bytes_rate(bps: float) -> str:
    """Formatea bytes/s a string legible."""
    if bps < 1024:
        return f"{bps:.0f} B/s"
    elif bps < 1024 ** 2:
        return f"{bps/1024:.1f} KB/s"
    else:
        return f"{bps/1024**2:.2f} MB/s"


# ─── Ventana principal ──────────────────────────────────────────────────────────

class NetWatch(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("NetWatch — Monitor de Red")
        self.geometry("1280x760")
        self.minsize(900, 500)
        self.configure(fg_color=C["bg"])

        self._running       = True
        self._connections   = []
        self._filter_text   = ""
        self._prev_net      = psutil.net_io_counters(pernic=True)
        self._prev_time     = time.time()
        self._sort_col      = "proc"   # columna de orden
        self._sort_rev      = False
        self._selected_row  = None

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

        # Logo / título
        ctk.CTkLabel(
            hdr,
            text="◈  NETWATCH",
            font=ctk.CTkFont("Courier New", 20, "bold"),
            text_color=C["accent"],
        ).pack(side="left", padx=18, pady=10)

        ctk.CTkLabel(
            hdr,
            text="Monitor de Conexiones & Red",
            font=ctk.CTkFont("Courier New", 11),
            text_color=C["muted"],
        ).pack(side="left", padx=0, pady=10)

        # Status indicator
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

        # Filtro
        ctk.CTkLabel(
            ctrl, text="Proceso:",
            font=ctk.CTkFont("Courier New", 11),
            text_color=C["muted"],
        ).pack(side="left", padx=(2, 4))

        self.entry_filter = ctk.CTkEntry(
            ctrl, width=180,
            fg_color=C["surface2"],
            border_color=C["subtle"],
            text_color=C["text"],
            font=ctk.CTkFont("Courier New", 11),
            placeholder_text="filtrar...",
        )
        self.entry_filter.pack(side="left", padx=4)
        self.entry_filter.bind("<KeyRelease>", lambda e: self._apply_filter())

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

        # Botón limpiar cache geo
        ctk.CTkButton(
            ctrl,
            text="Limpiar caché geo",
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

        # Contadores
        self.lbl_counts = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont("Courier New", 11),
            text_color=C["muted"],
        )
        self.lbl_counts.pack(side="right", padx=8)

    def _build_table(self):
        # Columnas: (nombre_interno, header_texto, ancho)
        self.COLS = [
            ("pid",     "PID",           55),
            ("proc",    "Proceso",       140),
            ("laddr",   "IP Local",      155),
            ("raddr",   "IP Remota",     165),
            ("country", "País",          110),
            ("org",     "Organización",  200),
            ("status",  "Estado",        90),
            ("threat",  "⚠",             28),
        ]

        # Header de tabla
        th_frame = ctk.CTkFrame(self, fg_color=C["subtle"], corner_radius=0, height=26)
        th_frame.pack(fill="x", padx=10, pady=(4, 0))
        th_frame.pack_propagate(False)

        for col_id, label, width in self.COLS:
            btn = ctk.CTkButton(
                th_frame,
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

        # Área scrollable
        self.scroll_frame = ctk.CTkScrollableFrame(
            self,
            fg_color=C["bg"],
            scrollbar_button_color=C["subtle"],
            scrollbar_button_hover_color=C["border"],
            corner_radius=0,
        )
        self.scroll_frame.pack(fill="both", expand=True, padx=10, pady=(0, 2))

    def _build_detail_panel(self):
        """Panel colapsable en la parte inferior para detalles de conexión seleccionada."""
        self.detail_frame = ctk.CTkFrame(self, fg_color=C["surface2"], corner_radius=0, height=54)
        self.detail_frame.pack(fill="x", padx=10, pady=(0, 2))
        self.detail_frame.pack_propagate(False)

        ctk.CTkLabel(
            self.detail_frame,
            text="DETALLE :",
            font=ctk.CTkFont("Courier New", 10, "bold"),
            text_color=C["muted"],
        ).pack(side="left", padx=12, pady=6)

        self.lbl_detail = ctk.CTkLabel(
            self.detail_frame,
            text="Haz clic en una conexión para ver detalles",
            font=ctk.CTkFont("Courier New", 10),
            text_color=C["muted"],
            wraplength=900,
            justify="left",
        )
        self.lbl_detail.pack(side="left", padx=4, pady=6)

    def _build_footer(self):
        ft = ctk.CTkFrame(self, fg_color=C["surface"], corner_radius=0, height=22)
        ft.pack(fill="x", side="bottom")
        ft.pack_propagate(False)

        for color, text in [
            (C["danger"],  "■ Sospechoso"),
            (C["warning"], "■ Sin geo / desconocido"),
            (C["success"], "■ Normal"),
            (C["muted"],   "■ Local / LAN"),
        ]:
            ctk.CTkLabel(
                ft, text=text,
                font=ctk.CTkFont("Courier New", 9),
                text_color=color,
            ).pack(side="left", padx=10)

        ctk.CTkLabel(
            ft,
            text="NetWatch v1.0 — TrinityBerserker",
            font=ctk.CTkFont("Courier New", 9),
            text_color=C["muted"],
        ).pack(side="right", padx=12)

    # ── Lógica de datos ─────────────────────────────────────────────────────────

    def _fetch_connections(self) -> list[dict]:
        results = []
        try:
            raw = psutil.net_connections(kind="inet")
        except Exception as e:
            print(f"[!] Error obteniendo conexiones: {e}")
            return results

        for conn in raw:
            if not conn.raddr:
                continue

            rip   = conn.raddr.ip
            rport = conn.raddr.port
            geo   = get_geo(rip)
            proc  = get_process_name(conn.pid)
            susp, reason = assess_threat(rport, geo)

            results.append({
                "pid":     conn.pid,
                "proc":    proc,
                "laddr":   f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—",
                "raddr":   f"{rip}:{rport}",
                "rip":     rip,
                "rport":   rport,
                "country": geo.get("country", "?"),
                "flag":    geo.get("flag", "🌐"),
                "org":     geo.get("org", "?"),
                "status":  conn.status or "—",
                "threat":  susp,
                "reason":  reason,
                "geo":     geo,
            })

        # Ordenar
        key = self._sort_col
        try:
            results.sort(
                key=lambda x: str(x.get(key, "")).lower(),
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
        # Destruir filas previas
        for w in self.scroll_frame.winfo_children():
            w.destroy()

        filt = self._filter_text.lower()
        shown = suspicious = local_count = 0

        for conn in connections:
            proc = conn.get("proc", "?")
            country = conn.get("country", "?")
            is_local = country == "Local"
            is_susp  = conn.get("threat", False)
            is_unkn  = country == "?" and not is_local

            # Aplicar filtro
            if filt and filt not in proc.lower() and filt not in conn.get("rip","").lower():
                continue

            # Color de fila
            if is_susp:
                row_bg    = C["danger_bg"]
                txt_color = C["danger"]
                suspicious += 1
            elif is_unkn:
                row_bg    = C["warn_bg"]
                txt_color = C["warning"]
            elif is_local:
                row_bg    = C["surface"]
                txt_color = C["muted"]
                local_count += 1
            else:
                row_bg    = C["surface2"]
                txt_color = C["text"]

            row = ctk.CTkFrame(
                self.scroll_frame,
                fg_color=row_bg,
                corner_radius=3,
                height=24,
                cursor="hand2",
            )
            row.pack(fill="x", pady=1)
            row.pack_propagate(False)

            # Datos de columnas
            cells = [
                (str(conn.get("pid") or "—"),                               55),
                (proc[:17],                                                  140),
                (conn.get("laddr", "—")[:20],                               155),
                (conn.get("raddr", "—")[:22],                               165),
                (f"{conn.get('flag','🌐')} {country[:10]}",                 110),
                (conn.get("org", "?")[:28],                                 200),
                (conn.get("status", "—"),                                   90),
                ("⚠" if is_susp else "",                                    28),
            ]

            for i, (val, w) in enumerate(cells):
                color = C["danger"] if (i == 7 and is_susp) else txt_color
                ctk.CTkLabel(
                    row,
                    text=val,
                    width=w,
                    font=ctk.CTkFont("Courier New", 10),
                    text_color=color,
                    anchor="w",
                ).pack(side="left", padx=3)

            # Click para detalle
            conn_snap = dict(conn)
            row.bind("<Button-1>", lambda e, c=conn_snap: self._show_detail(c))
            for child in row.winfo_children():
                child.bind("<Button-1>", lambda e, c=conn_snap: self._show_detail(c))

            shown += 1

        # Actualizar contadores
        self.lbl_counts.configure(
            text=f"Mostrando {shown}  |  ⚠ {suspicious} sospechosas  |  🏠 {local_count} locales"
        )

    def _show_detail(self, conn: dict):
        reason_txt = f"  ⚠ RAZÓN: {conn['reason']}" if conn.get("reason") else ""
        detail = (
            f"PID {conn.get('pid','?')}  |  Proceso: {conn.get('proc','?')}  |  "
            f"Local: {conn.get('laddr','?')}  →  Remoto: {conn.get('raddr','?')}  |  "
            f"País: {conn.get('flag','')} {conn.get('country','?')}  |  "
            f"Org: {conn.get('org','?')}  |  "
            f"Estado: {conn.get('status','?')}"
            f"{reason_txt}"
        )
        self.lbl_detail.configure(
            text=detail,
            text_color=C["danger"] if conn.get("threat") else C["text"],
        )

    # ── Interacciones ────────────────────────────────────────────────────────────

    def _apply_filter(self):
        self._filter_text = self.entry_filter.get().strip()
        self._render_rows(self._connections)

    def _sort_by(self, col_id: str):
        if self._sort_col == col_id:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col_id
            self._sort_rev = False
        self._render_rows(self._connections)

    def _force_refresh(self):
        self.lbl_live.configure(text="● ACTUALIZANDO", text_color=C["warning"])
        threading.Thread(target=self._do_refresh, daemon=True).start()

    def _clear_geo_cache(self):
        with _geo_lock:
            _geo_cache.clear()
        self._force_refresh()

    # ── Loop de actualización ────────────────────────────────────────────────────

    def _do_refresh(self):
        conns = self._fetch_connections()
        self._connections = conns
        self.after(0, self._render_rows, conns)
        self.after(0, self._update_bandwidth)
        self.after(0, self._tick_status)

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
        self.destroy()


# ─── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = NetWatch()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
