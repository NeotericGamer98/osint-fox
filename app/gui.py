import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
import time
import re
from datetime import datetime

from modules.registry import discover_modules
from modules.username import UsernameModule
from modules.email import EmailModule
from modules.phone import PhoneModule
from modules.domain import DomainModule
from modules.social import SocialModule
from modules.image import ImageModule
from modules.breaches import BreachModule
from modules.geo import GeoModule
from utils.exporter import EXPORT_FORMATS, export_to_pdf, export_to_txt, export_to_csv, export_to_json, export_to_html
from app.theme import Theme, CURRENT as theme
from app.session import SessionManager
from app.settings import AppSettings
from utils.apikeys import APIKeyManager
from utils.network import set_proxy, clear_proxy, get_proxy

VERSION = "v1.2"
session_mgr = SessionManager()
api_keys = APIKeyManager()
settings = AppSettings()


MODULES = {
    "Username": UsernameModule(),
    "Email": EmailModule(),
    "Phone": PhoneModule(),
    "Domain": DomainModule(),
    "Social Analyzer": SocialModule(),
    "Image": ImageModule(),
    "Breach Lookup": BreachModule(),
    "Geolocation": GeoModule(),
}

MODULE_ICONS = {
    "Username": "\U0001F575", "Email": "\u2709", "Phone": "\U0001F4DE",
    "Domain": "\U0001F310", "Social Analyzer": "\U0001F465", "Image": "\U0001F5BC",
    "Breach Lookup": "\U0001F50D", "Geolocation": "\U0001F30D",
}

INPUT_HINTS = {
    "Username": "Enter username (e.g. johndoe)",
    "Email": "Enter email (e.g. user@example.com)",
    "Phone": "Enter phone (e.g. +1234567890)",
    "Domain": "Enter domain or IP (e.g. example.com)",
    "Social Analyzer": "Enter username (e.g. johndoe)",
    "Image": "Enter image URL or local file path (or drag & drop)",
    "Breach Lookup": "Enter email, username, or phone",
    "Geolocation": "Enter IP address or domain",
}

MODULE_NAMES = [
    "Username", "Email", "Phone", "Domain",
    "Social Analyzer", "Image", "Breach Lookup", "Geolocation",
]


def apply_theme():
    ctk.set_appearance_mode("Dark" if theme.dark else "Light")


class TabManager:
    def __init__(self):
        self.tabs = []
        self.active = -1

    def add(self, tab_id, title, target, module_name, results_flat):
        self.tabs.append({"id": tab_id, "title": title, "target": target,
                          "module": module_name, "results_flat": results_flat})
        self.active = len(self.tabs) - 1

    def remove(self, tab_id):
        self.tabs = [t for t in self.tabs if t["id"] != tab_id]
        if self.active >= len(self.tabs):
            self.active = len(self.tabs) - 1

    def get_active(self):
        if 0 <= self.active < len(self.tabs):
            return self.tabs[self.active]
        return None


class OSINTFoxApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title(f"OSINT FOX {VERSION}")
        self.root.minsize(1000, 650)

        saved_geo = settings.get("window_geometry")
        if saved_geo:
            try:
                self.root.geometry(saved_geo)
            except Exception:
                self.root.geometry("1350x800")
        else:
            self.root.geometry("1350x800")

        saved_theme = settings.get("dark_theme")
        if saved_theme is not None:
            theme.dark = saved_theme
            theme._set_colors()
        apply_theme()
        ctk.set_default_color_theme("dark-blue")

        self.active_module = settings.get("last_module", "Username")
        self.last_results_flat = []
        self.last_target = None
        self.tab_mgr = TabManager()
        self.tab_counter = 0
        self.scan_start_time = None

        self._build_ui()
        self._bind_shortcuts()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        geo = self.root.geometry()
        settings.set("window_geometry", geo)
        settings.set("dark_theme", theme.dark)
        settings.set("last_module", self.active_module)
        self.root.destroy()

    def _bind_shortcuts(self):
        self.root.bind("<Control-Return>", lambda e: self._start_scan())
        self.root.bind("<Control-e>", lambda e: self._export_dialog())
        self.root.bind("<Control-s>", lambda e: self._save_session())
        self.root.bind("<Control-o>", lambda e: self._load_session())
        self.root.bind("<Control-f>", lambda e: self._focus_search())
        self.root.bind("<Control-c>", lambda e: self._copy_results())
        self.root.bind("<Control-l>", lambda e: self._clear_results())
        self.root.bind("<F1>", lambda e: self._show_about())

    def _focus_search(self):
        if hasattr(self, "search_entry") and self.search_entry.winfo_exists():
            self.search_entry.focus_set()
            self.search_entry.selection_range(0, "end")

    def _build_ui(self):
        self.root.grid_rowconfigure(0, weight=0)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=0)
        self.root.grid_columnconfigure(1, weight=1)

        self._build_header()
        self._build_sidebar()
        self._build_main_area()
        self._build_status_bar()

    def _build_header(self):
        hdr = ctk.CTkFrame(self.root, height=52, corner_radius=0, fg_color=theme.HEADER_BG)
        hdr.grid(row=0, column=0, columnspan=2, sticky="ew")
        hdr.grid_propagate(False)
        hdr.grid_columnconfigure(0, weight=1)
        hdr.grid_columnconfigure(1, weight=0)

        tf = ctk.CTkFrame(hdr, fg_color="transparent")
        tf.grid(row=0, column=0, padx=18, pady=5, sticky="w")
        ctk.CTkLabel(tf, text="\U0001F98A", font=("Segoe UI", 22),
                     text_color=theme.ORANGE).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(tf, text="OSINT FOX", font=("Segoe UI", 20, "bold"),
                     text_color=theme.ORANGE).pack(side="left")
        ctk.CTkLabel(tf, text=VERSION, font=("Segoe UI", 10),
                     text_color=theme.TEXT_DIM).pack(side="left", padx=(8, 0))
        ctk.CTkLabel(tf, text="Open Source Intelligence Tool",
                     font=("Segoe UI", 11),
                     text_color=theme.TEXT_DIM).pack(side="left", padx=(15, 0))

        btn_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        btn_frame.grid(row=0, column=1, padx=10, pady=5, sticky="e")

        ctk.CTkButton(btn_frame, text="\u2699 Settings",
                      font=("Segoe UI", 11), width=80, height=32,
                      fg_color=theme.BUTTON_SECONDARY,
                      hover_color=theme.BUTTON_SEC_HOVER,
                      command=self._settings_dialog).pack(side="left", padx=2)

        self.theme_btn = ctk.CTkButton(btn_frame, text="\U0001F319" if theme.dark else "\u2600",
                                        font=("Segoe UI", 14), width=36, height=32,
                                        fg_color=theme.BUTTON_SECONDARY,
                                        hover_color=theme.BUTTON_SEC_HOVER,
                                        command=self._toggle_theme)
        self.theme_btn.pack(side="left", padx=2)

        self.export_btn = ctk.CTkButton(btn_frame, text="\U0001F4C4 Export",
                                         font=("Segoe UI", 12, "bold"),
                                         fg_color=theme.ORANGE,
                                         hover_color=theme.BUTTON_HOVER,
                                         command=self._export_dialog,
                                         state="disabled", width=110, height=32)
        self.export_btn.pack(side="left", padx=2)

    def _build_sidebar(self):
        side = ctk.CTkFrame(self.root, width=200, corner_radius=0, fg_color=theme.SIDEBAR_BG)
        side.grid(row=1, column=0, sticky="nsw")
        side.grid_propagate(False)
        side.grid_rowconfigure(len(MODULE_NAMES) + 1, weight=1)

        ctk.CTkLabel(side, text="MODULES", font=("Segoe UI", 10, "bold"),
                     text_color=theme.TEXT_DIM).grid(row=0, column=0, padx=16, pady=(16, 6), sticky="w")

        self.module_buttons = {}
        for i, name in enumerate(MODULE_NAMES, 1):
            icon = MODULE_ICONS.get(name, "\u2699")
            is_active = name == self.active_module
            btn = ctk.CTkButton(side, text=f"  {icon}  {name}",
                                fg_color=theme.ORANGE if is_active else "transparent",
                                text_color="white" if is_active else theme.TEXT_DIM,
                                hover_color="#333366",
                                border_width=1,
                                border_color=theme.BORDER if not is_active else theme.ORANGE,
                                anchor="w", font=("Segoe UI", 12), height=36,
                                corner_radius=6,
                                command=lambda n=name: self._switch_module(n))
            btn.grid(row=i, column=0, padx=10, pady=2, sticky="ew")
            self.module_buttons[name] = btn

        # Bottom buttons in the sidebar
        ctk.CTkButton(side, text="\U0001F4BE Save Session",
                      fg_color="transparent", text_color=theme.TEXT_DIM,
                      hover_color="#333366", anchor="w",
                      font=("Segoe UI", 11), height=30,
                      command=self._save_session).grid(row=len(MODULE_NAMES) + 1, column=0, padx=10, pady=(0, 1), sticky="ew")
        ctk.CTkButton(side, text="\U0001F4C2 Load Session",
                      fg_color="transparent", text_color=theme.TEXT_DIM,
                      hover_color="#333366", anchor="w",
                      font=("Segoe UI", 11), height=30,
                      command=self._load_session).grid(row=len(MODULE_NAMES) + 2, column=0, padx=10, pady=1, sticky="ew")
        ctk.CTkButton(side, text="  \u2139  About",
                      fg_color="transparent", text_color=theme.TEXT_DIM,
                      hover_color="#333366", anchor="w",
                      font=("Segoe UI", 11), height=30,
                      command=self._show_about).grid(row=len(MODULE_NAMES) + 3, column=0, padx=10, pady=(1, 10), sticky="ew")

    def _build_main_area(self):
        main = ctk.CTkFrame(self.root, corner_radius=0, fg_color=theme.DARKER_BG)
        main.grid(row=1, column=1, sticky="nsew")
        main.grid_rowconfigure(3, weight=1)
        main.grid_columnconfigure(0, weight=1)

        # Input row
        input_frame = ctk.CTkFrame(main, fg_color=theme.CARD_BG, corner_radius=8)
        input_frame.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="ew")
        input_frame.grid_columnconfigure(1, weight=1)

        self.input_label = ctk.CTkLabel(input_frame, text=f"{MODULE_ICONS.get(self.active_module, '')} {self.active_module}:",
                                        font=("Segoe UI", 12, "bold"), text_color=theme.TEXT)
        self.input_label.grid(row=0, column=0, padx=(12, 6), pady=10, sticky="w")

        self.input_entry = ctk.CTkEntry(input_frame,
                                        placeholder_text=INPUT_HINTS.get(self.active_module, "Enter target..."),
                                        font=("Segoe UI", 12), height=34, fg_color=theme.INPUT_BG)
        self.input_entry.grid(row=0, column=1, padx=4, pady=10, sticky="ew")
        self.input_entry.bind("<Return>", lambda e: self._start_scan())

        self.scan_btn = ctk.CTkButton(input_frame, text="\u25B6 Start Scan",
                                       font=("Segoe UI", 12, "bold"),
                                       fg_color=theme.ORANGE, hover_color=theme.BUTTON_HOVER,
                                       command=self._start_scan, height=34)
        self.scan_btn.grid(row=0, column=2, padx=4, pady=10)

        self.clear_btn = ctk.CTkButton(input_frame, text="\u2716 Clear",
                                        font=("Segoe UI", 11),
                                        fg_color=theme.BUTTON_SECONDARY,
                                        hover_color=theme.BUTTON_SEC_HOVER,
                                        command=self._clear_results, height=34, width=70)
        self.clear_btn.grid(row=0, column=3, padx=4, pady=10)

        # Tab bar
        tab_frame = ctk.CTkFrame(main, fg_color="transparent", height=30)
        tab_frame.grid(row=1, column=0, padx=12, pady=(0, 0), sticky="ew")
        tab_frame.grid_columnconfigure(0, weight=1)
        self.tab_bar = ctk.CTkScrollableFrame(tab_frame, height=30, fg_color="transparent",
                                               orientation="horizontal")
        self.tab_bar.grid(row=0, column=0, sticky="ew")
        self._tab_buttons = []

        # Progress + search toolbar
        toolbar = ctk.CTkFrame(main, fg_color="transparent", height=28)
        toolbar.grid(row=2, column=0, padx=12, pady=(2, 0), sticky="ew")
        toolbar.grid_columnconfigure(1, weight=1)

        self.progress_bar = ctk.CTkProgressBar(toolbar, height=3, progress_color=theme.ORANGE)
        self.progress_bar.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 2))
        self.progress_bar.set(0)
        self.progress_bar.grid_remove()

        self.search_entry = ctk.CTkEntry(toolbar, placeholder_text="Search results...",
                                          font=("Segoe UI", 10), height=24, width=180)
        self.search_entry.grid(row=1, column=0, padx=(0, 4), sticky="w")
        self.search_entry.bind("<KeyRelease>", lambda e: self._filter_results())

        ctk.CTkButton(toolbar, text="\U0001F50D", font=("Segoe UI", 10), width=24, height=24,
                      fg_color=theme.BUTTON_SECONDARY, hover_color=theme.BUTTON_SEC_HOVER,
                      command=self._filter_results).grid(row=1, column=1, padx=(0, 4), sticky="w")

        ctk.CTkButton(toolbar, text="\U0001F4CB Copy", font=("Segoe UI", 10), height=24,
                      fg_color=theme.BUTTON_SECONDARY, hover_color=theme.BUTTON_SEC_HOVER,
                      command=self._copy_results).grid(row=1, column=2, padx=2, sticky="w")

        # Results area
        results_frame = ctk.CTkFrame(main, fg_color=theme.CARD_BG, corner_radius=8)
        results_frame.grid(row=3, column=0, padx=12, pady=(4, 12), sticky="nsew")
        results_frame.grid_rowconfigure(1, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)

        hdr_frame = ctk.CTkFrame(results_frame, fg_color="transparent")
        hdr_frame.grid(row=0, column=0, padx=12, pady=(8, 4), sticky="ew")
        ctk.CTkLabel(hdr_frame, text="RESULTS", font=("Segoe UI", 12, "bold"),
                     text_color=theme.ORANGE).pack(side="left")
        self.result_tab_label = ctk.CTkLabel(hdr_frame, text="", font=("Segoe UI", 10),
                                              text_color=theme.TEXT_DIM)
        self.result_tab_label.pack(side="left", padx=(12, 0))

        self.results_text = ctk.CTkTextbox(results_frame, font=("Cascadia Code", 10),
                                            fg_color=theme.RESULTS_BG, text_color=theme.TEXT,
                                            corner_radius=6, wrap="word")
        self.results_text.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")

        # Right-click context menu
        self._setup_context_menu()
        self.results_text.bind("<Button-3>", self._show_context_menu)
        self.results_text.bind("<Double-Button-1>", self._on_result_double_click)

        # Drag & drop for image module
        self._setup_drag_drop()

        self._show_welcome()

    def _setup_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self._copy_results, accelerator="Ctrl+C")
        self.context_menu.add_command(label="Copy All", command=lambda: self._copy_results(all_results=True))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Clear", command=self._clear_results, accelerator="Ctrl+L")
        self.context_menu.add_command(label="Export...", command=self._export_dialog, accelerator="Ctrl+E")
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Select All", command=lambda: self.results_text.tag_add("sel", "1.0", "end"))

    def _show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def _on_result_double_click(self, event):
        try:
            click_index = self.results_text.index(f"@{event.x},{event.y}")
            line_start = self.results_text.index(f"{click_index} linestart")
            line_end = self.results_text.index(f"{click_index} lineend")
            line = self.results_text.get(line_start, line_end)
            urls = re.findall(r'https?://[^\s]+', line)
            for url in urls:
                url = url.rstrip(".,;:!?)")
                import webbrowser
                webbrowser.open(url)
                break
        except Exception:
            pass

    def _setup_drag_drop(self):
        self.input_entry.drop_target = None
        try:
            self.input_entry.bind("<Drop>", self._on_drop)
        except Exception:
            pass

        def on_drag_enter(e):
            if self.active_module == "Image":
                self.input_entry.configure(placeholder_text="Drop image file here...")
        self.input_entry.bind("<Enter>", on_drag_enter)

    def _on_drop(self, event):
        try:
            filepath = event.data
            if filepath.startswith("{") and filepath.endswith("}"):
                filepath = filepath[1:-1]
            self.input_entry.delete(0, "end")
            self.input_entry.insert(0, filepath)
        except Exception:
            pass

    def _build_status_bar(self):
        status = ctk.CTkFrame(self.root, height=26, corner_radius=0, fg_color=theme.STATUS_BG)
        status.grid(row=2, column=0, columnspan=2, sticky="ew")
        status.grid_propagate(False)

        self.status_label = ctk.CTkLabel(status, text="Ready", font=("Segoe UI", 10),
                                          text_color=theme.TEXT_DIM)
        self.status_label.pack(side="left", padx=12, pady=2)

        self.status_stats = ctk.CTkLabel(status, text="", font=("Segoe UI", 10),
                                          text_color=theme.TEXT_DIM)
        self.status_stats.pack(side="right", padx=12, pady=2)

        self.status_timer = ctk.CTkLabel(status, text="", font=("Segoe UI", 10),
                                          text_color=theme.TEXT_DIM)
        self.status_timer.pack(side="right", padx=4, pady=2)

    def _show_welcome(self):
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", f"""OSINT FOX {VERSION}

Available Modules:
  \U0001F575  Username      - Search 40+ platforms for a username
  \u2709  Email         - Validation, Gravatar, EmailRep, HIBP, SMTP verify
  \U0001F4DE  Phone         - Carrier, location, WhatsApp/Telegram/Signal detection
  \U0001F310  Domain        - DNS, WHOIS, SSL, subdomains, IP intelligence
  \U0001F465  Social Analyzer - Cross-platform profile analysis & correlation
  \U0001F5BC  Image         - EXIF, metadata, hashes, reverse image search
  \U0001F50D  Breach Lookup - HIBP, DeHashed, IntelX, breach intelligence
  \U0001F30D  Geolocation   - IP geolocation, timezone, mapping

Keyboard Shortcuts:
  Ctrl+Enter   Start Scan         Ctrl+E   Export
  Ctrl+S       Save Session       Ctrl+O   Load Session
  Ctrl+F       Search Results     Ctrl+C   Copy Results
  Ctrl+L       Clear Results      F1       About

Select a module from the sidebar, enter a target, and click Start Scan.

v1.2 New Features:
  \u2022 Search/filter results inline
  \u2022 Copy results to clipboard
  \u2022 Double-click URLs to open in browser
  \u2022 Right-click context menu
  \u2022 Keyboard shortcuts
  \u2022 Settings persistence across sessions
  \u2022 Scan timer in status bar
  \u2022 Windows .exe build available
  \u2022 Bug fixes & performance improvements""")

    def _switch_module(self, name):
        self.active_module = name
        self.input_label.configure(text=f"{MODULE_ICONS.get(name, '')} {name}:")
        self.input_entry.configure(placeholder_text=INPUT_HINTS.get(name, "Enter target..."))
        self.input_entry.delete(0, "end")

        for n, btn in self.module_buttons.items():
            if n == name:
                btn.configure(fg_color=theme.ORANGE, text_color="white", border_color=theme.ORANGE)
            else:
                btn.configure(fg_color="transparent", text_color=theme.TEXT_DIM, border_color=theme.BORDER)
        self._clear_results()

    def _start_scan(self):
        target = self.input_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Required", f"Please enter a valid {self.active_module.lower()}.")
            return

        self.scan_btn.configure(state="disabled", text="\u23F3 Scanning...")
        self.export_btn.configure(state="disabled")
        self.results_text.delete("1.0", "end")
        self.progress_bar.grid()
        self.progress_bar.set(0)
        self.status_label.configure(text=f"Scanning {target}...")
        self.status_stats.configure(text="")
        self.scan_start_time = time.time()
        self._update_timer()

        self.last_target = target
        module = MODULES[self.active_module]

        def progress_callback(msg, pct):
            self.root.after(0, lambda: self._update_progress(msg, pct))

        def scan_thread():
            try:
                module.scan(target, progress_callback)
                self.root.after(0, lambda: self._on_scan_complete(module))
            except Exception as e:
                self.root.after(0, lambda: self._on_scan_error(str(e)))

        threading.Thread(target=scan_thread, daemon=True).start()

    def _update_timer(self):
        if self.scan_start_time is None:
            return
        elapsed = int(time.time() - self.scan_start_time)
        self.status_timer.configure(text=f"Elapsed: {elapsed}s")
        self.root.after(1000, self._update_timer)

    def _update_progress(self, msg, pct):
        self.progress_bar.set(pct)
        self.status_label.configure(text=msg)
        self.results_text.insert("end", f"{msg}\n")
        self.results_text.see("end")

    def _on_scan_complete(self, module):
        self.scan_btn.configure(state="normal", text="\u25B6 Start Scan")
        self.progress_bar.grid_remove()
        self.scan_start_time = None
        self.status_timer.configure(text="")

        results = module.get_results()
        flat = module.get_results_flat()
        self.last_results_flat = flat

        self.tab_counter += 1
        tab_id = self.tab_counter
        self.tab_mgr.add(tab_id, f"#{tab_id} {self.last_target[:20]}",
                         self.last_target, self.active_module, flat)
        self._refresh_tab_bar()

        self.results_text.delete("1.0", "end")
        self._display_results(results)

        summary = module.get_summary() if hasattr(module, "get_summary") else {}
        found = summary.get("found", 0)
        total = summary.get("total", 0)
        self.status_label.configure(text=f"Scan complete - {self.last_target}")
        self.status_stats.configure(text=f"Results: {found} found / {total} total")

        self.export_btn.configure(state="normal")

    def _display_results(self, results):
        for category, items in results.items():
            self.results_text.insert("end", f"\n{'='*50}\n")
            self.results_text.insert("end", f"  {category}\n")
            self.results_text.insert("end", f"{'='*50}\n")

            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        if "platform" in item:
                            icon = "\u2705" if item.get("found") else "\u274C"
                            if item.get("error"):
                                icon = "\u26A0"
                            self.results_text.insert("end", f"\n  {icon} {item.get('platform', '')}\n")
                            if item.get("found") and item.get("data"):
                                for k, v in item["data"].items():
                                    self.results_text.insert("end", f"     {k}: {v}\n")
                        else:
                            for k, v in item.items():
                                if v:
                                    self.results_text.insert("end", f"  {k}: {v}\n")
                    else:
                        self.results_text.insert("end", f"  \u2022 {item}\n")
            elif isinstance(items, dict):
                for k, v in items.items():
                    if v:
                        line = f"  {k}: {v}\n"
                        if str(v).startswith("http"):
                            self.results_text.insert("end", line)
                        else:
                            self.results_text.insert("end", line)
            else:
                self.results_text.insert("end", f"  {items}\n")

    def _on_scan_error(self, error_msg):
        self.scan_btn.configure(state="normal", text="\u25B6 Start Scan")
        self.progress_bar.grid_remove()
        self.scan_start_time = None
        self.status_timer.configure(text="")
        self.status_label.configure(text="Error during scan")
        self.status_stats.configure(text="")
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", f"Error: {error_msg}\n")

    def _clear_results(self):
        self.results_text.delete("1.0", "end")
        self.search_entry.delete(0, "end")
        self.last_results_flat = []
        self.last_target = None
        self.export_btn.configure(state="disabled")
        self.status_label.configure(text="Ready")
        self.status_stats.configure(text="")
        self.status_timer.configure(text="")
        self.results_text.insert("1.0", "Results cleared. Enter a target and start a new scan.\n")

    def _filter_results(self):
        query = self.search_entry.get().strip().lower()
        if not query or not self.last_results_flat:
            return
        self.results_text.delete("1.0", "end")
        matched = False
        for key, val in self.last_results_flat:
            if query in str(key).lower() or query in str(val).lower():
                if key and val:
                    self.results_text.insert("end", f"{key}: {val}\n")
                    matched = True
                elif not key and not val:
                    self.results_text.insert("end", "\n")
        if not matched:
            self.results_text.insert("1.0", f"No matches found for '{query}'.\n")

    def _copy_results(self, all_results=False):
        if all_results:
            text = self.results_text.get("1.0", "end-1c")
        else:
            try:
                text = self.results_text.get("sel.first", "sel.last")
                if not text:
                    text = self.results_text.get("1.0", "end-1c")
            except Exception:
                text = self.results_text.get("1.0", "end-1c")
        if text.strip():
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_label.configure(text="Copied to clipboard")

    def _refresh_tab_bar(self):
        for btn in self._tab_buttons:
            btn.destroy()
        self._tab_buttons = []
        for t in self.tab_mgr.tabs:
            is_active = t == self.tab_mgr.get_active()
            btn = ctk.CTkButton(self.tab_bar, text=f"  {t['title']}  \u2716",
                                font=("Segoe UI", 10),
                                fg_color=theme.ORANGE if is_active else theme.BUTTON_SECONDARY,
                                text_color="white" if is_active else theme.TEXT,
                                hover_color=theme.BUTTON_HOVER if is_active else theme.BUTTON_SEC_HOVER,
                                width=140, height=24,
                                command=lambda tid=t["id"]: self._switch_tab(tid))
            btn.pack(side="left", padx=2)
            self._tab_buttons.append(btn)

    def _switch_tab(self, tab_id):
        for i, t in enumerate(self.tab_mgr.tabs):
            if t["id"] == tab_id:
                self.tab_mgr.active = i
                self._refresh_tab_bar()
                self.last_results_flat = t["results_flat"]
                self.last_target = t["target"]
                self.results_text.delete("1.0", "end")
                self.results_text.insert("1.0", f"[Session: {t['title']} | Module: {t['module']}]\n\n")
                for key, val in self.last_results_flat:
                    if key and val:
                        self.results_text.insert("end", f"{key}: {val}\n")
                    elif not key and not val:
                        self.results_text.insert("end", "\n")
                self.export_btn.configure(state="normal")
                self.status_label.configure(text=f"Session: {t['target']}")
                break

    def _toggle_theme(self):
        tabs_save = {"tabs": [{
            "title": t["title"], "target": t["target"],
            "module": t["module"], "results_flat": t["results_flat"],
        } for t in self.tab_mgr.tabs], "active": self.tab_mgr.active,
            "last_results": self.last_results_flat, "last_target": self.last_target,
            "active_module": self.active_module}

        theme.toggle()
        apply_theme()
        self.theme_btn.configure(text="\U0001F319" if theme.dark else "\u2600")
        settings.set("dark_theme", theme.dark)

        for w in self.root.winfo_children():
            w.destroy()
        self._build_ui()

        self.tab_mgr = TabManager()
        self.tab_counter = 0
        saved = tabs_save
        self.last_results_flat = saved.get("last_results", [])
        self.last_target = saved.get("last_target")
        if saved.get("active_module"):
            self._switch_module(saved["active_module"])
        for t in saved.get("tabs", []):
            self.tab_counter += 1
            self.tab_mgr.add(self.tab_counter, t["title"], t["target"],
                             t["module"], t["results_flat"])
        if self.tab_mgr.tabs:
            self._refresh_tab_bar()
            self.export_btn.configure(state="normal")

    def _save_session(self):
        if not self.last_results_flat:
            messagebox.showinfo("No Results", "No results to save. Run a scan first.")
            return
        path = session_mgr.save(self.last_target, self.active_module, self.last_results_flat)
        messagebox.showinfo("Session Saved", f"Session saved to:\n{path}")

    def _load_session(self):
        path = filedialog.askopenfilename(filetypes=[("OSINT Session", "*.osint"), ("All files", "*.*")])
        if not path:
            return
        try:
            data = session_mgr.load(path)
            self.last_results_flat = data.get("results", [])
            self.last_target = data.get("target", "Unknown")
            self.tab_counter += 1
            self.tab_mgr.add(self.tab_counter, f"#{self.tab_counter} {self.last_target[:20]}",
                             self.last_target, data.get("module", "Loaded"), self.last_results_flat)
            self._refresh_tab_bar()
            self.results_text.delete("1.0", "end")
            self.results_text.insert("1.0", f"Loaded session: {self.last_target}\n")
            self.export_btn.configure(state="normal")
            self.status_label.configure(text=f"Loaded: {self.last_target}")
        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to load session:\n{e}")

    def _export_dialog(self):
        if not self.last_results_flat:
            messagebox.showinfo("No Results", "No results to export. Run a scan first.")
            return

        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Export Results")
        dialog.geometry("380x320")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="Export Intelligence Report", font=("Segoe UI", 16, "bold"),
                     text_color=theme.ORANGE).pack(pady=(18, 4))
        ctk.CTkLabel(dialog, text=f"Target: {self.last_target}", font=("Segoe UI", 11),
                     text_color=theme.TEXT).pack(pady=(0, 12))

        def do_export(fmt_key, label, ext, func):
            ftypes = [(label, f"*.{ext}")]
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe = "".join(c if c.isalnum() else "_" for c in str(self.last_target)[:20])
            fp = filedialog.asksaveasfilename(defaultextension=f".{ext}", filetypes=ftypes,
                                               initialfile=f"osint_report_{safe}_{ts}.{ext}")
            if fp:
                try:
                    if fmt_key == "PDF":
                        func(self.last_results_flat, fp, self.last_target, dark=theme.dark)
                    else:
                        func(self.last_results_flat, fp, self.last_target)
                    messagebox.showinfo("Export Complete", f"Saved to:\n{fp}")
                    dialog.destroy()
                except Exception as e:
                    messagebox.showerror("Export Error", str(e))

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(expand=True, fill="both", padx=20)

        formats = [
            ("PDF", "\U0001F4C4", "pdf", export_to_pdf),
            ("TXT", "\U0001F4DD", "txt", export_to_txt),
            ("CSV", "\U0001F4CA", "csv", export_to_csv),
            ("JSON", "\U0001F4CB", "json", export_to_json),
            ("HTML", "\U0001F310", "html", export_to_html),
        ]
        for fname, icon, ext, func in formats:
            ctk.CTkButton(btn_frame, text=f"  {icon}  Export as {fname}",
                          font=("Segoe UI", 12),
                          fg_color=theme.BUTTON_SECONDARY,
                          hover_color=theme.BUTTON_SEC_HOVER,
                          command=lambda k=fname, l=fname, e=ext, fn=func: do_export(k, l, e, fn),
                          height=34).pack(fill="x", pady=3)

        ctk.CTkButton(dialog, text="Cancel", font=("Segoe UI", 11),
                      fg_color="transparent", text_color=theme.TEXT_DIM,
                      command=dialog.destroy).pack(pady=(6, 10))

    def _settings_dialog(self):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title("Settings")
        dlg.geometry("500x450")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()

        tabs = ctk.CTkTabview(dlg, fg_color=theme.CARD_BG)
        tabs.pack(fill="both", expand=True, padx=10, pady=10)

        api_tab = tabs.add("API Keys")
        ctk.CTkLabel(api_tab, text="Configure API keys for enhanced scanning",
                     font=("Segoe UI", 11), text_color=theme.TEXT_DIM).pack(anchor="w", pady=(8, 4))

        scroll = ctk.CTkScrollableFrame(api_tab, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        key_entries = {}
        for service, desc in APIKeyManager.SERVICES.items():
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=desc, font=("Segoe UI", 11), width=160, anchor="w").pack(side="left")
            entry = ctk.CTkEntry(row, placeholder_text="Enter API key...", width=220, show="*")
            entry.pack(side="left", padx=4)
            entry.insert(0, api_keys.get(service))
            key_entries[service] = entry

        def save_keys():
            for service, entry in key_entries.items():
                val = entry.get().strip()
                if val:
                    api_keys.set(service, val)
                else:
                    api_keys.delete(service)
            messagebox.showinfo("Keys Saved", "API keys saved successfully.")

        ctk.CTkButton(api_tab, text="Save Keys", fg_color=theme.ORANGE,
                      hover_color=theme.BUTTON_HOVER, command=save_keys).pack(pady=8)

        proxy_tab = tabs.add("Proxy")
        ctk.CTkLabel(proxy_tab, text="Proxy / Tor Settings", font=("Segoe UI", 12, "bold"),
                     text_color=theme.ORANGE).pack(anchor="w", pady=8)
        ctk.CTkLabel(proxy_tab,
                     text="Leave empty for direct connection.\nFor Tor: socks5://127.0.0.1:9050",
                     font=("Segoe UI", 10), text_color=theme.TEXT_DIM, justify="left").pack(anchor="w")

        proxy_entry = ctk.CTkEntry(proxy_tab, placeholder_text="socks5://127.0.0.1:9050", width=350)
        proxy_entry.pack(anchor="w", pady=8)
        if get_proxy():
            proxy_entry.insert(0, get_proxy())

        def save_proxy():
            val = proxy_entry.get().strip()
            if val:
                set_proxy(val)
            else:
                clear_proxy()
            messagebox.showinfo("Proxy Saved", f"Proxy {'set to ' + val if val else 'cleared'}.")

        ctk.CTkButton(proxy_tab, text="Save Proxy", fg_color=theme.ORANGE,
                      hover_color=theme.BUTTON_HOVER, command=save_proxy).pack(anchor="w")

        about_tab = tabs.add("About")
        ctk.CTkLabel(about_tab, text=f"OSINT FOX {VERSION}", font=("Segoe UI", 18, "bold"),
                     text_color=theme.ORANGE).pack(pady=(20, 4))
        ctk.CTkLabel(about_tab, text="Open Source Intelligence Tool", font=("Segoe UI", 11),
                     text_color=theme.TEXT_DIM).pack()
        info = ("8 modules \u2022 Dark/Light theme \u2022 Tabbed sessions\n"
                "5 export formats \u2022 Plugin system \u2022 Proxy/Tor support\n"
                "API key management \u2022 Session save/load\n\n"
                "For authorized security research only.")
        ctk.CTkLabel(about_tab, text=info, font=("Segoe UI", 11),
                     text_color=theme.TEXT, justify="left").pack(pady=12)

    def _show_about(self):
        about = ctk.CTkToplevel(self.root)
        about.title("About OSINT FOX")
        about.geometry("420+400")
        about.resizable(False, False)
        about.transient(self.root)
        about.grab_set()

        ctk.CTkLabel(about, text="\U0001F98A", font=("Segoe UI", 48)).pack(pady=(20, 4))
        ctk.CTkLabel(about, text=f"OSINT FOX {VERSION}", font=("Segoe UI", 22, "bold"),
                     text_color=theme.ORANGE).pack()
        ctk.CTkLabel(about, text="Open Source Intelligence Tool", font=("Segoe UI", 12),
                     text_color=theme.TEXT_DIM).pack(pady=(0, 12))

        info = (
            "A GUI-based OSINT tool that gathers publicly available\n"
            "information about targets using handles, emails, phone\n"
            "numbers, domains, images, and more.\n\n"
            "Modules:\n"
            "  \U0001F575  Username (40+ platforms)    \U0001F310  Domain / IP\n"
            f"  \u2709  Email (SMTP, breaches)        \U0001F465  Social Analyzer\n"
            "  \U0001F4DE  Phone (WhatsApp, Telegram)  \U0001F5BC  Image OSINT\n"
            "  \U0001F50D  Breach Lookup              \U0001F30D  Geolocation\n\n"
            f"{VERSION} - 2026"
        )
        ctk.CTkLabel(about, text=info, font=("Segoe UI", 11),
                     text_color=theme.TEXT, justify="left").pack(padx=24, pady=8)
        ctk.CTkButton(about, text="Close", command=about.destroy,
                      fg_color=theme.BUTTON_SECONDARY,
                      hover_color=theme.BUTTON_SEC_HOVER).pack(pady=10)

    def run(self):
        self.root.mainloop()
