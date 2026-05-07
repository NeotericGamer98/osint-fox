import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
import json
from datetime import datetime

from modules.registry import discover_modules, get_all_metas, get_module
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
from utils.apikeys import APIKeyManager
from utils.network import set_proxy, clear_proxy, get_proxy

session_mgr = SessionManager()
api_keys = APIKeyManager()


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
    "Username": "\U0001F575",
    "Email": "\u2709",
    "Phone": "\U0001F4DE",
    "Domain": "\U0001F310",
    "Social Analyzer": "\U0001F465",
    "Image": "\U0001F5BC",
    "Breach Lookup": "\U0001F50D",
    "Geolocation": "\U0001F30D",
}

INPUT_HINTS = {
    "Username": "Enter username (e.g. johndoe)",
    "Email": "Enter email (e.g. user@example.com)",
    "Phone": "Enter phone (e.g. +1234567890)",
    "Domain": "Enter domain or IP (e.g. example.com)",
    "Social Analyzer": "Enter username (e.g. johndoe)",
    "Image": "Enter image URL or local file path",
    "Breach Lookup": "Enter email, username, or phone",
    "Geolocation": "Enter IP address or domain",
}


def apply_theme(widget=None):
    ctk.set_appearance_mode("Dark" if theme.dark else "Light")


class TabManager:
    def __init__(self):
        self.tabs = []
        self.active = -1

    def add(self, tab_id, title, target, module_name, results_flat):
        self.tabs.append({
            "id": tab_id,
            "title": title,
            "target": target,
            "module": module_name,
            "results_flat": results_flat,
        })
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
        self.root.title("OSINT FOX v1.1")
        self.root.geometry("1350x800")
        self.root.minsize(1000, 650)
        apply_theme()
        ctk.set_default_color_theme("dark-blue")

        self.active_module = "Username"
        self.last_results_flat = []
        self.last_target = None
        self.tab_mgr = TabManager()
        self.tab_counter = 0

        self._build_ui()

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
        hdr = ctk.CTkFrame(self.root, height=52, corner_radius=0,
                           fg_color=theme.HEADER_BG)
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
        ctk.CTkLabel(tf, text="v1.1", font=("Segoe UI", 10),
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
        side = ctk.CTkFrame(self.root, width=200, corner_radius=0,
                            fg_color=theme.SIDEBAR_BG)
        side.grid(row=1, column=0, sticky="nsw")
        side.grid_propagate(False)

        ctk.CTkLabel(side, text="MODULES", font=("Segoe UI", 10, "bold"),
                     text_color=theme.TEXT_DIM).pack(anchor="w", padx=16, pady=(16, 6))

        module_names = [
            "Username", "Email", "Phone", "Domain",
            "Social Analyzer", "Image", "Breach Lookup", "Geolocation",
        ]
        self.module_buttons = {}
        for name in module_names:
            icon = MODULE_ICONS.get(name, "\u2699")
            is_active = name == self.active_module
            btn = ctk.CTkButton(side, text=f"  {icon}  {name}",
                                fg_color=theme.ORANGE if is_active else "transparent",
                                text_color="white" if is_active else theme.TEXT_DIM,
                                hover_color="#333366",
                                border_width=1,
                                border_color=theme.BORDER if not is_active else theme.ORANGE,
                                anchor="w", font=("Segoe UI", 12), height=38,
                                corner_radius=6,
                                command=lambda n=name: self._switch_module(n))
            btn.pack(fill="x", padx=10, pady=2)
            self.module_buttons[name] = btn

        ctk.CTkLabel(side, text="").pack(expand=True)

        # Session buttons
        ctk.CTkButton(side, text="\U0001F4BE Save Session",
                      fg_color="transparent", text_color=theme.TEXT_DIM,
                      hover_color="#333366", anchor="w",
                      font=("Segoe UI", 11), height=30,
                      command=self._save_session).pack(fill="x", padx=10, pady=1)
        ctk.CTkButton(side, text="\U0001F4C2 Load Session",
                      fg_color="transparent", text_color=theme.TEXT_DIM,
                      hover_color="#333366", anchor="w",
                      font=("Segoe UI", 11), height=30,
                      command=self._load_session).pack(fill="x", padx=10, pady=1)
        ctk.CTkButton(side, text="  \u2139  About",
                      fg_color="transparent", text_color=theme.TEXT_DIM,
                      hover_color="#333366", anchor="w",
                      font=("Segoe UI", 11), height=30,
                      command=self._show_about).pack(fill="x", padx=10, pady=(1, 10))

    def _build_main_area(self):
        main = ctk.CTkFrame(self.root, corner_radius=0, fg_color=theme.DARKER_BG)
        main.grid(row=1, column=1, sticky="nsew")
        main.grid_rowconfigure(2, weight=1)
        main.grid_columnconfigure(0, weight=1)

        input_frame = ctk.CTkFrame(main, fg_color=theme.CARD_BG, corner_radius=8)
        input_frame.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="ew")
        input_frame.grid_columnconfigure(1, weight=1)

        self.input_label = ctk.CTkLabel(input_frame, text="Username:",
                                        font=("Segoe UI", 12, "bold"),
                                        text_color=theme.TEXT)
        self.input_label.grid(row=0, column=0, padx=(12, 6), pady=10, sticky="w")

        self.input_entry = ctk.CTkEntry(input_frame,
                                        placeholder_text=INPUT_HINTS[self.active_module],
                                        font=("Segoe UI", 12), height=34,
                                        fg_color=theme.INPUT_BG)
        self.input_entry.grid(row=0, column=1, padx=4, pady=10, sticky="ew")
        self.input_entry.bind("<Return>", lambda e: self._start_scan())

        self.scan_btn = ctk.CTkButton(input_frame, text="\u25B6 Start Scan",
                                       font=("Segoe UI", 12, "bold"),
                                       fg_color=theme.ORANGE,
                                       hover_color=theme.BUTTON_HOVER,
                                       command=self._start_scan, height=34)
        self.scan_btn.grid(row=0, column=2, padx=4, pady=10)

        self.clear_btn = ctk.CTkButton(input_frame, text="\u2716 Clear",
                                        font=("Segoe UI", 11),
                                        fg_color=theme.BUTTON_SECONDARY,
                                        hover_color=theme.BUTTON_SEC_HOVER,
                                        command=self._clear_results, height=34,
                                        width=70)
        self.clear_btn.grid(row=0, column=3, padx=4, pady=10)

        # Tab bar
        tab_frame = ctk.CTkFrame(main, fg_color="transparent", height=30)
        tab_frame.grid(row=1, column=0, padx=12, pady=(0, 0), sticky="ew")
        tab_frame.grid_columnconfigure(0, weight=1)
        self.tab_bar = ctk.CTkScrollableFrame(tab_frame, height=30,
                                               fg_color="transparent",
                                               orientation="horizontal")
        self.tab_bar.grid(row=0, column=0, sticky="ew")
        self._tab_buttons = []

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(main, height=3,
                                                progress_color=theme.ORANGE)
        self.progress_bar.grid(row=1, column=0, padx=12, pady=(3, 0), sticky="ew")
        self.progress_bar.set(0)
        self.progress_bar.grid_remove()

        # Results area
        results_frame = ctk.CTkFrame(main, fg_color=theme.CARD_BG, corner_radius=8)
        results_frame.grid(row=2, column=0, padx=12, pady=(4, 12), sticky="nsew")
        results_frame.grid_rowconfigure(1, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)

        hdr_frame = ctk.CTkFrame(results_frame, fg_color="transparent")
        hdr_frame.grid(row=0, column=0, padx=12, pady=(8, 4), sticky="ew")
        ctk.CTkLabel(hdr_frame, text="RESULTS",
                     font=("Segoe UI", 12, "bold"),
                     text_color=theme.ORANGE).pack(side="left")
        self.result_tab_label = ctk.CTkLabel(hdr_frame, text="",
                                              font=("Segoe UI", 10),
                                              text_color=theme.TEXT_DIM)
        self.result_tab_label.pack(side="left", padx=(12, 0))

        self.results_text = ctk.CTkTextbox(results_frame,
                                            font=("Cascadia Code", 10),
                                            fg_color=theme.RESULTS_BG,
                                            text_color=theme.TEXT,
                                            corner_radius=6, wrap="word")
        self.results_text.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")

        self._show_welcome()

    def _build_status_bar(self):
        status = ctk.CTkFrame(self.root, height=26, corner_radius=0,
                              fg_color=theme.STATUS_BG)
        status.grid(row=2, column=0, columnspan=2, sticky="ew")
        status.grid_propagate(False)

        self.status_label = ctk.CTkLabel(status, text="Ready",
                                         font=("Segoe UI", 10),
                                         text_color=theme.TEXT_DIM)
        self.status_label.pack(side="left", padx=12, pady=2)

    def _show_welcome(self):
        self.results_text.delete("1.0", "end")
        welcome = """OSINT FOX v1.1

Available Modules:
  \U0001F575  Username      - Search 40+ platforms for a username
  \u2709  Email         - Validation, Gravatar, EmailRep, HIBP, SMTP verify
  \U0001F4DE  Phone         - Carrier, location, WhatsApp/Telegram/Signal detection
  \U0001F310  Domain        - DNS, WHOIS, SSL, subdomains, IP intelligence
  \U0001F465  Social Analyzer - Cross-platform profile analysis & correlation
  \U0001F5BC  Image         - EXIF, metadata, hashes, reverse image search
  \U0001F50D  Breach Lookup - HIBP, DeHashed, IntelX, breach intelligence
  \U0001F30D  Geolocation   - IP geolocation, timezone, mapping

Select a module from the sidebar, enter a target, and click Start Scan.

New in v1.1:
  - 5 new modules (Domain, Social, Image, Breach, Geo)
  - Dark/Light theme toggle
  - Tabbed scan sessions
  - API key management
  - Proxy/Tor support
  - CSV, JSON, HTML export
  - Session save/load
  - Per-platform rate limiting with caching
  - SMTP email verification
  - WhatsApp/Telegram/Signal phone detection"""
        self.results_text.insert("1.0", welcome)

    def _switch_module(self, name):
        self.active_module = name
        self.input_label.configure(text=f"{MODULE_ICONS.get(name, '')} {name}:")
        self.input_entry.configure(placeholder_text=INPUT_HINTS.get(name, "Enter target..."))

        for n, btn in self.module_buttons.items():
            if n == name:
                btn.configure(fg_color=theme.ORANGE, text_color="white",
                              border_color=theme.ORANGE)
            else:
                btn.configure(fg_color="transparent", text_color=theme.TEXT_DIM,
                              border_color=theme.BORDER)
        self._clear_results()

    def _start_scan(self):
        target = self.input_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Required",
                                   f"Please enter a valid {self.active_module.lower()}.")
            return

        self.scan_btn.configure(state="disabled", text="\u23F3 Scanning...")
        self.export_btn.configure(state="disabled")
        self.results_text.delete("1.0", "end")
        self.progress_bar.grid()
        self.progress_bar.set(0)
        self.status_label.configure(text=f"Scanning {target}...")

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

    def _update_progress(self, msg, pct):
        self.progress_bar.set(pct)
        self.status_label.configure(text=msg)
        self.results_text.insert("end", f"{msg}\n")
        self.results_text.see("end")

    def _on_scan_complete(self, module):
        self.scan_btn.configure(state="normal", text="\u25B6 Start Scan")
        self.progress_bar.grid_remove()
        self.status_label.configure(text=f"Scan complete - {self.last_target}")
        self.results_text.delete("1.0", "end")

        results = module.get_results()
        flat = module.get_results_flat()
        self.last_results_flat = flat

        # Add to tab manager
        self.tab_counter += 1
        tab_id = self.tab_counter
        self.tab_mgr.add(tab_id, f"#{tab_id} {self.last_target[:20]}",
                         self.last_target, self.active_module, flat)
        self._refresh_tab_bar()

        # Display results
        self._display_results(results)

        self.export_btn.configure(state="normal")

    def _display_results(self, results):
        for category, items in results.items():
            self.results_text.insert("end", f"\n{'='*50}\n", "category")
            self.results_text.insert("end", f"  {category}\n", "category")
            self.results_text.insert("end", f"{'='*50}\n", "category")

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
                        self.results_text.insert("end", f"  {k}: {v}\n")
            else:
                self.results_text.insert("end", f"  {items}\n")

    def _on_scan_error(self, error_msg):
        self.scan_btn.configure(state="normal", text="\u25B6 Start Scan")
        self.progress_bar.grid_remove()
        self.status_label.configure(text="Error during scan")
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", f"Error: {error_msg}\n")

    def _clear_results(self):
        self.results_text.delete("1.0", "end")
        self.last_results_flat = []
        self.last_target = None
        self.export_btn.configure(state="disabled")
        self.status_label.configure(text="Ready")
        self.results_text.insert("1.0", "Results cleared. Enter a target and start a new scan.\n")

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
                self.results_text.insert("1.0", f"Loaded from tab {t['title']}")
                self.export_btn.configure(state="normal")
                self.status_label.configure(text=f"Session: {t['target']}")
                break

    def _toggle_theme(self):
        theme.toggle()
        apply_theme()
        self.theme_btn.configure(text="\U0001F319" if theme.dark else "\u2600")
        # Rebuild entire UI to apply theme
        for w in self.root.winfo_children():
            w.destroy()
        self._build_ui()

    def _save_session(self):
        if not self.last_results_flat:
            messagebox.showinfo("No Results", "No results to save. Run a scan first.")
            return
        path = session_mgr.save(self.last_target, self.active_module, self.last_results_flat)
        messagebox.showinfo("Session Saved", f"Session saved to:\n{path}")

    def _load_session(self):
        path = filedialog.askopenfilename(
            filetypes=[("OSINT Session", "*.osint"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            data = session_mgr.load(path)
            self.last_results_flat = data.get("results", [])
            self.last_target = data.get("target", "Unknown")
            self.tab_counter += 1
            self.tab_mgr.add(self.tab_counter,
                             f"#{self.tab_counter} {self.last_target[:20]}",
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

        ctk.CTkLabel(dialog, text="Export Intelligence Report",
                     font=("Segoe UI", 16, "bold"),
                     text_color=theme.ORANGE).pack(pady=(18, 4))
        ctk.CTkLabel(dialog, text=f"Target: {self.last_target}",
                     font=("Segoe UI", 11),
                     text_color=theme.TEXT).pack(pady=(0, 12))

        def do_export(fmt_key, label, ext, func):
            ftypes = [(label, f"*.{ext}")]
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe = "".join(c if c.isalnum() else "_" for c in str(self.last_target)[:20])
            fp = filedialog.asksaveasfilename(
                defaultextension=f".{ext}", filetypes=ftypes,
                initialfile=f"osint_report_{safe}_{ts}.{ext}"
            )
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

        # API Keys tab
        api_tab = tabs.add("API Keys")
        ctk.CTkLabel(api_tab, text="Configure API keys for enhanced scanning",
                     font=("Segoe UI", 11), text_color=theme.TEXT_DIM).pack(anchor="w", pady=(8, 4))

        scroll = ctk.CTkScrollableFrame(api_tab, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        key_entries = {}
        for service, desc in APIKeyManager.SERVICES.items():
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=desc, font=("Segoe UI", 11),
                         width=160, anchor="w").pack(side="left")
            entry = ctk.CTkEntry(row, placeholder_text="Enter API key...",
                                 width=220, show="*")
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

        ctk.CTkButton(api_tab, text="Save Keys",
                      fg_color=theme.ORANGE, hover_color=theme.BUTTON_HOVER,
                      command=save_keys).pack(pady=8)

        # Proxy tab
        proxy_tab = tabs.add("Proxy")
        ctk.CTkLabel(proxy_tab, text="Proxy / Tor Settings",
                     font=("Segoe UI", 12, "bold"),
                     text_color=theme.ORANGE).pack(anchor="w", pady=8)

        ctk.CTkLabel(proxy_tab,
                     text="Leave empty for direct connection.\nFor Tor: socks5://127.0.0.1:9050",
                     font=("Segoe UI", 10), text_color=theme.TEXT_DIM,
                     justify="left").pack(anchor="w")

        proxy_entry = ctk.CTkEntry(proxy_tab, placeholder_text="socks5://127.0.0.1:9050",
                                    width=350)
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

        ctk.CTkButton(proxy_tab, text="Save Proxy",
                      fg_color=theme.ORANGE, hover_color=theme.BUTTON_HOVER,
                      command=save_proxy).pack(anchor="w")

        # About tab
        about_tab = tabs.add("About")
        ctk.CTkLabel(about_tab, text="OSINT FOX v1.1",
                     font=("Segoe UI", 18, "bold"),
                     text_color=theme.ORANGE).pack(pady=(20, 4))
        ctk.CTkLabel(about_tab, text="Open Source Intelligence Tool",
                     font=("Segoe UI", 11),
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
        about.geometry("420x380")
        about.resizable(False, False)
        about.transient(self.root)
        about.grab_set()

        ctk.CTkLabel(about, text="\U0001F98A", font=("Segoe UI", 48)).pack(pady=(20, 4))
        ctk.CTkLabel(about, text="OSINT FOX v1.1",
                     font=("Segoe UI", 22, "bold"),
                     text_color=theme.ORANGE).pack()
        ctk.CTkLabel(about, text="Open Source Intelligence Tool",
                     font=("Segoe UI", 12),
                     text_color=theme.TEXT_DIM).pack(pady=(0, 12))

        info = (
            "A GUI-based OSINT tool that gathers publicly available\n"
            "information about targets using handles, emails, phone\n"
            "numbers, domains, images, and more.\n\n"
            "Modules:\n"
            "  \U0001F575  Username (40+ platforms)    \U0001F310  Domain / IP\n"
            "  \u2709  Email (SMTP, breaches)        \U0001F465  Social Analyzer\n"
            "  \U0001F4DE  Phone (WhatsApp, Telegram)  \U0001F5BC  Image OSINT\n"
            "  \U0001F50D  Breach Lookup              \U0001F30D  Geolocation\n\n"
            "v1.1 - 2026"
        )
        ctk.CTkLabel(about, text=info, font=("Segoe UI", 11),
                     text_color=theme.TEXT, justify="left").pack(padx=24, pady=8)
        ctk.CTkButton(about, text="Close", command=about.destroy,
                      fg_color=theme.BUTTON_SECONDARY,
                      hover_color=theme.BUTTON_SEC_HOVER).pack(pady=10)

    def run(self):
        self.root.mainloop()
