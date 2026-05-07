import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
from datetime import datetime

from modules.username import UsernameModule
from modules.email import EmailModule
from modules.phone import PhoneModule
from utils.exporter import export_to_pdf, export_to_txt
from app.theme import *


MODULES = {
    "Username": UsernameModule(),
    "Email": EmailModule(),
    "Phone": PhoneModule(),
}


class OSINTFoxApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("OSINT FOX")
        self.root.geometry("1200x750")
        self.root.minsize(900, 600)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        self.active_module = "Username"
        self.last_results_flat = []
        self.last_target = None

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
        header = ctk.CTkFrame(self.root, height=HEADER_HEIGHT, corner_radius=0,
                              fg_color=FOX_DARKER_BG)
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        header.grid_propagate(False)

        header.grid_columnconfigure(0, weight=1)
        header.grid_columnconfigure(1, weight=0)

        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.grid(row=0, column=0, padx=20, pady=5, sticky="w")

        ctk.CTkLabel(title_frame, text="\U0001F98A", font=("Segoe UI", 22),
                     text_color=FOX_ORANGE).pack(side="left", padx=(0, 8))

        ctk.CTkLabel(title_frame, text="OSINT FOX",
                     font=("Segoe UI", 20, "bold"), text_color=FOX_ORANGE).pack(side="left")

        ctk.CTkLabel(title_frame, text="Open Source Intelligence Tool",
                     font=("Segoe UI", 11), text_color=FOX_TEXT_DIM).pack(side="left", padx=(15, 0))

        self.export_btn = ctk.CTkButton(header, text="\U0001F4C4 Export Results",
                                         font=("Segoe UI", 12, "bold"),
                                         fg_color=FOX_ORANGE, hover_color="#C45F10",
                                         command=self._export_dialog,
                                         state="disabled", width=140)
        self.export_btn.grid(row=0, column=1, padx=15, pady=8, sticky="e")

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self.root, width=SIDEBAR_WIDTH, corner_radius=0,
                               fg_color=FOX_DARK_BG)
        sidebar.grid(row=1, column=0, sticky="nsw")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(sidebar, text="MODULES",
                     font=("Segoe UI", 11, "bold"), text_color=FOX_TEXT_DIM).pack(
            anchor="w", padx=20, pady=(20, 10))

        module_meta = [
            ("Username", "\U0001F575", "Search 35+ platforms for username presence"),
            ("Email", "\u2709", "Email breaches, gravatar, reputation"),
            ("Phone", "\U0001F4DE", "Phone carrier, location, intelligence"),
        ]

        self.module_buttons = {}
        btn_style = {"anchor": "w", "font": ("Segoe UI", 13),
                     "height": 48, "corner_radius": 8}

        for name, icon, desc in module_meta:
            is_active = (name == self.active_module)
            btn = ctk.CTkButton(sidebar, text=f"  {icon}  {name}",
                                fg_color=FOX_ORANGE if is_active else "transparent",
                                text_color="white" if is_active else FOX_TEXT_DIM,
                                hover_color="#333366",
                                border_width=1,
                                border_color="#333366" if not is_active else FOX_ORANGE,
                                command=lambda n=name: self._switch_module(n),
                                **{k: btn_style[k] for k in btn_style})
            btn.pack(fill="x", padx=12, pady=3)
            self.module_buttons[name] = btn

            ctk.CTkLabel(sidebar, text=desc,
                         font=("Segoe UI", 9), text_color=FOX_TEXT_DIM).pack(
                anchor="w", padx=(30, 15), pady=(0, 8))

        ctk.CTkLabel(sidebar, text="").pack(expand=True)

        about_btn = ctk.CTkButton(sidebar, text="  \u2139  About",
                                  fg_color="transparent", text_color=FOX_TEXT_DIM,
                                  hover_color="#333366", anchor="w",
                                  font=("Segoe UI", 12), command=self._show_about)
        about_btn.pack(fill="x", padx=12, pady=(0, 10))

    def _build_main_area(self):
        main = ctk.CTkFrame(self.root, corner_radius=0, fg_color=FOX_DARKER_BG)
        main.grid(row=1, column=1, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        # Input area
        input_frame = ctk.CTkFrame(main, fg_color=FOX_CARD_BG, corner_radius=10)
        input_frame.grid(row=0, column=0, padx=15, pady=(15, 8), sticky="ew")
        input_frame.grid_columnconfigure(0, weight=0)
        input_frame.grid_columnconfigure(1, weight=1)
        input_frame.grid_columnconfigure(2, weight=0)
        input_frame.grid_columnconfigure(3, weight=0)
        input_frame.grid_columnconfigure(4, weight=0)

        self.input_label = ctk.CTkLabel(input_frame, text="Username:",
                                        font=("Segoe UI", 13, "bold"),
                                        text_color=FOX_TEXT)
        self.input_label.grid(row=0, column=0, padx=(15, 8), pady=12, sticky="w")

        self.input_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter target...",
                                        font=("Segoe UI", 13), height=36)
        self.input_entry.grid(row=0, column=1, padx=5, pady=12, sticky="ew")
        self.input_entry.bind("<Return>", lambda e: self._start_scan())

        self.scan_btn = ctk.CTkButton(input_frame, text="\u25B6 Start Scan",
                                       font=("Segoe UI", 12, "bold"),
                                       fg_color=FOX_ORANGE, hover_color="#C45F10",
                                       command=self._start_scan, height=36)
        self.scan_btn.grid(row=0, column=2, padx=5, pady=12)

        self.clear_btn = ctk.CTkButton(input_frame, text="\u2716 Clear",
                                        font=("Segoe UI", 12),
                                        fg_color="#3A3A5C", hover_color="#4A4A6C",
                                        command=self._clear_results, height=36,
                                        width=80)
        self.clear_btn.grid(row=0, column=3, padx=5, pady=12)

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(main, height=4, progress_color=FOX_ORANGE)
        self.progress_bar.grid(row=1, column=0, padx=15, pady=(0, 0), sticky="ew")
        self.progress_bar.set(0)
        self.progress_bar.grid_remove()

        # Results area
        results_frame = ctk.CTkFrame(main, fg_color=FOX_CARD_BG, corner_radius=10)
        results_frame.grid(row=2, column=0, padx=15, pady=(8, 15), sticky="nsew")
        results_frame.grid_rowconfigure(1, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(results_frame, text="RESULTS",
                     font=("Segoe UI", 13, "bold"), text_color=FOX_ORANGE).grid(
            row=0, column=0, padx=15, pady=(10, 5), sticky="w")

        self.results_text = ctk.CTkTextbox(results_frame, font=("Cascadia Code", 11),
                                            fg_color="#12121E", text_color=FOX_TEXT,
                                            corner_radius=8, wrap="word")
        self.results_text.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")

        self.results_text.insert("1.0", "Welcome to OSINT FOX\n\n"
                                        "Select a module from the sidebar, enter a target, and click Start Scan.\n\n"
                                        "Modules available:\n"
                                        "  \U0001F575  Username  - Search 35+ platforms for a username\n"
                                        "  \u2709  Email     - Breach checks, Gravatar, reputation\n"
                                        "  \U0001F4DE  Phone     - Carrier, location, format analysis\n\n"
                                        "Results are organized by category for easy analysis.\n"
                                        "Use the Export button in the header to save results to PDF or TXT.")

    def _build_status_bar(self):
        status = ctk.CTkFrame(self.root, height=28, corner_radius=0, fg_color="#0E0E1A")
        status.grid(row=2, column=0, columnspan=2, sticky="ew")
        status.grid_propagate(False)

        self.status_label = ctk.CTkLabel(status, text="Ready",
                                         font=("Segoe UI", 10), text_color=FOX_TEXT_DIM)
        self.status_label.pack(side="left", padx=15, pady=2)

    def _switch_module(self, name):
        self.active_module = name
        self.input_label.configure(text=f"{name}:")
        if name == "Username":
            self.input_entry.configure(placeholder_text="Enter username (e.g. johndoe)")
        elif name == "Email":
            self.input_entry.configure(placeholder_text="Enter email (e.g. user@example.com)")
        elif name == "Phone":
            self.input_entry.configure(placeholder_text="Enter phone (e.g. +1234567890)")

        for n, btn in self.module_buttons.items():
            if n == name:
                btn.configure(fg_color=FOX_ORANGE, text_color="white",
                              border_color=FOX_ORANGE)
            else:
                btn.configure(fg_color="transparent", text_color=FOX_TEXT_DIM,
                              border_color="#333366")

        self._clear_results()

    def _start_scan(self):
        target = self.input_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Required", f"Please enter a valid {self.active_module.lower()}.")
            return

        self.scan_btn.configure(state="disabled", text="\u23F3 Scanning...")
        self.export_btn.configure(state="disabled")
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", "Starting scan...\n")
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

        for category, items in results.items():
            self.results_text.insert("end", f"\n{'='*50}\n", "category")
            self.results_text.insert("end", f"  {category}\n", "category")
            self.results_text.insert("end", f"{'='*50}\n", "category")

            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        if "platform" in item:
                            status_icon = "\u2705" if item.get("found") else "\u274C"
                            if item.get("error"):
                                status_icon = "\u26A0"
                            platform = item.get("platform", "Unknown")
                            self.results_text.insert("end", f"\n  {status_icon} {platform}\n", "platform")
                            if item.get("found") and item.get("data"):
                                for k, v in item["data"].items():
                                    self.results_text.insert("end", f"     {k}: {v}\n")
                        else:
                            for k, v in item.items():
                                self.results_text.insert("end", f"  {k}: {v}\n")
                    else:
                        self.results_text.insert("end", f"  \u2022 {item}\n")

            elif isinstance(items, dict):
                for k, v in items.items():
                    val_str = str(v) if v else "N/A"
                    self.results_text.insert("end", f"  {k}: {val_str}\n")

            else:
                self.results_text.insert("end", f"  {items}\n")

        self.export_btn.configure(state="normal")

    def _on_scan_error(self, error_msg):
        self.scan_btn.configure(state="normal", text="\u25B6 Start Scan")
        self.progress_bar.grid_remove()
        self.status_label.configure(text="Error during scan")
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", f"Error: {error_msg}\n")

    def _clear_results(self):
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", "Results cleared. Enter a target and start a new scan.\n")
        self.last_results_flat = []
        self.last_target = None
        self.export_btn.configure(state="disabled")
        self.status_label.configure(text="Ready")

    def _export_dialog(self):
        if not self.last_results_flat:
            messagebox.showinfo("No Results", "No results to export. Run a scan first.")
            return

        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Export Results")
        dialog.geometry("400x250")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        dialog.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(dialog, text="Export Intelligence Report",
                     font=("Segoe UI", 16, "bold"), text_color=FOX_ORANGE).pack(
            pady=(20, 5))
        ctk.CTkLabel(dialog, text=f"Target: {self.last_target}",
                     font=("Segoe UI", 11), text_color=FOX_TEXT).pack(pady=(0, 15))

        def export_pdf():
            filepath = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf")],
                initialfile=f"osint_report_{self.last_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            )
            if filepath:
                try:
                    export_to_pdf(self.last_results_flat, filepath, self.last_target)
                    messagebox.showinfo("Export Complete", f"PDF saved to:\n{filepath}")
                    dialog.destroy()
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to export PDF:\n{e}")

        def export_txt():
            filepath = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")],
                initialfile=f"osint_report_{self.last_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            if filepath:
                try:
                    export_to_txt(self.last_results_flat, filepath, self.last_target)
                    messagebox.showinfo("Export Complete", f"Text file saved to:\n{filepath}")
                    dialog.destroy()
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to export text:\n{e}")

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(expand=True)

        ctk.CTkButton(btn_frame, text="\U0001F4C4 Export as PDF",
                      font=("Segoe UI", 13, "bold"),
                      fg_color=FOX_ORANGE, hover_color="#C45F10",
                      command=export_pdf, width=160, height=40).pack(pady=8)

        ctk.CTkButton(btn_frame, text="\U0001F4DD Export as Text",
                      font=("Segoe UI", 13),
                      fg_color="#3A3A5C", hover_color="#4A4A6C",
                      command=export_txt, width=160, height=40).pack(pady=8)

        ctk.CTkButton(dialog, text="Cancel",
                      font=("Segoe UI", 11),
                      fg_color="transparent", text_color=FOX_TEXT_DIM,
                      command=dialog.destroy).pack(pady=(0, 10))

    def _show_about(self):
        about = ctk.CTkToplevel(self.root)
        about.title("About OSINT FOX")
        about.geometry("450x350")
        about.resizable(False, False)
        about.transient(self.root)
        about.grab_set()

        ctk.CTkLabel(about, text="\U0001F98A", font=("Segoe UI", 48)).pack(pady=(20, 5))
        ctk.CTkLabel(about, text="OSINT FOX",
                     font=("Segoe UI", 22, "bold"), text_color=FOX_ORANGE).pack()
        ctk.CTkLabel(about, text="Open Source Intelligence Tool",
                     font=("Segoe UI", 12), text_color=FOX_TEXT_DIM).pack(pady=(0, 15))

        info_text = (
            "OSINT FOX is a GUI-based OSINT tool that gathers publicly\n"
            "available information about a target using a handle/username,\n"
            "email address, or phone number.\n\n"
            "Features:\n"
            "  \u2022 Username search across 35+ platforms\n"
            "  \u2022 Email breach checks, Gravatar, reputation\n"
            "  \u2022 Phone number carrier & location analysis\n"
            "  \u2022 Export results to PDF or TXT\n"
            "  \u2022 Sleek dark-themed interface\n\n"
            "Version 1.0"
        )
        ctk.CTkLabel(about, text=info_text, font=("Segoe UI", 11),
                     text_color=FOX_TEXT, justify="left").pack(padx=30, pady=10)

        ctk.CTkButton(about, text="Close", command=about.destroy,
                      fg_color="#3A3A5C", hover_color="#4A4A6C").pack(pady=10)

    def run(self):
        self.root.mainloop()
