from __future__ import annotations

import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import requests


DEFAULT_SERVER = "http://65.183.147.192:65432"
DEFAULT_ENDPOINT = "/scan"  # @John, change this if the server uses a different path


class PrivScanGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PrivScan Uploader")
        self.root.geometry("720x420")
        self.root.minsize(640, 380)

        # PrivScan's theme (I like blue and grey)
        style = ttk.Style()
        style.theme_use("clam")

        self.bg = "#2b2f36"      # dark grey
        self.panel = "#343a43"   # slightly lighter grey
        self.blue = "#2f81f7"    # blue accent
        self.text = "#e6edf3"    # near-white text

        self.root.configure(bg=self.bg)
        style.configure("TFrame", background=self.bg)
        style.configure("Panel.TFrame", background=self.panel)
        style.configure("TLabel", background=self.bg, foreground=self.text, font=("Segoe UI", 11))
        style.configure("Panel.TLabel", background=self.panel, foreground=self.text, font=("Segoe UI", 11))
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("TButton", font=("Segoe UI", 11), padding=8)
        style.map("Accent.TButton",
                  foreground=[("active", "white"), ("!active", "white")],
                  background=[("active", self.blue), ("!active", self.blue)])

        self.selected_file: Path | None = None
        self.status_var = tk.StringVar(value="Choose a file to upload.")
        self.server_var = tk.StringVar(value=DEFAULT_SERVER)
        self.endpoint_var = tk.StringVar(value=DEFAULT_ENDPOINT)

        self._build()

    def _build(self):
        outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True, padx=18, pady=18)

        ttk.Label(outer, text="PrivScan Uploader", style="Title.TLabel").pack(anchor="w", pady=(0, 10))

        panel = ttk.Frame(outer, style="Panel.TFrame")
        panel.pack(fill="both", expand=True)


        # server config row
        cfg = ttk.Frame(panel, style="Panel.TFrame")
        cfg.pack(fill="x", padx=14, pady=(14, 8))

        ttk.Label(cfg, text="Server URL:", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Entry(cfg, textvariable=self.server_var, width=45).grid(row=0, column=1, sticky="we", padx=(10, 0))

        ttk.Label(cfg, text="Endpoint:", style="Panel.TLabel").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(cfg, textvariable=self.endpoint_var, width=45).grid(row=1, column=1, sticky="we", padx=(10, 0), pady=(8, 0))

        cfg.columnconfigure(1, weight=1)


        # file row
        file_row = ttk.Frame(panel, style="Panel.TFrame")
        file_row.pack(fill="x", padx=14, pady=10)

        self.file_label = ttk.Label(file_row, text="No file selected.", style="Panel.TLabel")
        self.file_label.pack(side="left", fill="x", expand=True)

        ttk.Button(file_row, text="Import File…", command=self.import_file, style="Accent.TButton").pack(side="right")


        # action row
        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill="x", padx=14, pady=10)

        ttk.Button(actions, text="Upload", command=self.upload_clicked, style="Accent.TButton").pack(side="left")
        ttk.Button(actions, text="Clear", command=self.clear).pack(side="left", padx=(10, 0))


        # status box
        status = ttk.Frame(panel, style="Panel.TFrame")
        status.pack(fill="both", expand=True, padx=14, pady=(10, 14))

        ttk.Label(status, text="Status:", style="Panel.TLabel").pack(anchor="w")
        ttk.Label(status, textvariable=self.status_var, style="Panel.TLabel", wraplength=660, justify="left").pack(anchor="w", pady=(8, 0))


    # callbacks
    def import_file(self):
        path = filedialog.askopenfilename(title="Select a file to upload")
        if not path:
            return
        self.selected_file = Path(path)
        self.file_label.config(text=str(self.selected_file))
        self.status_var.set("Ready to upload.")

    def clear(self):
        self.selected_file = None
        self.file_label.config(text="No file selected.")
        self.status_var.set("Choose a file to upload.")

    def upload_clicked(self):
        if not self.selected_file or not self.selected_file.exists():
            messagebox.showwarning("No file", "Please import a file first.")
            return

        server = self.server_var.get().strip().rstrip("/")
        endpoint = self.endpoint_var.get().strip()
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint

        url = f"{server}{endpoint}"

        self.status_var.set(f"Uploading to {url} …")


        # run upload in a background thread so the UI doesn’t freeze
        t = threading.Thread(target=self._upload_thread, args=(url, self.selected_file), daemon=True)
        t.start()


    def _upload_thread(self, url: str, file_path: Path):
        try:
            with file_path.open("rb") as f:
                files = {"file": (file_path.name, f)}
                resp = requests.post(url, files=files, timeout=300)

            # update UI safely via root.after
            if resp.status_code != 200:
                self.root.after(0, lambda: self.status_var.set(f"Server error {resp.status_code}:\n{resp.text[:500]}"))
                return

            # if server returns JSON:
            content_type = resp.headers.get("content-type", "")
            if "application/json" in content_type:
                data = resp.json()
                self.root.after(0, lambda: self.status_var.set(f"Success (JSON):\n{data}"))
                return

            # otherwise, treat it as a file download
            save_path = filedialog.asksaveasfilename(
                title="Save server response",
                initialfile=f"response_{file_path.stem}",
            )
            if not save_path:
                self.root.after(0, lambda: self.status_var.set("Upload succeeded, but you cancelled saving the response."))
                return

            Path(save_path).write_bytes(resp.content)
            self.root.after(0, lambda: self.status_var.set(f"Done! Saved response to:\n{save_path}"))

        except requests.Timeout:
            self.root.after(0, lambda: self.status_var.set("Timed out waiting for the server."))
        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda message=error_msg: self.status_var.set(f"Upload failed:\n{message}"))


def main():
    root = tk.Tk()
    app = PrivScanGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()