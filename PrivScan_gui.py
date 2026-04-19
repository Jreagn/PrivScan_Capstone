from __future__ import annotations

import threading
import time
import queue
import uuid
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests


DEFAULT_SERVER = "http://scan.audio-sync.com"
DEFAULT_ENDPOINT = "/scan"
DEFAULT_POLL_INTERVAL_SEC = 5
DEFAULT_POLL_TIMEOUT_SEC = 3600


class PrivScanGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PrivScan Hidden-Data Detector")
        self.root.geometry("720x420")
        self.root.minsize(640, 380)

        style = ttk.Style()
        style.theme_use("clam")

        self.bg = "#2b2f36"
        self.panel = "#343a43"
        self.blue = "#2f81f7"
        self.text = "#e6edf3"

        self.root.configure(bg=self.bg)
        style.configure("TFrame", background=self.bg)
        style.configure("Panel.TFrame", background=self.panel)
        style.configure("TLabel", background=self.bg, foreground=self.text, font=("Segoe UI", 11))
        style.configure("Panel.TLabel", background=self.panel, foreground=self.text, font=("Segoe UI", 11))
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("TButton", font=("Segoe UI", 11), padding=8)
        style.map(
            "Accent.TButton",
            foreground=[("active", "white"), ("!active", "white")],
            background=[("active", self.blue), ("!active", self.blue)],
        )

        self.selected_file: Path | None = None
        self.status_var = tk.StringVar(value="Choose a file to scan for hidden data.")
        self.server_var = tk.StringVar(value=DEFAULT_SERVER)
        self.endpoint_var = tk.StringVar(value=DEFAULT_ENDPOINT)
        self.prompt_var = tk.StringVar(value="")
        self._upload_token = 0
        self._upload_lock = threading.Lock()

        self._build()

    def _build(self):
        outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True, padx=18, pady=18)

        ttk.Label(outer, text="PrivScan Hidden-Data Detector", style="Title.TLabel").pack(anchor="w", pady=(0, 10))

        panel = ttk.Frame(outer, style="Panel.TFrame")
        panel.pack(fill="both", expand=True)

        cfg = ttk.Frame(panel, style="Panel.TFrame")
        cfg.pack(fill="x", padx=14, pady=(14, 8))

        ttk.Label(cfg, text="Server URL:", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Entry(cfg, textvariable=self.server_var, width=45).grid(row=0, column=1, sticky="we", padx=(10, 0))

        ttk.Label(cfg, text="Endpoint:", style="Panel.TLabel").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(cfg, textvariable=self.endpoint_var, width=45).grid(row=1, column=1, sticky="we", padx=(10, 0), pady=(8, 0))

        ttk.Label(cfg, text="Detection notes:", style="Panel.TLabel").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(cfg, textvariable=self.prompt_var, width=45).grid(row=2, column=1, sticky="we", padx=(10, 0), pady=(8, 0))

        cfg.columnconfigure(1, weight=1)

        file_row = ttk.Frame(panel, style="Panel.TFrame")
        file_row.pack(fill="x", padx=14, pady=10)

        self.file_label = ttk.Label(file_row, text="No file selected.", style="Panel.TLabel")
        self.file_label.pack(side="left", fill="x", expand=True)

        ttk.Button(file_row, text="Import File...", command=self.import_file, style="Accent.TButton").pack(side="right")

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.pack(fill="x", padx=14, pady=10)

        self.upload_button = ttk.Button(actions, text="Upload", command=self.upload_clicked, style="Accent.TButton")
        self.upload_button.pack(side="left")
        self.clear_button = ttk.Button(actions, text="Clear", command=self.clear)
        self.clear_button.pack(side="left", padx=(10, 0))

        status = ttk.Frame(panel, style="Panel.TFrame")
        status.pack(fill="both", expand=True, padx=14, pady=(10, 14))

        ttk.Label(status, text="Status:", style="Panel.TLabel").pack(anchor="w")
        ttk.Label(status, textvariable=self.status_var, style="Panel.TLabel", wraplength=660, justify="left").pack(anchor="w", pady=(8, 0))

    def import_file(self):
        path = filedialog.askopenfilename(title="Select a file to scan")
        if not path:
            return
        self.selected_file = Path(path)
        self.file_label.config(text=str(self.selected_file))
        self.status_var.set("Ready to scan.")

    def clear(self):
        self.selected_file = None
        self.file_label.config(text="No file selected.")
        self.status_var.set("Choose a file to scan for hidden data.")

    def upload_clicked(self):
        if not self.selected_file or not self.selected_file.exists():
            messagebox.showwarning("No file", "Please import a file first.")
            return

        server = self.server_var.get().strip().rstrip("/")
        endpoint = self.endpoint_var.get().strip()
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint

        url = f"{server}{endpoint}"
        self.status_var.set(f"Uploading to {url} for hidden-data detection...")
        self._set_busy(True)
        token = self._next_upload_token()

        prompt = self.prompt_var.get().strip()
        t = threading.Thread(target=self._upload_thread, args=(token, url, self.selected_file, prompt), daemon=True)
        t.start()

    def _next_upload_token(self) -> int:
        with self._upload_lock:
            self._upload_token += 1
            return self._upload_token

    def _is_active_upload(self, token: int) -> bool:
        with self._upload_lock:
            return token == self._upload_token

    def _set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.upload_button.config(state=state)
        self.clear_button.config(state=state)

    def _set_status_if_active(self, token: int, message: str) -> None:
        if not self._is_active_upload(token):
            return
        self.root.after(0, lambda msg=message: self.status_var.set(msg))

    def _ask_save_path(self, token: int, title: str, initialfile: str) -> str:
        if not self._is_active_upload(token):
            return ""
        result_queue: queue.Queue[str] = queue.Queue(maxsize=1)

        def _open_dialog() -> None:
            if not self._is_active_upload(token):
                result_queue.put("")
                return
            result_queue.put(
                filedialog.asksaveasfilename(
                    title=title,
                    initialfile=initialfile,
                )
            )

        self.root.after(0, _open_dialog)
        return result_queue.get()

    def _upload_thread(self, token: int, url: str, file_path: Path, prompt: str):
        def poll_job(session: requests.Session, job_url: str):
            start = time.time()
            while True:
                if not self._is_active_upload(token):
                    return None, "Superseded by a newer upload."
                if time.time() - start > DEFAULT_POLL_TIMEOUT_SEC:
                    return None, "Timed out waiting for the server job."
                cache_buster = f"{job_url}?t={int(time.time())}"
                try:
                    resp = session.get(
                        cache_buster,
                        timeout=(10, 30),
                        headers={"Cache-Control": "no-cache"},
                    )
                except requests.Timeout:
                    time.sleep(DEFAULT_POLL_INTERVAL_SEC)
                    continue
                if resp.status_code == 200:
                    try:
                        payload = resp.json()
                    except Exception:
                        return None, "Server returned invalid JSON during polling."
                    if payload.get("request_id") and payload.get("request_id") != request_id:
                        return None, "Server returned stale status for a different upload."
                    if payload.get("filename") and payload.get("filename") != file_path.name:
                        return None, "Server returned status for a different filename."
                    status = payload.get("status")
                    if status in ("queued", "running", "pending", "processing", "waiting_for_slot") or status is None:
                        if status is None and (payload.get("analysis_result") or payload.get("llama_output") or payload.get("llama_error")):
                            return resp, None
                        if status == "waiting_for_slot":
                            self._set_status_if_active(token, "Queued. Waiting for the current scan to finish before analysis starts...")
                        time.sleep(DEFAULT_POLL_INTERVAL_SEC)
                        continue
                    if status == "error":
                        return resp, f"Server error:\n{payload.get('error') or payload.get('result')}"
                    return resp, None
                return resp, f"Server error {resp.status_code}:\n{resp.text[:500]}"

        def file_chunks(path: Path, chunk_size: int = 4 * 1024 * 1024):
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

        try:
            file_size = file_path.stat().st_size
            request_id = uuid.uuid4().hex
            parts = urlsplit(url)
            query = dict(parse_qsl(parts.query))
            query["filename"] = file_path.name
            query["request_id"] = request_id
            if prompt:
                query["prompt"] = prompt
            url = urlunsplit(parts._replace(query=urlencode(query)))

            session = requests.Session()
            session.trust_env = False
            headers = {
                "X-Filename": file_path.name,
                "X-Request-Id": request_id,
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            }
            if file_size <= 10 * 1024 * 1024:
                payload = file_path.read_bytes()
                headers["Content-Length"] = str(len(payload))
                resp = session.post(url, data=payload, headers=headers, timeout=(10, 600))
            else:
                resp = session.post(url, data=file_chunks(file_path), headers=headers, timeout=(10, 600))

            if resp.status_code == 202:
                try:
                    data = resp.json()
                except Exception:
                    self.root.after(0, lambda: self.status_var.set("Server queued the job but returned invalid JSON."))
                    return
                if data.get("request_id") and data.get("request_id") != request_id:
                    self._set_status_if_active(token, "Server returned a stale queued response for a different upload.")
                    return
                status_url = data.get("status_url")
                if not status_url:
                    self._set_status_if_active(token, "Server queued the job but did not return status_url.")
                    return
                job_url = status_url
                if status_url.startswith("/"):
                    job_url = f"{parts.scheme}://{parts.netloc}{status_url}"
                self._set_status_if_active(token, f"Queued. Polling job status...\n{job_url}")
                resp, err = poll_job(session, job_url)
                if err:
                    if err != "Superseded by a newer upload.":
                        self._set_status_if_active(token, err)
                    return
            elif resp.status_code != 200:
                self._set_status_if_active(token, f"Server error {resp.status_code}:\n{resp.text[:500]}")
                return

            content_type = resp.headers.get("content-type", "")
            if "application/json" in content_type:
                data = resp.json()
                if isinstance(data, dict) and data.get("status") in ("done", "error") and "result" in data:
                    if data.get("request_id") and data.get("request_id") != request_id:
                        self._set_status_if_active(token, "Server returned a stale job result for a different upload.")
                        return
                    data = data["result"]
                if isinstance(data, dict):
                    if data.get("request_id") and data.get("request_id") != request_id:
                        self._set_status_if_active(token, "Server returned a stale response for a different upload.")
                        return
                    if data.get("filename") and data.get("filename") != file_path.name:
                        self._set_status_if_active(token, "Server response filename did not match the uploaded file.")
                        return
                self._set_status_if_active(token, f"Success (JSON):\n{data}")
                save_path = self._ask_save_path(token, "Save server response", f"response_{file_path.stem}_detection.json")
                if not save_path:
                    self._set_status_if_active(token, "Upload succeeded, but you cancelled saving the JSON response.")
                    return
                if not self._is_active_upload(token):
                    return
                Path(save_path).write_text(str(data), encoding="utf-8")
                self._set_status_if_active(token, f"Done! Saved response to:\n{save_path}")
                return

            save_path = self._ask_save_path(token, "Save server response", f"response_{file_path.stem}_detection")
            if not save_path:
                self._set_status_if_active(token, "Upload succeeded, but you cancelled saving the response.")
                return

            if not self._is_active_upload(token):
                return
            Path(save_path).write_bytes(resp.content)
            self._set_status_if_active(token, f"Done! Saved response to:\n{save_path}")

        except requests.Timeout:
            self._set_status_if_active(token, "Timed out waiting for the server.")
        except Exception as e:
            error_msg = str(e)
            self._set_status_if_active(token, f"Upload failed:\n{error_msg}")
        finally:
            if self._is_active_upload(token):
                self.root.after(0, lambda: self._set_busy(False))


def main():
    root = tk.Tk()
    app = PrivScanGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
