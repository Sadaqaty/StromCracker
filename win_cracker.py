import subprocess
import os
import time
import sys
import threading
import queue
import signal
import shutil
import hashlib
import tempfile

try:
    import customtkinter as ctk
except ImportError:
    print("CRITICAL: customtkinter is not installed. Run 'pip install customtkinter'.")
    sys.exit(1)

# ==================== CONFIGURATION ====================
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

CRACKED_PASSWORDS_FILE = "cracked_passwords_windows.txt"
POTFILE_NAME = "win_cracker.potfile"
SESSION_NAME = "win_cracker_session"
RESTORE_FILE = f"{SESSION_NAME}.restore"
LOG_FILE = "win_cracker.log"

# ==================== LOGGING ====================
def log_to_file(message):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {message}\n")
    except:
        pass

# ==================== PATH RESOLVERS ====================
def get_resource_path(relative_path):
    """Resolve path for PyInstaller bundled resources."""
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

def get_hashcat_path():
    """Check embedded hashcat first, then system PATH."""
    # 1. Embedded (Windows .exe or Linux binary)
    local_hashcat = get_resource_path("hashcat.exe" if os.name == 'nt' else "hashcat")
    if os.path.exists(local_hashcat):
        return local_hashcat

    # 2. System PATH (Linux/Mac/Windows if installed globally)
    path_hashcat = shutil.which("hashcat")
    if path_hashcat:
        return path_hashcat

    # 3. Common installation paths (Kali/Windows defaults)
    common_paths = [
        "/usr/bin/hashcat",
        "/usr/local/bin/hashcat",
        "C:\\Program Files\\hashcat\\hashcat.exe",
        "C:\\hashcat\\hashcat.exe"
    ]
    for p in common_paths:
        if os.path.exists(p):
            return p

    return None

def get_default_wordlist():
    if os.name == 'nt':
        return get_resource_path("rockyou.txt")
    else:
        kali_path = "/usr/share/wordlists/rockyou.txt"
        if os.path.exists(kali_path):
            return kali_path
        return get_resource_path("rockyou.txt")

# ==================== MAIN APPLICATION ====================
class WinCrackerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("StormCracker GPU Engine - Reloaded")
        self.geometry("900x650")
        self.minsize(800, 600)

        # State
        self.hashcat_proc = None
        self.update_queue = queue.Queue()
        self.is_cracking = False
        self.target_file = None
        self.wordlist_file = get_default_wordlist()
        self.session_id = None          # Tracks which hash file we are cracking
        self.crack_thread = None
        self.force_stop = False

        # Build UI
        self._build_ui()
        self.after(100, self._process_queue)

        # Bind window close event to safe shutdown
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Initial checks
        self._check_hashcat_availability()
        self._log("System initialized. Awaiting target.")
        self._update_button_state()

    # ==================== UI CONSTRUCTION ====================
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Header
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))

        title = ctk.CTkLabel(header_frame, text="StormCracker", font=ctk.CTkFont(size=32, weight="bold"))
        title.pack(side="left")

        subtitle = ctk.CTkLabel(header_frame, text="GPU Hardware Acceleration", font=ctk.CTkFont(size=14), text_color="gray")
        subtitle.pack(side="left", padx=10, pady=(12, 0))

        # Dashboard Panel
        dash_frame = ctk.CTkFrame(self)
        dash_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=10)
        dash_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.metric_speed = self._create_metric(dash_frame, 0, "Hash Rate", "0 H/s")
        self.metric_temp = self._create_metric(dash_frame, 1, "GPU Temp", "0°C")
        self.metric_time = self._create_metric(dash_frame, 2, "Time Est.", "--:--:--")
        self.metric_prog = self._create_metric(dash_frame, 3, "Progress", "0.00%")

        # Progress Bar & Candidates
        prog_frame = ctk.CTkFrame(dash_frame, fg_color="transparent")
        prog_frame.grid(row=1, column=0, columnspan=4, sticky="ew", padx=20, pady=(10, 20))
        prog_frame.grid_columnconfigure(0, weight=1)

        self.progress_bar = ctk.CTkProgressBar(prog_frame, height=12)
        self.progress_bar.grid(row=0, column=0, sticky="ew")
        self.progress_bar.set(0)

        self.lbl_candidates = ctk.CTkLabel(
            prog_frame, text="Ready.", font=ctk.CTkFont(family="Consolas", size=16), text_color="#00FFCC"
        )
        self.lbl_candidates.grid(row=1, column=0, pady=(10, 0))

        # Lower Frame: Console + Controls
        lower_frame = ctk.CTkFrame(self, fg_color="transparent")
        lower_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(10, 20))
        lower_frame.grid_columnconfigure(0, weight=1)
        lower_frame.grid_rowconfigure(0, weight=1)

        self.console = ctk.CTkTextbox(lower_frame, font=ctk.CTkFont(family="Consolas", size=12))
        self.console.grid(row=0, column=0, sticky="nsew")
        self.console.configure(state="disabled")

        control_frame = ctk.CTkFrame(lower_frame)
        control_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        self.btn_select_hash = ctk.CTkButton(control_frame, text="Select Target File", command=self._select_file)
        self.btn_select_hash.pack(fill="x", padx=20, pady=(20, 5))

        self.lbl_target = ctk.CTkLabel(
            control_frame, text="No target selected", font=ctk.CTkFont(size=11), text_color="gray", wraplength=120
        )
        self.lbl_target.pack(fill="x", padx=20, pady=(0, 10))

        self.btn_select_wordlist = ctk.CTkButton(control_frame, text="Select Wordlist (Optional)", command=self._select_wordlist)
        self.btn_select_wordlist.pack(fill="x", padx=20, pady=(0, 5))

        wl_name = os.path.basename(self.wordlist_file) if self.wordlist_file and os.path.exists(self.wordlist_file) else "None"
        self.lbl_wordlist = ctk.CTkLabel(
            control_frame, text=f"WL: {wl_name}", font=ctk.CTkFont(size=11), text_color="gray", wraplength=120
        )
        self.lbl_wordlist.pack(fill="x", padx=20, pady=(0, 20))

        self.btn_start = ctk.CTkButton(
            control_frame, text="ENGAGE", fg_color="#00AA00", hover_color="#008800",
            height=50, font=ctk.CTkFont(weight="bold"), command=self._toggle_crack
        )
        self.btn_start.pack(fill="x", padx=20, pady=10)

        self.btn_extract = ctk.CTkButton(control_frame, text="Extract Trophies", command=self._extract_keys)
        self.btn_extract.pack(fill="x", padx=20, pady=10)

        # Status indicator for Hashcat availability
        self.hashcat_status = ctk.CTkLabel(
            control_frame, text="🔍 Checking Hashcat...", font=ctk.CTkFont(size=11), text_color="#FFA500"
        )
        self.hashcat_status.pack(fill="x", padx=20, pady=(10, 0))

    def _create_metric(self, parent, col, title, value):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=0, column=col, padx=10, pady=15)

        lbl_title = ctk.CTkLabel(frame, text=title, text_color="gray", font=ctk.CTkFont(size=12))
        lbl_title.pack()

        lbl_value = ctk.CTkLabel(frame, text=value, font=ctk.CTkFont(size=24, weight="bold"))
        lbl_value.pack()
        return lbl_value

    # ==================== UI HELPERS ====================
    def _log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}"
        self.console.configure(state="normal")
        self.console.insert("end", formatted + "\n")
        self.console.see("end")
        self.console.configure(state="disabled")
        log_to_file(message)  # Also write to file

    def _update_button_state(self):
        """Enable/disable controls based on cracking state and hashcat availability."""
        is_busy = self.is_cracking
        hashcat_ok = get_hashcat_path() is not None

        self.btn_select_hash.configure(state="normal" if not is_busy else "disabled")
        self.btn_select_wordlist.configure(state="normal" if not is_busy else "disabled")
        self.btn_extract.configure(state="normal" if not is_busy else "disabled")

        if is_busy:
            self.btn_start.configure(text="PAUSE", fg_color="#AA0000", hover_color="#880000")
        else:
            self.btn_start.configure(text="ENGAGE", fg_color="#00AA00", hover_color="#008800")

        # Disable ENGAGE if no target, no wordlist, or hashcat missing
        if not is_busy:
            if not self.target_file:
                self.btn_start.configure(state="disabled")
            elif not os.path.exists(self.wordlist_file):
                self.btn_start.configure(state="disabled")
            elif not hashcat_ok:
                self.btn_start.configure(state="disabled")
            else:
                self.btn_start.configure(state="normal")

    def _check_hashcat_availability(self):
        path = get_hashcat_path()
        if path:
            self.hashcat_status.configure(text=f"✅ Hashcat found: {os.path.basename(path)}", text_color="#00FF00")
        else:
            self.hashcat_status.configure(
                text="❌ Hashcat not found! Place hashcat.exe in the app folder or install globally.",
                text_color="#FF0000"
            )
        self._update_button_state()

    # ==================== FILE SELECTION ====================
    def _select_file(self):
        from tkinter import filedialog
        file = filedialog.askopenfilename(
            title="Select .hc22000 Hash File",
            filetypes=(("Hashcat Files", "*.hc22000"), ("All Files", "*.*"))
        )
        if file:
            # Clean up stale restore file if session changes
            new_session_id = hashlib.md5(file.encode()).hexdigest()
            if os.path.exists(RESTORE_FILE):
                if self.session_id and self.session_id != new_session_id:
                    self._log(f"⚠️ Session mismatch. Removing old restore file ({RESTORE_FILE}).")
                    try:
                        os.remove(RESTORE_FILE)
                    except Exception as e:
                        self._log(f"Could not remove old restore: {e}")

            self.target_file = file
            self.session_id = new_session_id
            self.lbl_target.configure(text=os.path.basename(file))
            self._log(f"Target locked: {os.path.basename(file)} (Session: {self.session_id[:8]})")
            self._update_button_state()

    def _select_wordlist(self):
        from tkinter import filedialog
        file = filedialog.askopenfilename(
            title="Select Wordlist",
            filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"))
        )
        if file:
            self.wordlist_file = file
            self.lbl_wordlist.configure(text=f"WL: {os.path.basename(file)}")
            self._log(f"Wordlist loaded: {os.path.basename(file)}")
            self._update_button_state()

    # ==================== CRACK ENGINE ====================
    def _toggle_crack(self):
        if self.is_cracking:
            self._pause_crack()
        else:
            self._start_crack()

    def _start_crack(self):
        hashcat_exe = get_hashcat_path()
        if not hashcat_exe:
            self._log("CRITICAL: Hashcat executable not found.")
            return

        if not self.target_file or not os.path.exists(self.target_file):
            self._log("ERROR: Target hash file is missing or invalid.")
            return

        if not self.wordlist_file or not os.path.exists(self.wordlist_file):
            self._log(f"ERROR: Wordlist '{self.wordlist_file}' not found.")
            return

        # Check if target file is empty
        if os.path.getsize(self.target_file) == 0:
            self._log("ERROR: Target file is empty (0 bytes).")
            return

        self.is_cracking = True
        self._update_button_state()
        self.lbl_candidates.configure(text="Initializing Hashcat engine...", text_color="#FFA500")
        self._log("Engaging GPU compute...")

        # Build command
        cmd = [
            hashcat_exe,
            "--session", SESSION_NAME,
            "--machine-readable",
            "--quiet",
            "--status",
            "--status-timer=1",
            "--potfile-path", POTFILE_NAME
        ]

        # Check for valid restore file matching this session
        if os.path.exists(RESTORE_FILE):
            # Heuristic: if we have a session ID and the restore file is from a previous session, ignore it.
            # We already removed stale on file selection, but double-check.
            self._log("Restore file detected. Attempting to resume session.")
            cmd.append("--restore")
        else:
            # Fresh start
            cmd.extend([
                "-m", "22000",
                self.target_file,
                self.wordlist_file,
                "-w", "3",          # High performance
                "-O"                # Optimized kernels
            ])
            # Optional: add --force if needed, but let's not force by default to respect GPU drivers.
            # If they want force, they can add it manually via future argument.

        # Start thread
        self.crack_thread = threading.Thread(target=self._run_hashcat, args=(cmd,), daemon=True)
        self.crack_thread.start()

    def _pause_crack(self):
        if not self.hashcat_proc:
            self._reset_ui("No process to pause.")
            return

        self._log("Saving session and pausing compute (sending 'q' to Hashcat)...")
        try:
            if self.hashcat_proc.stdin:
                self.hashcat_proc.stdin.write('q\n')
                self.hashcat_proc.stdin.flush()

            # Give it 5 seconds to exit gracefully
            self.hashcat_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._log("Graceful exit timed out. Forcing termination.")
            self.hashcat_proc.terminate()
            time.sleep(0.5)
            if self.hashcat_proc.poll() is None:
                self.hashcat_proc.kill()
        except Exception as e:
            self._log(f"Error during pause: {e}. Forcing kill.")
            try:
                self.hashcat_proc.kill()
            except:
                pass

        self._reset_ui("Compute paused. Session saved to restore file.")

    def _reset_ui(self, message="Idle."):
        self.is_cracking = False
        self.hashcat_proc = None
        self.lbl_candidates.configure(text=message, text_color="gray")
        self._update_button_state()
        self._log("Engine stopped.")

    def _run_hashcat(self, cmd):
        startupinfo = None
        creationflags = 0
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        try:
            self.hashcat_proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
                startupinfo=startupinfo,
                creationflags=creationflags
            )

            # Read stdout line by line
            for line in self.hashcat_proc.stdout:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("STATUS"):
                    self.update_queue.put(("status", line))
                elif "Recovered" in line or "Exhausted" in line:
                    self.update_queue.put(("log", line))

            # Wait for process to finish
            self.hashcat_proc.wait()

            # Check stderr for driver errors (OpenCL, CUDA)
            stderr_data = self.hashcat_proc.stderr.read()
            if stderr_data:
                for err_line in stderr_data.strip().splitlines():
                    self.update_queue.put(("log", f"⚠️ {err_line}"))

            self.update_queue.put(("done", None))

        except Exception as e:
            self.update_queue.put(("log", f"CRITICAL ERROR: {e}"))
            self.update_queue.put(("done", None))

    def _process_queue(self):
        try:
            while True:
                msg_type, data = self.update_queue.get_nowait()

                if msg_type == "log":
                    self._log(data)

                elif msg_type == "status":
                    self._parse_status(data)

                elif msg_type == "done":
                    # If we get done, check if we have any recovered keys
                    self._extract_keys()
                    self._reset_ui("Compute finished.")
                    if self.force_stop:
                        self.force_stop = False

        except queue.Empty:
            pass
        except Exception as e:
            self._log(f"Queue error: {e}")

        # Heartbeat: check if process died unexpectedly
        if self.is_cracking and self.hashcat_proc:
            if self.hashcat_proc.poll() is not None:
                self._log("⚠️ Hashcat process died unexpectedly. Resetting UI.")
                self._extract_keys()
                self._reset_ui("Process crashed.")

        self.after(100, self._process_queue)

    def _parse_status(self, data):
        """Parse Hashcat machine-readable status and update UI metrics."""
        try:
            parts = data.split('\t')
            parsed = {}
            i = 0
            while i < len(parts):
                key = parts[i]
                if key == "STATUS" and i + 1 < len(parts):
                    parsed["STATUS"] = int(parts[i+1])
                    i += 2
                elif key == "SPEED" and i + 2 < len(parts):
                    parsed["SPEED"] = float(parts[i+1])
                    i += 3
                elif key == "PROGRESS" and i + 2 < len(parts):
                    parsed["PROGRESS_CUR"] = int(parts[i+1])
                    parsed["PROGRESS_ALL"] = int(parts[i+2])
                    i += 3
                elif key == "TEMP" and i + 1 < len(parts):
                    parsed["TEMP"] = parts[i+1]
                    i += 2
                elif key == "EST" and i + 1 < len(parts):
                    parsed["EST"] = int(parts[i+1])
                    i += 2
                elif key == "CAND" and i + 1 < len(parts):
                    parsed["CAND"] = parts[i+1]
                    i += 2
                else:
                    i += 1

            if "STATUS" in parsed:
                status_id = parsed["STATUS"]
                # 1=Running, 2=Paused, 3=Quit, 4=Exhausted, 5=Cracked

                if "SPEED" in parsed:
                    speed = parsed["SPEED"]
                    if speed > 1000000:
                        self.metric_speed.configure(text=f"{speed/1000000:.1f} MH/s")
                    elif speed > 1000:
                        self.metric_speed.configure(text=f"{speed/1000:.1f} kH/s")
                    else:
                        self.metric_speed.configure(text=f"{int(speed)} H/s")

                if "PROGRESS_CUR" in parsed and "PROGRESS_ALL" in parsed:
                    cur = parsed["PROGRESS_CUR"]
                    total = parsed["PROGRESS_ALL"]
                    if total > 0:
                        perc = cur / total
                        self.progress_bar.set(perc)
                        self.metric_prog.configure(text=f"{perc*100:.2f}%")

                if "TEMP" in parsed:
                    temp = parsed["TEMP"]
                    self.metric_temp.configure(text=f"{temp}°C")
                    try:
                        tv = int(temp)
                        if tv > 80:
                            self.metric_temp.configure(text_color="#FF0000")
                        elif tv > 70:
                            self.metric_temp.configure(text_color="#FFA500")
                        else:
                            self.metric_temp.configure(text_color="white")
                    except:
                        pass

                if "CAND" in parsed and parsed["CAND"]:
                    self.lbl_candidates.configure(text=f"🔑 {parsed['CAND']}", text_color="#00FFCC")

                if status_id in (4, 5):  # Exhausted or Cracked
                    self._extract_keys()

        except Exception as e:
            self._log(f"Status parsing error: {e}")

    # ==================== KEY EXTRACTION ====================
    def _extract_keys(self):
        """Safely extract passwords from Hashcat potfile."""
        if not os.path.exists(POTFILE_NAME):
            self._log("No potfile found. No keys to extract.")
            return

        # Load already known passwords to avoid duplicates
        known = set()
        if os.path.exists(CRACKED_PASSWORDS_FILE):
            try:
                with open(CRACKED_PASSWORDS_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        if " | Key: " in line:
                            parts = line.split(" | ")
                            if len(parts) >= 3:
                                essid = parts[1].strip()
                                pwd = parts[2].replace("Key: ", "").strip()
                                known.add((essid, pwd))
            except Exception as e:
                self._log(f"Failed to read known passwords: {e}")

        new_count = 0
        try:
            with open(POTFILE_NAME, "r", encoding="utf-8") as pf, \
                 open(CRACKED_PASSWORDS_FILE, "a", encoding="utf-8") as out:

                for line in pf:
                    line = line.strip()
                    if not line:
                        continue

                    # Hashcat 22000 potfile format: hash:password
                    # hash contains ESSID in hex, we parse the last two fields
                    # Example: $HEX[70617373776f7264]:password
                    # But often: hash:password where hash includes ESSID
                    # Reliable method: look for the colon, but the hash may contain colons?
                    # Safer: split by ':' and assume password is the last field.
                    parts = line.split(':')
                    if len(parts) < 2:
                        continue

                    password = parts[-1].strip()
                    # The hash part is everything before the last colon
                    hash_part = ':'.join(parts[:-1])

                    # Try to extract ESSID from hash.
                    # For 22000, the ESSID is often hex encoded in the hash.
                    # We'll look for $HEX[...] or just assume the hash contains it.
                    # Using the method from the old code: attempt to decode hex at the end.
                    essid = "Unknown"
                    try:
                        # The last part of the hash might be the ESSID in hex
                        # Many 22000 hashes end with *essid_hex
                        # Let's just use the last 16-32 chars of hash as a fallback
                        # Actually, let's parse the 22000 format properly:
                        # Format: $NETNTLM$...$essid
                        # We can try to find the last '$' delimited part
                        if '$' in hash_part:
                            essid_candidates = hash_part.split('$')
                            for candidate in reversed(essid_candidates):
                                if candidate and len(candidate) > 4:
                                    try:
                                        decoded = bytes.fromhex(candidate).decode('utf-8', 'ignore')
                                        if decoded.isprintable() and len(decoded) > 0:
                                            essid = decoded
                                            break
                                    except:
                                        pass
                    except:
                        pass

                    if (essid, password) not in known:
                        self._log(f"🎉 VICTORY! [{essid}] Key found: {password}")
                        out.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {essid} | Key: {password}\n")
                        out.flush()
                        known.add((essid, password))
                        new_count += 1

            if new_count > 0:
                self._log(f"Extraction complete. New passwords recovered: {new_count}.")
            else:
                self._log("Extraction complete. No new passwords found.")

        except Exception as e:
            self._log(f"Failed to extract keys: {e}")

    # ==================== SAFE SHUTDOWN ====================
    def _on_closing(self):
        """Handle window close: stop Hashcat cleanly before exiting."""
        if self.is_cracking and self.hashcat_proc:
            self._log("⚠️ Closing window while engine is running. Attempting graceful stop...")
            self.force_stop = True
            try:
                if self.hashcat_proc.stdin:
                    self.hashcat_proc.stdin.write('q\n')
                    self.hashcat_proc.stdin.flush()
                self.hashcat_proc.wait(timeout=3)
            except:
                try:
                    self.hashcat_proc.terminate()
                except:
                    pass
            self._log("Engine terminated. Exiting.")
        self.destroy()

# ==================== ENTRY POINT ====================
if __name__ == "__main__":
    app = WinCrackerApp()
    app.mainloop()