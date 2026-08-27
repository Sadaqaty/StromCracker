import subprocess
import os
import time
import sys
import threading
import queue
import signal
import shutil

try:
    import customtkinter as ctk
except ImportError:
    print("CRITICAL: customtkinter is not installed. Run 'pip install customtkinter'.")
    sys.exit(1)

# Configuration
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Constants
CRACKED_PASSWORDS_FILE = "cracked_passwords_windows.txt"
POTFILE_NAME = "win_cracker.potfile"
SESSION_NAME = "win_cracker_session"
RESTORE_FILE = f"{SESSION_NAME}.restore"

def get_resource_path(relative_path):
    """
    Get absolute path to resource.
    Resolves to the directory of the executable when frozen by PyInstaller,
    or the directory of the script when run natively.
    """
    if getattr(sys, 'frozen', False):
        # Running as a compiled PyInstaller executable
        base_path = os.path.dirname(sys.executable)
    else:
        # Running natively
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

def get_hashcat_path():
    if os.name == 'nt':
        return get_resource_path("hashcat.exe")
    else:
        # On Linux, rely on the system PATH
        path = shutil.which("hashcat")
        if path: return path
        return "hashcat" # Fallback

def get_default_wordlist():
    if os.name == 'nt':
        return get_resource_path("rockyou.txt")
    else:
        # Kali Linux default rockyou location
        kali_path = "/usr/share/wordlists/rockyou.txt"
        if os.path.exists(kali_path): return kali_path
        return get_resource_path("rockyou.txt")

class WinCrackerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("StormCracker GPU Engine")
        self.geometry("900x650")
        self.minsize(800, 600)
        
        self.hashcat_proc = None
        self.update_queue = queue.Queue()
        self.is_cracking = False
        
        self._build_ui()
        self.after(100, self._process_queue)
        
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
        
        # Metrics
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
        
        self.lbl_candidates = ctk.CTkLabel(prog_frame, text="Waiting for target...", font=ctk.CTkFont(family="Consolas", size=16), text_color="#00FFCC")
        self.lbl_candidates.grid(row=1, column=0, pady=(10, 0))
        
        # Console & Controls
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
        
        self.lbl_target = ctk.CTkLabel(control_frame, text="No target selected", font=ctk.CTkFont(size=11), text_color="gray", wraplength=120)
        self.lbl_target.pack(fill="x", padx=20, pady=(0, 10))
        
        self.btn_select_wordlist = ctk.CTkButton(control_frame, text="Select Wordlist (Optional)", command=self._select_wordlist)
        self.btn_select_wordlist.pack(fill="x", padx=20, pady=(0, 5))
        
        self.wordlist_file = get_default_wordlist()
        wl_name = os.path.basename(self.wordlist_file) if self.wordlist_file else "None"
        self.lbl_wordlist = ctk.CTkLabel(control_frame, text=f"WL: {wl_name}", font=ctk.CTkFont(size=11), text_color="gray", wraplength=120)
        self.lbl_wordlist.pack(fill="x", padx=20, pady=(0, 20))
        
        self.btn_start = ctk.CTkButton(control_frame, text="ENGAGE", fg_color="#00AA00", hover_color="#008800", height=50, font=ctk.CTkFont(weight="bold"), command=self._toggle_crack)
        self.btn_start.pack(fill="x", padx=20, pady=10)
        
        self.btn_extract = ctk.CTkButton(control_frame, text="Extract Trophies", command=self._extract_keys)
        self.btn_extract.pack(fill="x", padx=20, pady=10)
        
        self.target_file = None
        self._log("System initialized. Awaiting target.")

    def _create_metric(self, parent, col, title, value):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=0, column=col, padx=10, pady=15)
        
        lbl_title = ctk.CTkLabel(frame, text=title, text_color="gray", font=ctk.CTkFont(size=12))
        lbl_title.pack()
        
        lbl_value = ctk.CTkLabel(frame, text=value, font=ctk.CTkFont(size=24, weight="bold"))
        lbl_value.pack()
        
        return lbl_value

    def _log(self, message):
        self.console.configure(state="normal")
        timestamp = time.strftime("%H:%M:%S")
        self.console.insert("end", f"[{timestamp}] {message}\n")
        self.console.see("end")
        self.console.configure(state="disabled")

    def _select_file(self):
        from tkinter import filedialog
        file = filedialog.askopenfilename(title="Select .hc22000 Hash File", filetypes=(("Hashcat Files", "*.hc22000"), ("All Files", "*.*")))
        if file:
            self.target_file = file
            self.lbl_target.configure(text=os.path.basename(file))
            self._log(f"Target locked: {os.path.basename(file)}")

    def _select_wordlist(self):
        from tkinter import filedialog
        file = filedialog.askopenfilename(title="Select Wordlist", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
        if file:
            self.wordlist_file = file
            self.lbl_wordlist.configure(text=f"WL: {os.path.basename(file)}")
            self._log(f"Wordlist loaded: {os.path.basename(file)}")

    def _toggle_crack(self):
        if self.is_cracking:
            self._pause_crack()
        else:
            self._start_crack()

    def _start_crack(self):
        if not self.target_file:
            self._log("ERROR: No target file selected.")
            return
            
        hashcat_exe = get_hashcat_path()
        wordlist = self.wordlist_file
        
        # On Linux, shutil.which might return something valid even if it's not a full absolute path in our dir, 
        # but if it's Windows we definitely want to check exists if it's supposed to be embedded.
        if os.name == 'nt' and not os.path.exists(hashcat_exe):
            self._log("CRITICAL: Embedded hashcat.exe not found.")
            return
            
        if not wordlist or not os.path.exists(wordlist):
            self._log(f"CRITICAL: Wordlist '{wordlist}' not found.")
            return

        self.is_cracking = True
        self.btn_start.configure(text="PAUSE", fg_color="#AA0000", hover_color="#880000")
        self.lbl_candidates.configure(text="Initializing engine... Please wait.", text_color="#FFA500")
        self._log("Engaging GPU compute...")

        # Construct machine-readable command
        cmd = [
            hashcat_exe,
            "--session", SESSION_NAME,
            "--machine-readable",
            "--quiet",
            "--status",
            "--status-timer=1",
            "--potfile-path", POTFILE_NAME
        ]
        
        if os.path.exists(RESTORE_FILE):
            self._log("Restoring previous session...")
            cmd.append("--restore")
        else:
            cmd.extend([
                "-m", "22000",
                self.target_file,
                wordlist,
                "-w", "3",
                "-O"
            ])

        # Start thread
        self.crack_thread = threading.Thread(target=self._run_hashcat, args=(cmd,), daemon=True)
        self.crack_thread.start()

    def _pause_crack(self):
        if self.hashcat_proc:
            self._log("Saving session and halting compute...")
            try:
                # Send 'q' to Hashcat's stdin to trigger a clean exit and save the .restore file
                if self.hashcat_proc.stdin:
                    self.hashcat_proc.stdin.write('q\n')
                    self.hashcat_proc.stdin.flush()
                
                # Wait up to 3 seconds for clean exit
                try:
                    self.hashcat_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._log("Clean exit timed out. Forcing kill.")
                    self.hashcat_proc.kill()
                    
            except Exception as e:
                self._log(f"Interrupt failed: {e}. Forcing kill.")
                self.hashcat_proc.kill()
                
        self._reset_ui()
        self._log("Compute paused. Session saved.")

    def _reset_ui(self):
        self.is_cracking = False
        self.btn_start.configure(text="ENGAGE", fg_color="#00AA00", hover_color="#008800")
        self.lbl_candidates.configure(text="Compute paused.", text_color="gray")

    def _run_hashcat(self, cmd):
        startupinfo = None
        creationflags = 0
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW # Hide console window
            creationflags = subprocess.CREATE_NO_WINDOW
            
        # Force Python to not buffer the output so the UI updates instantly
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
            
        try:
            self.hashcat_proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1, # Line buffered
                env=env,
                startupinfo=startupinfo,
                creationflags=creationflags
            )
            
            # Read stdout line by line
            for line in self.hashcat_proc.stdout:
                line = line.strip()
                if line.startswith("STATUS"):
                    self.update_queue.put(("status", line))
                elif "Recovered" in line or "Exhausted" in line:
                     self.update_queue.put(("log", line))
                     
            self.hashcat_proc.wait()
            self.update_queue.put(("done", None))
            
        except Exception as e:
            self.update_queue.put(("log", f"Error: {e}"))
            self.update_queue.put(("done", None))

    def _process_queue(self):
        try:
            while True:
                msg_type, data = self.update_queue.get_nowait()
                
                if msg_type == "log":
                    self._log(data)
                    
                elif msg_type == "status":
                    try:
                        # Parse modern machine-readable status (tab separated Key-Value pairs)
                        # Example: STATUS 3 SPEED 1207 1000 PROGRESS 9404 57377540 TEMP 44
                        parts = data.split('\t')
                        
                        # Convert to dictionary for easy access
                        # The format is typically: KEY  VAL1  [VAL2]  KEY  VAL1
                        # We will iterate and build a dict based on known keys
                        parsed_data = {}
                        i = 0
                        while i < len(parts):
                            key = parts[i]
                            if key == "STATUS" and i + 1 < len(parts):
                                parsed_data["STATUS"] = int(parts[i+1])
                                i += 2
                            elif key == "SPEED" and i + 2 < len(parts):
                                parsed_data["SPEED"] = float(parts[i+1])
                                i += 3
                            elif key == "PROGRESS" and i + 2 < len(parts):
                                parsed_data["PROGRESS_CUR"] = int(parts[i+1])
                                parsed_data["PROGRESS_ALL"] = int(parts[i+2])
                                i += 3
                            elif key == "TEMP" and i + 1 < len(parts):
                                parsed_data["TEMP"] = parts[i+1]
                                i += 2
                            elif key == "EST" and i + 1 < len(parts): # Some versions use EST
                                parsed_data["EST"] = int(parts[i+1])
                                i += 2
                            elif key == "CAND" and i + 1 < len(parts): # Some versions use CAND
                                parsed_data["CAND"] = parts[i+1]
                                i += 2
                            else:
                                i += 1

                        if "STATUS" in parsed_data:
                            status_id = parsed_data["STATUS"]
                            
                            # Speed Formatting
                            if "SPEED" in parsed_data:
                                speed = parsed_data["SPEED"]
                                if speed > 1000000:
                                    self.metric_speed.configure(text=f"{speed/1000000:.1f} MH/s")
                                elif speed > 1000:
                                    self.metric_speed.configure(text=f"{speed/1000:.1f} kH/s")
                                else:
                                    self.metric_speed.configure(text=f"{int(speed)} H/s")
                                    
                            # Progress Formatting
                            if "PROGRESS_CUR" in parsed_data and "PROGRESS_ALL" in parsed_data:
                                prog_cur = parsed_data["PROGRESS_CUR"]
                                prog_all = parsed_data["PROGRESS_ALL"]
                                if prog_all > 0:
                                    perc = (prog_cur / prog_all)
                                    self.progress_bar.set(perc)
                                    self.metric_prog.configure(text=f"{perc*100:.2f}%")
                                    
                            # Temp Formatting
                            if "TEMP" in parsed_data:
                                temp = parsed_data["TEMP"]
                                self.metric_temp.configure(text=f"{temp}°C")
                                try:
                                    temp_val = int(temp)
                                    if temp_val > 80: self.metric_temp.configure(text_color="#FF0000")
                                    elif temp_val > 70: self.metric_temp.configure(text_color="#FFA500")
                                    else: self.metric_temp.configure(text_color="white")
                                except ValueError:
                                    pass
                                    
                            if status_id == 4: # Exhausted
                                self._reset_ui()
                                self._log("Compute exhausted (Wordlist complete).")
                                self._extract_keys()
                                
                    except Exception as e:
                        self._log(f"UI Parsing Error: {e}")
                        
                elif msg_type == "done":
                    self._reset_ui()
                    self._extract_keys()
                    
        except queue.Empty:
            pass
        except Exception as e:
            self._log(f"Queue Processing Error: {e}")
            
        # Schedule next check
        self.after(100, self._process_queue)

    def _extract_keys(self):
        """Parses the potfile and logs newly found keys."""
        if not os.path.exists(POTFILE_NAME):
            self._log("No potfile found. No keys extracted.")
            return
            
        cracked_count = 0
        known_cracks = set()
        
        if os.path.exists(CRACKED_PASSWORDS_FILE):
            with open(CRACKED_PASSWORDS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if " | Key: " in line:
                        try:
                            known_cracks.add(line.split(" | ")[1] + line.split(" | Key: ")[1].strip())
                        except IndexError:
                            pass

        with open(CRACKED_PASSWORDS_FILE, "a", encoding="utf-8") as cpf:
            with open(POTFILE_NAME, "r", encoding="utf-8") as pf:
                for line in pf:
                    line = line.strip()
                    if not line: continue
                    
                    parts = line.split(":")
                    if len(parts) >= 5:
                        essid_hex = parts[-2]
                        password = parts[-1]
                        try:
                            essid = bytes.fromhex(essid_hex).decode('utf-8', 'ignore')
                        except Exception:
                            essid = essid_hex
                        
                        dup_key = essid + password
                        if dup_key not in known_cracks:
                            msg = f"VICTORY! [{essid}] Key found: {password}"
                            self._log(msg)
                            cpf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {essid} | Key: {password}\n")
                            cpf.flush()
                            known_cracks.add(dup_key)
                            cracked_count += 1
                            
        if cracked_count > 0:
            self._log(f"Extraction complete. New passwords recovered: {cracked_count}.")
        else:
            self._log("Extraction complete. No new passwords found.")

if __name__ == "__main__":
    app = WinCrackerApp()
    app.mainloop()
