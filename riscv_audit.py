import psutil
import time
import logging
import os
import subprocess
from datetime import datetime
import curses # For Text User Interface (TUI)

# --- Configuration ---
LOG_FILE = "system_audit.log"
AUDIT_INTERVAL_SECONDS = 5  # How often to run the audit and update display
AUTH_LOG_LINES_TO_CHECK = 50  # Number of recent lines to check in auth logs
AUTH_LOG_PATHS = [
    "/var/log/auth.log",  # Debian/Ubuntu
    "/var/log/secure",    # RHEL/CentOS/Fedora
    "/var/log/messages"   # General (less specific, but might contain auth info)
]
MAX_CONNECTIONS_ON_SCREEN = 8 # Max active connections to display in TUI window
MAX_PROCESSES_ON_SCREEN = 8   # Max processes to display in TUI window
MAX_AUTH_LOGS_ON_SCREEN = 5   # Max auth log entries to display in TUI window

# --- Logging Setup ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger()

# --- Global variables for bandwidth calculation ---
last_net_io_counters = None
last_timestamp = None

def get_network_stats():
    """
    Retrieves network bandwidth usage and connection counts.
    Calculates bandwidth by comparing network I/O counters over time.
    """
    global last_net_io_counters, last_timestamp

    current_net_io_counters = psutil.net_io_counters()
    current_timestamp = time.time()

    total_bytes_sent = current_net_io_counters.bytes_sent
    total_bytes_recv = current_net_io_counters.bytes_recv

    upload_speed_kbps = 0
    download_speed_kbps = 0

    if last_net_io_counters and last_timestamp:
        time_delta = current_timestamp - last_timestamp
        if time_delta > 0:
            bytes_sent_delta = total_bytes_sent - last_net_io_counters.bytes_sent
            bytes_recv_delta = total_bytes_recv - last_net_io_counters.bytes_recv

            upload_speed_kbps = (bytes_sent_delta / time_delta) / 1024
            download_speed_kbps = (bytes_recv_delta / time_delta) / 1024

    last_net_io_counters = current_net_io_counters
    last_timestamp = current_timestamp

    # Get connection counts
    connections = psutil.net_connections(kind='inet')
    established_connections = sum(1 for conn in connections if conn.status == 'ESTABLISHED')
    listening_connections = sum(1 for conn in connections if conn.status == 'LISTEN')
    total_connections = len(connections)

    return {
        "upload_speed_kbps": upload_speed_kbps,
        "download_speed_kbps": download_speed_kbps,
        "established_connections": established_connections,
        "listening_connections": listening_connections,
        "total_connections": total_connections
    }

def get_active_connections():
    """
    Retrieves detailed information about all active network connections.
    """
    active_connections = []
    for conn in psutil.net_connections(kind='inet'):
        conn_info = {
            "fd": conn.fd,
            "family": conn.family.name,
            "type": conn.type.name,
            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
            "status": conn.status,
            "pid": conn.pid,
            "process_name": "N/A"
        }
        if conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                conn_info["process_name"] = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                conn_info["process_name"] = "N/A (Process Gone/Denied)"
        active_connections.append(conn_info)
    return active_connections

def get_open_ports():
    """
    Lists all open (listening) TCP/UDP ports and the processes using them.
    """
    open_ports = []
    try:
        # Using 'ss -tulnp' for a comprehensive list of listening ports and associated processes
        # -t: TCP, -u: UDP, -l: listening, -n: numeric, -p: processes
        result = subprocess.run(['ss', '-tulnp'], capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()[1:] # Skip header
        for line in lines:
            parts = line.split()
            if len(parts) < 6:
                continue
            protocol = parts[0]
            local_address_port = parts[4]
            process_info = parts[5] if len(parts) > 5 else "N/A" # Process info can be missing

            # Extract port from address:port
            try:
                port = local_address_port.rsplit(':', 1)[-1]
            except IndexError:
                port = "N/A"

            # Extract PID and Program Name from process_info (e.g., "users:(("sshd",pid=1234,fd=3)))")
            pid = "N/A"
            program = "N/A"
            if "pid=" in process_info:
                try:
                    pid_start = process_info.find("pid=") + 4
                    pid_end = process_info.find(",", pid_start)
                    pid = process_info[pid_start:pid_end]
                    
                    program_start = process_info.find("(\"") + 2
                    program_end = process_info.find("\",", program_start)
                    program = process_info[program_start:program_end]
                except Exception:
                    pass # Couldn't parse, keep as N/A

            open_ports.append({
                "protocol": protocol,
                "port": port,
                "local_address": local_address_port,
                "process_info": process_info,
                "pid": pid,
                "program": program
            })
    except FileNotFoundError:
        logger.error("`ss` command not found. Please install iproute2 package.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running `ss` command: {e.stderr}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while getting open ports: {e}")
    return open_ports

def get_running_processes():
    """
    Lists all running processes with their PID, name, and username.
    """
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'cpu_percent', 'memory_percent']):
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'username', 'cmdline', 'cpu_percent', 'memory_percent'])
            # cmdline can be None if process has exited or permissions issue
            pinfo['cmdline'] = ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else ''
            processes.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes

def audit_auth_logs():
    """
    Checks common authentication log files for failed login attempts.
    """
    suspicious_entries = []
    for log_path in AUTH_LOG_PATHS:
        if os.path.exists(log_path):
            try:
                # Read the last N lines
                with open(log_path, 'r', errors='ignore') as f:
                    lines = f.readlines()
                    recent_lines = lines[-AUTH_LOG_LINES_TO_CHECK:]

                for line in recent_lines:
                    line_lower = line.lower()
                    if "failed password" in line_lower or \
                       "authentication failure" in line_lower or \
                       "invalid user" in line_lower:
                        suspicious_entries.append(f"[{log_path}] {line.strip()}")
            except Exception as e:
                logger.warning(f"Could not read log file {log_path}: {e}")
        else:
            logger.debug(f"Auth log path not found: {log_path}")
    return suspicious_entries

def get_system_security_checks():
    """
    Performs additional system security-related checks.
    """
    checks = {}

    # 1. Logged-in Users
    users = psutil.users()
    checks['logged_in_users'] = []
    for user in users:
        checks['logged_in_users'].append({
            "name": user.name,
            "terminal": user.terminal,
            "host": user.host,
            "started": datetime.fromtimestamp(user.started).strftime("%Y-%m-%d %H:%M:%S")
        })

    # 2. Firewall Status (UFW or Firewalld)
    checks['firewall_status'] = "Unknown"
    try:
        # Check UFW
        ufw_status = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True, check=False)
        if ufw_status.returncode == 0:
            if "Status: active" in ufw_status.stdout:
                checks['firewall_status'] = "UFW Active"
                checks['ufw_rules'] = [line.strip() for line in ufw_status.stdout.splitlines() if line.strip() and not line.startswith("Status:")]
            else:
                checks['firewall_status'] = "UFW Inactive"
        else:
            # Check Firewalld
            firewalld_status = subprocess.run(['sudo', 'firewall-cmd', '--state'], capture_output=True, text=True, check=False)
            if firewalld_status.returncode == 0 and "running" in firewalld_status.stdout:
                checks['firewall_status'] = "Firewalld Active"
                # Optionally, fetch more firewalld info:
                zones = subprocess.run(['sudo', 'firewall-cmd', '--get-active-zones'], capture_output=True, text=True, check=False)
                checks['firewalld_zones'] = [line.strip() for line in zones.stdout.splitlines() if line.strip()]
            else:
                checks['firewall_status'] = "Firewall Service Not Running/Installed"
    except FileNotFoundError:
        checks['firewall_status'] = "Firewall command (ufw/firewall-cmd) not found."
    except Exception as e:
        logger.error(f"Error checking firewall status: {e}")
        checks['firewall_status'] = f"Error: {e}"

    # 3. System Uptime
    boot_time_timestamp = psutil.boot_time()
    checks['system_uptime'] = str(datetime.now() - datetime.fromtimestamp(boot_time_timestamp))

    # 4. Disk Usage of Root Partition
    disk_usage = psutil.disk_usage('/')
    checks['root_disk_usage'] = {
        "total": f"{disk_usage.total / (1024**3):.2f} GB",
        "used": f"{disk_usage.used / (1024**3):.2f} GB",
        "free": f"{disk_usage.free / (1024**3):.2f} GB",
        "percent": f"{disk_usage.percent}%"
    }

    # 5. Sudoers File Existence and Permissions (Basic Check)
    sudoers_path = "/etc/sudoers"
    checks['sudoers_file'] = {
        "exists": os.path.exists(sudoers_path)
    }
    if checks['sudoers_file']['exists']:
        try:
            stat_info = os.stat(sudoers_path)
            checks['sudoers_file']['permissions'] = oct(stat_info.st_mode & 0o777)
            checks['sudoers_file']['owner'] = stat_info.st_uid
            checks['sudoers_file']['group'] = stat_info.st_gid
        except Exception as e:
            checks['sudoers_file']['error'] = f"Could not get stats: {e}"

    return checks

def draw_window(stdscr, y, x, height, width, title, content_lines, color_pair=0):
    """
    Draws a bordered window with a title and content.
    Handles truncation if content exceeds window height.
    """
    win = stdscr.subwin(height, width, y, x)
    win.box()
    win.addstr(0, 2, f" {title} ", curses.A_BOLD | color_pair)

    for i, line in enumerate(content_lines):
        if i + 1 < height - 1: # Leave space for border and title
            # Truncate line if it's too long for the window width
            if len(line) >= width - 4:
                line = line[:width - 7] + "..."
            try:
                win.addstr(i + 1, 2, line)
            except curses.error:
                # Handle cases where line might extend beyond window boundary
                pass
    win.refresh()

def main_tui_loop(stdscr):
    """
    Main TUI loop for displaying system audit information.
    """
    curses.curs_set(0)  # Hide the cursor
    stdscr.nodelay(True) # Make getch non-blocking
    stdscr.clear()
    stdscr.refresh()

    # Define color pairs
    curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)

    # Initialize bandwidth calculation
    get_network_stats() # Call once to set initial counters

    while True:
        # Get terminal dimensions
        max_y, max_x = stdscr.getmaxyx()

        # Ensure minimum size for display
        if max_y < 25 or max_x < 80:
            stdscr.clear()
            stdscr.addstr(0, 0, "Terminal too small. Please resize to at least 80x25.")
            stdscr.refresh()
            time.sleep(1)
            continue

        # Fetch data
        network_stats = get_network_stats()
        active_connections = get_active_connections()
        open_ports = get_open_ports() # Still useful for log, but less prominent on screen
        running_processes = get_running_processes()
        auth_log_findings = audit_auth_logs()
        system_security_checks = get_system_security_checks()

        # Clear screen for redraw
        stdscr.clear()

        # --- Layout Definition ---
        # Top row: Network Stats (left) | System Checks (right)
        # Middle row: Active Connections (left) | Auth Logs (right)
        # Bottom row: Running Processes (full width)

        # Heights and widths for windows
        net_stats_height = 7
        conn_height = MAX_CONNECTIONS_ON_SCREEN + 3 # +3 for border and title
        auth_log_height = MAX_AUTH_LOGS_ON_SCREEN + 3
        process_height = MAX_PROCESSES_ON_SCREEN + 3
        
        # Calculate available height for process window dynamically
        remaining_height = max_y - (net_stats_height + conn_height + 1) # 1 for separator line/spacing
        process_height = max(process_height, remaining_height) # Ensure it's at least min size

        # Calculate widths for left/right columns
        col_width = max_x // 2

        # --- Network Stats Window (Top-Left) ---
        net_stats_lines = [
            f"Upload: {network_stats['upload_speed_kbps']:.2f} KB/s",
            f"Download: {network_stats['download_speed_kbps']:.2f} KB/s",
            f"Established: {network_stats['established_connections']}",
            f"Listening: {network_stats['listening_connections']}",
            f"Total: {network_stats['total_connections']}"
        ]
        draw_window(stdscr, 0, 0, net_stats_height, col_width, "Network Activity", net_stats_lines, curses.color_pair(1))

        # --- System Security Checks Window (Top-Right) ---
        sys_check_lines = [
            f"Uptime: {system_security_checks['system_uptime'].split('.')[0]}", # Remove milliseconds
            f"Firewall: {system_security_checks['firewall_status']}",
            f"Root Disk Used: {system_security_checks['root_disk_usage']['percent']}",
            f"Sudoers Exists: {system_security_checks['sudoers_file']['exists']}",
            f"Sudoers Perms: {system_security_checks['sudoers_file'].get('permissions', 'N/A')}",
            "Users: " + ", ".join([u['name'] for u in system_security_checks['logged_in_users']])
        ]
        draw_window(stdscr, 0, col_width, net_stats_height, max_x - col_width, "System Checks", sys_check_lines, curses.color_pair(2))

        # --- Active Connections Window (Middle-Left) ---
        conn_lines = []
        # Sort connections by status, then by PID for some consistency
        sorted_connections = sorted(active_connections, key=lambda c: (c['status'], c['pid'] or 0))
        for i, conn in enumerate(sorted_connections[:MAX_CONNECTIONS_ON_SCREEN]):
            conn_lines.append(f"[{conn['status']}] {conn['laddr']} <-> {conn['raddr']} (PID:{conn['pid']})")
        if len(active_connections) > MAX_CONNECTIONS_ON_SCREEN:
            conn_lines.append(f"...({len(active_connections) - MAX_CONNECTIONS_ON_SCREEN} more logged)")
        if not conn_lines:
            conn_lines.append("No active connections.")
        draw_window(stdscr, net_stats_height, 0, conn_height, col_width, "Active Connections", conn_lines, curses.color_pair(3))

        # --- Suspicious Auth Log Entries Window (Middle-Right) ---
        auth_log_lines = []
        if auth_log_findings:
            for entry in auth_log_findings[:MAX_AUTH_LOGS_ON_SCREEN]:
                auth_log_lines.append(entry)
            if len(auth_log_findings) > MAX_AUTH_LOGS_ON_SCREEN:
                auth_log_lines.append(f"...({len(auth_log_findings) - MAX_AUTH_LOGS_ON_SCREEN} more logged)")
        else:
            auth_log_lines.append("No suspicious entries.")
        draw_window(stdscr, net_stats_height, col_width, auth_log_height, max_x - col_width, "Auth Log Warnings", auth_log_lines, curses.color_pair(4))

        # --- Running Processes Window (Bottom - Full Width) ---
        process_lines = ["PID   CPU%  MEM%  User      Name"]
        # Sort processes by CPU usage for more relevant display
        # Need to ensure cpu_percent is called with interval=None for non-blocking
        # And handle NoSuchProcess for processes that might disappear
        sorted_processes = []
        for p in running_processes:
            try:
                proc_obj = psutil.Process(p['pid'])
                p['cpu_percent'] = proc_obj.cpu_percent(interval=None) # Non-blocking
                p['memory_percent'] = proc_obj.memory_percent()
                sorted_processes.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        sorted_processes.sort(key=lambda p: p.get('cpu_percent', 0), reverse=True)

        for proc in sorted_processes[:MAX_PROCESSES_ON_SCREEN]:
            process_lines.append(
                f"{proc['pid']:<5} {proc.get('cpu_percent', 0):<5.1f} {proc.get('memory_percent', 0):<5.1f} "
                f"{proc['username']:<9} {proc['name']}"
            )
        if len(running_processes) > MAX_PROCESSES_ON_SCREEN:
            process_lines.append(f"...({len(running_processes) - MAX_PROCESSES_ON_SCREEN} more logged)")
        if not process_lines:
            process_lines.append("No running processes.")

        draw_window(stdscr, net_stats_height + conn_height, 0, process_height, max_x, "Running Processes", process_lines, curses.color_pair(1))


        # --- Detailed Logging (to file) ---
        current_time_log = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"--- System Audit Report ({current_time_log}) ---")
        logger.info("--- Network Activity ---")
        logger.info(f"  Upload Speed: {network_stats['upload_speed_kbps']:.2f} KB/s")
        logger.info(f"  Download Speed: {network_stats['download_speed_kbps']:.2f} KB/s")
        logger.info(f"  Established Connections: {network_stats['established_connections']}")
        logger.info(f"  Listening Ports: {network_stats['listening_connections']}")
        logger.info(f"  Total Connections: {network_stats['total_connections']}")

        logger.info("\n--- Active Connections (All) ---")
        if active_connections:
            for conn in sorted_connections: # Log all connections
                logger.info(f"  - FD: {conn['fd']}, Family: {conn['family']}, Type: {conn['type']}, Status: {conn['status']}, "
                            f"Local: {conn['laddr']}, Remote: {conn['raddr']}, PID: {conn['pid']}, Process: {conn['process_name']}")
        else:
            logger.info("  No active connections found.")

        logger.info("\n--- Open Ports ---")
        if open_ports:
            for port_info in open_ports:
                logger.info(f"  Proto: {port_info['protocol']}, Port: {port_info['port']}, "
                            f"Local: {port_info['local_address']}, PID: {port_info['pid']}, "
                            f"Program: {port_info['program']}")
        else:
            logger.info("  No open listening ports found.")

        logger.info("\n--- Running Processes (All) ---")
        # Log all processes, sorted by CPU
        for proc in sorted_processes:
            logger.info(f"  PID: {proc['pid']}, Name: {proc['name']}, User: {proc['username']}, "
                        f"CPU%: {proc.get('cpu_percent', 0):.1f}, MEM%: {proc.get('memory_percent', 0):.1f}, "
                        f"Cmd: {proc['cmdline']}")

        logger.info("\n--- Suspicious Auth Log Entries ---")
        if auth_log_findings:
            for entry in auth_log_findings:
                logger.info(f"  - {entry}")
        else:
            logger.info("  No suspicious entries found in recent logs.")

        logger.info("\n--- Additional System Security Checks ---")
        logger.info(f"  System Uptime: {system_security_checks['system_uptime'].split('.')[0]}")
        logger.info(f"  Firewall Status: {system_security_checks['firewall_status']}")
        if 'ufw_rules' in system_security_checks:
            for rule in system_security_checks['ufw_rules']:
                logger.info(f"    UFW Rule: {rule}")
        if 'firewalld_zones' in system_security_checks:
            for zone in system_security_checks['firewalld_zones']:
                logger.info(f"    Firewalld Zone: {zone}")
        logger.info(f"  Root Disk Usage: {system_security_checks['root_disk_usage']['percent']} used "
                    f"({system_security_checks['root_disk_usage']['used']} / {system_security_checks['root_disk_usage']['total']})")
        logger.info(f"  Sudoers File Exists: {system_security_checks['sudoers_file']['exists']}")
        if system_security_checks['sudoers_file']['exists']:
            logger.info(f"    Sudoers Permissions: {system_security_checks['sudoers_file'].get('permissions', 'N/A')}")
            logger.info(f"    Sudoers Owner (UID): {system_security_checks['sudoers_file'].get('owner', 'N/A')}")
            logger.info(f"    Sudoers Group (GID): {system_security_checks['sudoers_file'].get('group', 'N/A')}")
        if 'error' in system_security_checks['sudoers_file']:
            logger.info(f"    Sudoers Error: {system_security_checks['sudoers_file']['error']}")
        logger.info("  Logged-in Users:")
        if system_security_checks['logged_in_users']:
            for user in system_security_checks['logged_in_users']:
                logger.info(f"    - Name: {user['name']}, Terminal: {user['terminal']}, "
                            f"Host: {user['host']}, Started: {user['started']}")
        else:
            logger.info("    No users currently logged in.")

        logger.info("-" * 50 + "\n") # Separator for log entries

        stdscr.refresh()
        time.sleep(AUDIT_INTERVAL_SECONDS)

        # Check for user input (e.g., 'q' to quit)
        key = stdscr.getch()
        if key == ord('q') or key == ord('Q'):
            break

def main():
    """
    Main function to run the system audit loop.
    """
    print("Starting Linux System Security Auditor (TUI Mode)...")
    print("This script requires root privileges. Please run with `sudo`.")
    print(f"Logging all findings to: {os.path.abspath(LOG_FILE)}")
    print("Press 'q' to quit the TUI at any time.")
    time.sleep(3) # Give user time to read initial message

    try:
        # Initialize curses
        curses.wrapper(main_tui_loop)
    except KeyboardInterrupt:
        print("\nAuditing stopped by user. Exiting.")
        logger.info("Auditing stopped by user. Exiting.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        logger.exception("An unhandled error occurred during auditing.")
    finally:
        # Ensure terminal is restored even if an error occurs
        pass # curses.wrapper handles this cleanup

if __name__ == "__main__":
    main()
