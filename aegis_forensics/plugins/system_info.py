import os
import sys
import subprocess
import platform
from typing import List, Dict, Any

# Platform-specific registry import
IS_WINDOWS = sys.platform == "win32"
if IS_WINDOWS:
    import winreg
else:
    winreg = None


def query_registry_run_keys() -> List[Dict[str, str]]:
    """
    Queries standard Windows Registry Run keys for persistence.
    """
    run_items = []
    if not IS_WINDOWS or winreg is None:
        return run_items
        
    targets = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce")
    ]
    
    for hive, subkey, category in targets:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                num_values = winreg.QueryInfoKey(key)[1]
                for i in range(num_values):
                    name, value, _ = winreg.EnumValue(key, i)
                    run_items.append({
                        "category": category,
                        "name": name,
                        "value": str(value)
                    })
        except Exception:
            # Key might not exist or access denied
            pass
            
    return run_items


def query_usb_history() -> List[Dict[str, str]]:
    """
    Queries USBSTOR registry key to find history of connected USB storage devices.
    """
    usb_devices = []
    if not IS_WINDOWS or winreg is None:
        return usb_devices
        
    subkey = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ) as key:
            num_subkeys = winreg.QueryInfoKey(key)[0]
            for i in range(num_subkeys):
                device_id = winreg.EnumKey(key, i)
                # Device ID looks like: Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_...
                # Inside this, there are unique serial number keys
                device_key_path = f"{subkey}\\{device_id}"
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_key_path, 0, winreg.KEY_READ) as dev_key:
                        num_serials = winreg.QueryInfoKey(dev_key)[0]
                        for j in range(num_serials):
                            serial = winreg.EnumKey(dev_key, j)
                            serial_key_path = f"{device_key_path}\\{serial}"
                            try:
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, serial_key_path, 0, winreg.KEY_READ) as ser_key:
                                    friendly_name = ""
                                    try:
                                        friendly_name = winreg.QueryValueEx(ser_key, "FriendlyName")[0]
                                    except FileNotFoundError:
                                        pass
                                        
                                    usb_devices.append({
                                        "device_id": device_id,
                                        "serial": serial,
                                        "friendly_name": friendly_name or "Unknown USB Device"
                                    })
                            except Exception:
                                pass
                except Exception:
                    pass
    except Exception:
        pass
        
    return usb_devices


def get_active_connections() -> List[Dict[str, str]]:
    """
    Gathers active network connections using 'netstat' shell command.
    """
    connections = []
    try:
        # netstat -ano: active connections with numerical addresses and PID
        output = subprocess.check_output("netstat -ano", shell=True, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
        lines = output.splitlines()
        for line in lines:
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] in ["TCP", "UDP"]:
                proto = parts[0]
                local_addr = parts[1]
                foreign_addr = parts[2]
                state = parts[3] if proto == "TCP" else "-"
                pid = parts[-1] if len(parts) > (4 if proto == "TCP" else 3) else "-"
                
                # Filter out standard listening/local loops if desired, or keep all
                connections.append({
                    "protocol": proto,
                    "local_address": local_addr,
                    "foreign_address": foreign_addr,
                    "state": state,
                    "pid": pid
                })
    except Exception as e:
        connections.append({"error": f"Failed to get connections: {e}"})
        
    return connections[:1000] # Limit output


def get_running_processes() -> List[Dict[str, str]]:
    """
    Gathers running processes list using 'tasklist' shell command on Windows
    or 'ps' on Unix.
    """
    processes = []
    try:
        if IS_WINDOWS:
            # tasklist /FO CSV /NH: output in CSV format, no header
            output = subprocess.check_output("tasklist /FO CSV /NH", shell=True, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
            lines = output.splitlines()
            for line in lines:
                if not line.strip():
                    continue
                # Split CSV line (format: "Image Name","PID","Session Name","Session#","Mem Usage")
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 5:
                    processes.append({
                        "name": parts[0],
                        "pid": parts[1],
                        "session": parts[2],
                        "memory": parts[4]
                    })
        else:
            # Linux/Mac fallback
            output = subprocess.check_output("ps -eo comm,pid,rss", shell=True, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
            lines = output.splitlines()
            for line in lines[1:]:  # Skip header
                parts = line.strip().split()
                if len(parts) >= 3:
                    processes.append({
                        "name": parts[0],
                        "pid": parts[1],
                        "session": "-",
                        "memory": f"{int(parts[2]) // 1024} MB" if parts[2].isdigit() else parts[2]
                    })
    except Exception as e:
        processes.append({"error": f"Failed to list processes: {e}"})
        
    return processes


def run_system_info_forensics() -> Dict[str, Any]:
    """
    Aggregates all host information, registry persistence, USB history, and live processes.
    """
    info = {
        "os_info": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "node": platform.node(),
            "processor": platform.processor(),
            "python_version": sys.version
        },
        "persistence_keys": query_registry_run_keys(),
        "usb_history": query_usb_history(),
        "network_connections": get_active_connections(),
        "running_processes": get_running_processes()
    }
    return info
