import os
import re
import glob
from typing import List, Dict, Any
import xml.etree.ElementTree as ET

# Try importing Evtx, fallback if not installed yet (will install in dependencies stage)
try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None


def get_event_log_dir(system_root: str = "") -> str:
    """
    Returns the path to the Windows Event Logs directory.
    """
    if system_root:
        log_dir = os.path.join(system_root, "Windows", "System32", "Winevt", "Logs")
    else:
        system32 = os.environ.get("SystemRoot", "C:\\Windows")
        log_dir = os.path.join(system32, "System32", "Winevt", "Logs")
        
    return log_dir if os.path.exists(log_dir) else ""


def parse_xml_record(xml_str: str) -> Dict[str, Any]:
    """
    Parses event record XML and extracts standard and security metadata.
    Handles XML namespaces automatically.
    """
    # Remove XML namespaces to simplify XPath queries
    xml_str = re.sub(r' xmlns="[^"]+"', '', xml_str)
    xml_str = re.sub(r' xmlns:[^=]+="[^"]+"', '', xml_str)
    
    event_data = {
        "event_id": 0,
        "timestamp": "",
        "computer": "",
        "provider": "",
        "channel": "",
        "details": {}
    }
    
    try:
        root = ET.fromstring(xml_str)
        
        # Parse System section
        system = root.find("System")
        if system is not None:
            event_id_elem = system.find("EventID")
            if event_id_elem is not None:
                event_data["event_id"] = int(event_id_elem.text or 0)
                
            provider_elem = system.find("Provider")
            if provider_elem is not None:
                event_data["provider"] = provider_elem.attrib.get("Name", "")
                
            channel_elem = system.find("Channel")
            if channel_elem is not None:
                event_data["channel"] = channel_elem.text or ""
                
            computer_elem = system.find("Computer")
            if computer_elem is not None:
                event_data["computer"] = computer_elem.text or ""
                
            time_created = system.find("TimeCreated")
            if time_created is not None:
                event_data["timestamp"] = time_created.attrib.get("SystemTime", "")
                
        # Parse EventData section (details vary by event ID)
        event_data_node = root.find("EventData")
        if event_data_node is not None:
            for data in event_data_node.findall("Data"):
                name = data.attrib.get("Name")
                if name:
                    event_data["details"][name] = data.text
                    
        # Parse UserData section (alternative structure used in some events)
        user_data_node = root.find("UserData")
        if user_data_node is not None:
            for child in user_data_node.iter():
                if child.text and child.text.strip():
                    tag_name = child.tag.split('}')[-1]  # Strip any leftover namespace
                    event_data["details"][tag_name] = child.text.strip()
                    
    except Exception as e:
        event_data["details"]["parse_error"] = str(e)
        
    return event_data


def run_event_log_forensics(system_root: str = "", max_records_per_file: int = 5000) -> Dict[str, Any]:
    """
    Scans Windows Event Logs and extracts key security, audit, and audit-cleared events.
    """
    forensic_data = {
        "logon_events": [],       # ID 4624, 4625
        "cleared_logs": [],       # ID 1102, 104
        "process_creations": [],   # ID 4688, 1 (Sysmon)
        "services_installed": [], # ID 7045
        "errors": []
    }
    
    if evtx is None:
        forensic_data["errors"].append("python-evtx library is not installed.")
        return forensic_data
        
    log_dir = get_event_log_dir(system_root)
    if not log_dir:
        forensic_data["errors"].append(f"Event Log directory not found relative to: '{system_root}'")
        return forensic_data
        
    # We will specifically target Security, System, and Sysmon operational logs
    target_logs = {
        "Security.evtx": ["Security"],
        "System.evtx": ["System"],
        "Microsoft-Windows-Sysmon%4Operational.evtx": ["Sysmon"]
    }
    
    for log_filename, labels in target_logs.items():
        log_path = os.path.join(log_dir, log_filename)
        if not os.path.exists(log_path):
            continue
            
        try:
            with evtx.Evtx(log_path) as log:
                count = 0
                for record in log.records():
                    if count >= max_records_per_file:
                        break
                        
                    xml_str = record.xml()
                    data = parse_xml_record(xml_str)
                    event_id = data["event_id"]
                    
                    # 1. Audit Logs Cleared (Anti-Forensics)
                    # ID 1102 (Security audit log was cleared)
                    # ID 104 (System log was cleared)
                    if event_id in [1102, 104]:
                        forensic_data["cleared_logs"].append({
                            "timestamp": data["timestamp"],
                            "event_id": event_id,
                            "computer": data["computer"],
                            "provider": data["provider"],
                            "user": data["details"].get("SubjectUserName", "Unknown"),
                            "domain": data["details"].get("SubjectUserDomain", "")
                        })
                        count += 1
                        
                    # 2. Logon Events (Authentication Analysis)
                    # ID 4624 (Successful Logon)
                    # ID 4625 (Failed Logon)
                    elif event_id in [4624, 4625]:
                        details = data["details"]
                        logon_type = details.get("LogonType", "Unknown")
                        ip_address = details.get("IpAddress", "-")
                        username = details.get("TargetUserName", "Unknown")
                        domain = details.get("TargetUserDomain", "")
                        
                        # Filter out system service logins (e.g. SYSTEM, LOCAL SERVICE) to focus on actual user logins
                        # Ignore computer accounts ending with $
                        if username and not username.endswith("$") and username not in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]:
                            forensic_data["logon_events"].append({
                                "timestamp": data["timestamp"],
                                "event_id": event_id,
                                "status": "Success" if event_id == 4624 else "Failure",
                                "username": f"{domain}\\{username}" if domain else username,
                                "logon_type": logon_type,
                                "ip_address": ip_address,
                                "computer": data["computer"]
                            })
                            count += 1
                            
                    # 3. Process Execution Analysis
                    # ID 4688 (New Process Created)
                    # ID 1 (Sysmon Process Create)
                    elif event_id in [4688, 1]:
                        details = data["details"]
                        if event_id == 4688:
                            proc_name = details.get("NewProcessName", "")
                            cmd_line = details.get("CommandLine", "-")
                            parent_proc = details.get("ParentProcessName", "-")
                            user = details.get("SubjectUserName", "")
                        else:  # Sysmon ID 1
                            proc_name = details.get("Image", "")
                            cmd_line = details.get("CommandLine", "-")
                            parent_proc = details.get("ParentImage", "-")
                            user = details.get("User", "")
                            
                        # Format process path for readability
                        if proc_name:
                            forensic_data["process_creations"].append({
                                "timestamp": data["timestamp"],
                                "event_id": event_id,
                                "process_name": os.path.basename(proc_name),
                                "command_line": cmd_line,
                                "parent_process": os.path.basename(parent_proc) if parent_proc != "-" else "-",
                                "user": user,
                                "computer": data["computer"]
                            })
                            count += 1
                            
                    # 4. Service Installations (Persistence)
                    # ID 7045 (A service was installed in the system)
                    elif event_id == 7045:
                        details = data["details"]
                        forensic_data["services_installed"].append({
                            "timestamp": data["timestamp"],
                            "event_id": event_id,
                            "service_name": details.get("ServiceName", "Unknown"),
                            "image_path": details.get("ImagePath", "Unknown"),
                            "service_type": details.get("ServiceType", "-"),
                            "start_type": details.get("StartType", "-"),
                            "computer": data["computer"]
                        })
                        count += 1
                        
        except Exception as e:
            forensic_data["errors"].append(f"Failed to read {log_filename}: {e}")
            
    return forensic_data
