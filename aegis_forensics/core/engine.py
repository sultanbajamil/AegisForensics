import os
from typing import Dict, Any, List
from aegis_forensics.plugins.browser_forensics import run_browser_forensics
from aegis_forensics.plugins.event_logs import run_event_log_forensics
from aegis_forensics.plugins.file_recovery import scan_recycle_bin
from aegis_forensics.plugins.system_info import run_system_info_forensics
from aegis_forensics.core.memory import carve_memory_generator


class ForensicEngine:
    """
    Main forensic engine that coordinates live/offline collections and memory analysis.
    """
    def __init__(self, system_root: str = ""):
        # system_root can be empty (live system) or a path to a directory/drive (offline analysis)
        self.system_root = system_root
        
    def run_live_or_offline_analysis(
        self, 
        collect_system: bool = True,
        collect_browsers: bool = True,
        collect_logs: bool = True,
        collect_recovery: bool = True,
        max_log_records: int = 5000
    ) -> Dict[str, Any]:
        """
        Runs standard live or offline filesystem analysis.
        """
        results = {
            "target": "Live Host" if not self.system_root else f"Offline Directory ({self.system_root})",
            "system_info": {},
            "browser_data": {},
            "event_logs": {},
            "recovered_files": [],
            "errors": []
        }
        
        # 1. System Info
        if collect_system:
            try:
                # Note: Registry/Process commands run on the host. If system_root is set,
                # we read static system properties.
                results["system_info"] = run_system_info_forensics()
            except Exception as e:
                results["errors"].append(f"System Info module failed: {e}")
                
        # 2. Browser Forensics
        if collect_browsers:
            try:
                results["browser_data"] = run_browser_forensics(self.system_root)
            except Exception as e:
                results["errors"].append(f"Browser Forensics module failed: {e}")
                
        # 3. Windows Event Logs
        if collect_logs:
            try:
                results["event_logs"] = run_event_log_forensics(self.system_root, max_log_records)
            except Exception as e:
                results["errors"].append(f"Event Log module failed: {e}")
                
        # 4. File Recovery (Recycle Bin)
        if collect_recovery:
            try:
                results["recovered_files"] = scan_recycle_bin(self.system_root)
            except Exception as e:
                results["errors"].append(f"Recycle Bin recovery module failed: {e}")
                
        return results

    def run_memory_carving(self, memory_dump_path: str) -> Dict[str, Any]:
        """
        Synchronous wrapper for memory carving.
        Useful for CLI execution.
        """
        carver = carve_memory_generator(memory_dump_path)
        final_results = {}
        
        for update in carver:
            if update["status"] == "complete":
                final_results = update["results"]
            elif update["status"] == "error":
                return {"error": update["message"]}
                
        return final_results
