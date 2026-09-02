import os
import sys
import argparse
from aegis_forensics.core.engine import ForensicEngine
from aegis_forensics.utils.reporter import generate_html_report, generate_json_report


def main():
    parser = argparse.ArgumentParser(
        description="AegisForensics: Digital Forensics & Incident Response (DFIR) Tool"
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--live", action="store_true", help="Analyze the live host system (requires Administrator privileges)")
    group.add_argument("--offline", type=str, help="Analyze an offline directory or mounted partition root")
    group.add_argument("--memory", type=str, help="Carve patterns from a memory dump file (.raw/.dmp)")
    
    parser.add_argument("--html", type=str, default="forensic_report.html", help="Path to save the HTML report")
    parser.add_argument("--json", type=str, help="Path to save the JSON raw results (optional)")
    parser.add_argument("--max-logs", type=int, default=5000, help="Maximum event logs to parse per file (default: 5000)")
    
    args = parser.parse_args()
    
    # 1. Memory Analysis Mode
    if args.memory:
        print(f"[*] Starting memory carving on: {args.memory}")
        if not os.path.exists(args.memory):
            print(f"[!] Error: File '{args.memory}' does not exist.")
            sys.exit(1)
            
        engine = ForensicEngine()
        try:
            from aegis_forensics.core.memory import carve_memory_generator
            carver = carve_memory_generator(args.memory)
            results = {}
            for update in carver:
                if update["status"] == "start":
                    print(f"[*] Size: {update['file_size'] / (1024*1024):.2f} MB")
                elif update["status"] == "progress":
                    sys.stdout.write(f"\r[*] Progress: {update['progress']:.1f}% (IPs: {update['counts']['ips']}, Emails: {update['counts']['emails']}, URLs: {update['counts']['urls']})")
                    sys.stdout.flush()
                elif update["status"] == "complete":
                    results = update["results"]
                    print("\n[*] Carving completed successfully!")
                elif update["status"] == "error":
                    print(f"\n[!] Error during carving: {update['message']}")
                    sys.exit(1)
                    
            print(f"[*] Found {len(results.get('ips', []))} IP addresses.")
            print(f"[*] Found {len(results.get('emails', []))} email addresses.")
            print(f"[*] Found {len(results.get('urls', []))} URLs.")
            print(f"[*] Found {len(results.get('aws_keys', []))} AWS Access Keys.")
            print(f"[*] Found {len(results.get('private_keys', []))} private key headers.")
            
            if args.json:
                with open(args.json, "w", encoding="utf-8") as f:
                    import json
                    json.dump(results, f, indent=4)
                print(f"[*] Raw JSON results saved to: {args.json}")
                
        except Exception as e:
            print(f"[!] Memory analysis failed: {e}")
            sys.exit(1)
            
    # 2. Live or Offline Filesystem Analysis Mode
    else:
        target_path = "" if args.live else args.offline
        if not args.live and not os.path.exists(target_path):
            print(f"[!] Error: Target directory '{target_path}' does not exist.")
            sys.exit(1)
            
        if args.live:
            print("[*] Performing analysis on the Live Host...")
        else:
            print(f"[*] Performing analysis on offline system root: {target_path}")
            
        engine = ForensicEngine(system_root=target_path)
        
        print("[*] Collecting artifacts (Browser, Event Logs, Recycle Bin, System Info)...")
        results = engine.run_live_or_offline_analysis(max_log_records=args.max_logs)
        
        # Log any non-fatal errors
        if results.get("errors"):
            print("[!] Warnings encountered during collection:")
            for err in results["errors"]:
                print(f"  - {err}")
                
        # Generate HTML report
        if args.html:
            try:
                generate_html_report(results, args.html)
                print(f"[+] Beautiful HTML report generated: {os.path.abspath(args.html)}")
            except Exception as e:
                print(f"[!] Failed to generate HTML report: {e}")
                
        # Generate JSON report if requested
        if args.json:
            try:
                generate_json_report(results, args.json)
                print(f"[+] Raw JSON results saved: {os.path.abspath(args.json)}")
            except Exception as e:
                print(f"[!] Failed to generate JSON report: {e}")
                
        print("[*] Forensic analysis complete.")


if __name__ == "__main__":
    main()
