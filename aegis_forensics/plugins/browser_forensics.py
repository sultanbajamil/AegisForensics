import os
import shutil
import sqlite3
import tempfile
import glob
from typing import List, Dict, Any
from aegis_forensics.utils.decryptor import get_chromium_master_key, decrypt_chromium_string


def get_default_paths(system_root: str = "") -> List[Dict[str, str]]:
    """
    Returns lists of potential browser profile paths.
    If system_root is provided (e.g. for offline analysis), it searches relative to that partition root.
    """
    browsers = []
    
    # Resolve User folders
    if system_root:
        users_dir = os.path.join(system_root, "Users")
    else:
        # Live system
        user_profile = os.environ.get("USERPROFILE", "C:\\Users")
        users_dir = os.path.dirname(user_profile)
        
    if not os.path.exists(users_dir):
        return browsers
        
    for username in os.listdir(users_dir):
        user_path = os.path.join(users_dir, username)
        if not os.path.isdir(user_path):
            continue
            
        # Chromium LocalAppData paths
        local_app_data = os.path.join(user_path, "AppData", "Local")
        # Firefox RoamingAppData path
        roaming_app_data = os.path.join(user_path, "AppData", "Roaming")
        
        # Chrome
        chrome_path = os.path.join(local_app_data, "Google", "Chrome", "User Data")
        if os.path.exists(chrome_path):
            browsers.append({
                "name": f"Chrome ({username})",
                "type": "chromium",
                "base_path": chrome_path,
                "local_state": os.path.join(chrome_path, "Local State")
            })
            
        # Edge
        edge_path = os.path.join(local_app_data, "Microsoft", "Edge", "User Data")
        if os.path.exists(edge_path):
            browsers.append({
                "name": f"Edge ({username})",
                "type": "chromium",
                "base_path": edge_path,
                "local_state": os.path.join(edge_path, "Local State")
            })
            
        # Firefox
        ff_path = os.path.join(roaming_app_data, "Mozilla", "Firefox", "Profiles")
        if os.path.exists(ff_path):
            browsers.append({
                "name": f"Firefox ({username})",
                "type": "firefox",
                "base_path": ff_path
            })
            
    return browsers


def parse_chromium_history(history_db_path: str) -> List[Dict[str, Any]]:
    """
    Parses Chromium history SQLite database.
    """
    results = []
    temp_db = tempfile.mktemp(suffix=".db")
    try:
        shutil.copy2(history_db_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Chromium stores history timestamps in microseconds since 1601-01-01 (WebKit epoch)
        query = """
        SELECT url, title, visit_count, typed_count, 
               datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') AS last_visit
        FROM urls 
        ORDER BY last_visit_time DESC
        LIMIT 5000
        """
        cursor.execute(query)
        for row in cursor.fetchall():
            results.append({
                "url": row[0],
                "title": row[1] or "[No Title]",
                "visit_count": row[2],
                "typed_count": row[3],
                "last_visit": row[4]
            })
        conn.close()
    except Exception as e:
        results.append({"error": f"Failed to parse history: {e}"})
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)
            
    return results


def parse_chromium_passwords(login_db_path: str, master_key: bytes) -> List[Dict[str, Any]]:
    """
    Parses and decrypts Chromium logins database.
    """
    results = []
    temp_db = tempfile.mktemp(suffix=".db")
    try:
        shutil.copy2(login_db_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        query = "SELECT origin_url, action_url, username_value, password_value FROM logins"
        cursor.execute(query)
        for row in cursor.fetchall():
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            encrypted_password = row[3]
            
            decrypted_password = "[Decryption Failed]"
            if encrypted_password:
                try:
                    decrypted_password = decrypt_chromium_string(encrypted_password, master_key)
                except Exception as e:
                    decrypted_password = f"[Error: {e}]"
                    
            if username or decrypted_password:
                results.append({
                    "origin_url": origin_url,
                    "action_url": action_url,
                    "username": username,
                    "password": decrypted_password
                })
        conn.close()
    except Exception as e:
        results.append({"error": f"Failed to parse passwords: {e}"})
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)
            
    return results


def parse_firefox_history(profiles_path: str) -> List[Dict[str, Any]]:
    """
    Parses Firefox history (places.sqlite) for all profiles.
    """
    results = []
    # Find places.sqlite across profiles
    places_files = glob.glob(os.path.join(profiles_path, "*", "places.sqlite"))
    
    for db_path in places_files:
        profile_name = os.path.basename(os.path.dirname(db_path))
        temp_db = tempfile.mktemp(suffix=".sqlite")
        try:
            shutil.copy2(db_path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Firefox stores timestamps in microseconds since 1970-01-01
            query = """
            SELECT p.url, p.title, p.visit_count, 
                   datetime(h.visit_date/1000000, 'unixepoch') AS last_visit
            FROM moz_places p
            JOIN moz_historyvisits h ON p.id = h.place_id
            ORDER BY h.visit_date DESC
            LIMIT 2000
            """
            cursor.execute(query)
            for row in cursor.fetchall():
                results.append({
                    "profile": profile_name,
                    "url": row[0],
                    "title": row[1] or "[No Title]",
                    "visit_count": row[2],
                    "last_visit": row[3]
                })
            conn.close()
        except Exception as e:
            results.append({"profile": profile_name, "error": f"Failed to parse places.sqlite: {e}"})
        finally:
            if os.path.exists(temp_db):
                os.remove(temp_db)
                
    return results


def run_browser_forensics(system_root: str = "") -> Dict[str, Any]:
    """
    Main runner for browser forensics.
    Collects browser artifacts from all detected profiles.
    """
    browsers = get_default_paths(system_root)
    forensic_data = {
        "history": [],
        "passwords": [],
        "errors": []
    }
    
    for browser in browsers:
        name = browser["name"]
        b_type = browser["type"]
        
        if b_type == "chromium":
            base_path = browser["base_path"]
            local_state = browser["local_state"]
            
            # Resolve Master Key
            master_key = None
            try:
                master_key = get_chromium_master_key(local_state)
            except Exception as e:
                forensic_data["errors"].append(f"Could not load master key for {name}: {e}")
                
            # Scan profiles (Default, Profile 1, Profile 2, etc.)
            # Profiles can either be Default or Profile *
            profiles = glob.glob(os.path.join(base_path, "Default")) + glob.glob(os.path.join(base_path, "Profile *"))
            
            for profile in profiles:
                p_name = os.path.basename(profile)
                
                # Extract history
                history_path = os.path.join(profile, "History")
                if os.path.exists(history_path):
                    hist_entries = parse_chromium_history(history_path)
                    for entry in hist_entries:
                        entry["browser"] = f"{name} ({p_name})"
                        forensic_data["history"].append(entry)
                        
                # Extract passwords
                login_path = os.path.join(profile, "Login Data")
                if os.path.exists(login_path):
                    if master_key:
                        pwd_entries = parse_chromium_passwords(login_path, master_key)
                        for entry in pwd_entries:
                            entry["browser"] = f"{name} ({p_name})"
                            forensic_data["passwords"].append(entry)
                    else:
                        forensic_data["errors"].append(f"Skipped passwords for {name} ({p_name}) - Master key missing")
                        
        elif b_type == "firefox":
            base_path = browser["base_path"]
            ff_history = parse_firefox_history(base_path)
            for entry in ff_history:
                entry["browser"] = f"Firefox ({entry.pop('profile', 'default')})"
                forensic_data["history"].append(entry)
                
    return forensic_data
