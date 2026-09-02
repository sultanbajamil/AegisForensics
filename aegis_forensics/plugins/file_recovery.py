import os
import struct
import glob
from typing import List, Dict, Any
from datetime import datetime, timezone


def filetime_to_datetime(filetime: int) -> str:
    """
    Converts Windows FILETIME (100-nanosecond intervals since Jan 1, 1601)
    to a human-readable ISO timestamp in UTC.
    """
    if filetime <= 0:
        return "-"
    try:
        # Offset between 1601-01-01 and 1970-01-01 is 11644473600 seconds
        unix_ts = (filetime - 116444736000000000) / 10000000
        if unix_ts < 0:
            return "-"
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "-"


def parse_dollar_i_file(file_path: str) -> Dict[str, Any]:
    """
    Parses a Windows Recycle Bin metadata file ($I file).
    Supports both Version 1 (Win Vista/7) and Version 2 (Win 10/11) formats.
    """
    metadata = {
        "metadata_file": os.path.basename(file_path),
        "full_path": file_path,
        "original_name": "",
        "original_path": "",
        "file_size": 0,
        "deletion_time": "",
        "version": 0,
        "r_file_exists": False,
        "r_file_path": ""
    }
    
    try:
        with open(file_path, "rb") as f:
            header_data = f.read(28)
            if len(header_data) < 24:
                return metadata
                
            # Read first 8 bytes (version header)
            version = struct.unpack("<Q", header_data[0:8])[0]
            metadata["version"] = version
            
            # Read original file size (bytes 8-15) and deletion filetime (bytes 16-23)
            file_size = struct.unpack("<Q", header_data[8:16])[0]
            deletion_filetime = struct.unpack("<Q", header_data[16:24])[0]
            
            metadata["file_size"] = file_size
            metadata["deletion_time"] = filetime_to_datetime(deletion_filetime)
            
            # Read filepath based on version
            if version == 1:
                # Version 1: 520 bytes (UTF-16LE filepath) at offset 24
                filepath_bytes = f.read(520)
                filepath = filepath_bytes.decode("utf-16-le", errors="ignore").split("\x00")[0]
            elif version == 2:
                # Version 2: filepath length is a 32-bit int at offset 24-27
                if len(header_data) >= 28:
                    filepath_len = struct.unpack("<I", header_data[24:28])[0]
                    # Original path is at offset 28 and is length * 2 bytes (UTF-16LE)
                    filepath_bytes = f.read(filepath_len * 2)
                    filepath = filepath_bytes.decode("utf-16-le", errors="ignore").split("\x00")[0]
                else:
                    filepath = ""
            else:
                # Unknown version, try to scan remainder as string
                remainder = f.read()
                filepath = remainder.decode("utf-16-le", errors="ignore").split("\x00")[0]
                
            metadata["original_path"] = filepath
            metadata["original_name"] = os.path.basename(filepath)
            
            # Check corresponding $R file (actual file contents)
            dir_name = os.path.dirname(file_path)
            base_name = os.path.basename(file_path)
            # $Ixxxxxx has corresponding $Rxxxxxx
            r_filename = "S" + base_name[1:] if base_name.startswith("$I") else "R" + base_name[1:]
            if base_name.startswith("$I"):
                r_filename = "$R" + base_name[2:]
            elif base_name.startswith("I"):
                r_filename = "R" + base_name[1:]
                
            r_filepath = os.path.join(dir_name, r_filename)
            if os.path.exists(r_filepath):
                metadata["r_file_exists"] = True
                metadata["r_file_path"] = r_filepath
                
    except Exception as e:
        metadata["error"] = str(e)
        
    return metadata


def scan_recycle_bin(system_root: str = "") -> List[Dict[str, Any]]:
    """
    Scans the Windows Recycle Bin ($Recycle.Bin) on the target drive
    and parses all deleted file metadata.
    """
    recovered_files = []
    
    # Identify Recycle Bin folder
    if system_root:
        recycle_dir = os.path.join(system_root, "$Recycle.Bin")
    else:
        # Check standard C drive on host
        recycle_dir = "C:\\$Recycle.Bin"
        
    if not os.path.exists(recycle_dir):
        # On some non-system drives or modified systems, check D:\$Recycle.Bin, etc.
        for letter in ["C", "D", "E", "F"]:
            alt_dir = f"{letter}:\\$Recycle.Bin"
            if os.path.exists(alt_dir):
                recycle_dir = alt_dir
                break
                
    if not os.path.exists(recycle_dir):
        return recovered_files
        
    # Walk all folders inside $Recycle.Bin (these are named after user SIDs)
    # Target files starting with $I
    search_pattern = os.path.join(recycle_dir, "**", "$I*")
    metadata_files = glob.glob(search_pattern, recursive=True)
    
    for meta_file in metadata_files:
        meta_data = parse_dollar_i_file(meta_file)
        if meta_data.get("original_name"):
            recovered_files.append(meta_data)
            
    # Sort by deletion time (latest first)
    recovered_files.sort(key=lambda x: x.get("deletion_time", ""), reverse=True)
    return recovered_files


def recover_file(r_file_path: str, destination_dir: str, original_filename: str) -> str:
    """
    Recovers the deleted file by copying the $R file to a target folder
    with its original filename.
    """
    if not os.path.exists(r_file_path):
        return "Source $R file does not exist."
        
    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir, exist_ok=True)
        
    dest_path = os.path.join(destination_dir, original_filename)
    try:
        shutil.copy2(r_file_path, dest_path)
        return dest_path
    except Exception as e:
        return f"Failed to recover file: {e}"
