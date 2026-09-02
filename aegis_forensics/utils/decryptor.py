import os
import json
import base64
import sys

# Platform-specific imports for Windows DPAPI decryption
IS_WINDOWS = sys.platform == "win32"
if IS_WINDOWS:
    try:
        import win32crypt
    except ImportError:
        win32crypt = None
else:
    win32crypt = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None


def decrypt_dpapi(data: bytes) -> bytes:
    """
    Decrypts data using Windows Data Protection API (DPAPI).
    Only works on Windows and requires the pywin32 library.
    """
    if not IS_WINDOWS:
        raise OSError("DPAPI decryption is only supported on Windows systems.")
    
    if win32crypt is None:
        raise ImportError("pywin32 (win32crypt) is not installed or failed to import.")
    
    try:
        # CryptUnprotectData args: (encrypted_bytes, optional_entropy, reserved, prompt_struct, flags)
        # Returns (description, decrypted_bytes)
        _, decrypted_data = win32crypt.CryptUnprotectData(data, None, None, None, 0)
        return decrypted_data
    except Exception as e:
        raise ValueError(f"DPAPI decryption failed: {e}")


def get_chromium_master_key(local_state_path: str) -> bytes:
    """
    Reads the Local State file of a Chromium-based browser, extracts
    the encrypted master key, and decrypts it using DPAPI.
    """
    if not os.path.exists(local_state_path):
        raise FileNotFoundError(f"Chromium local state file not found: {local_state_path}")
        
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
            
        encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
        encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
        
        # Remove 'DPAPI' prefix (first 5 bytes)
        if encrypted_key_bytes.startswith(b"DPAPI"):
            encrypted_key_bytes = encrypted_key_bytes[5:]
        else:
            raise ValueError("Encrypted key does not begin with DPAPI prefix")
            
        # Decrypt using DPAPI
        master_key = decrypt_dpapi(encrypted_key_bytes)
        return master_key
    except Exception as e:
        raise RuntimeError(f"Failed to retrieve Chromium master key: {e}")


def decrypt_chromium_string(ciphertext: bytes, master_key: bytes) -> str:
    """
    Decrypts a password or cookie string from a Chromium database.
    Supports older version DPAPI-only strings and modern AES-256-GCM encrypted strings (v10/v11).
    """
    if not ciphertext:
        return ""
        
    # Check for AES-GCM prefix (v10 / v11)
    if ciphertext.startswith(b"v10") or ciphertext.startswith(b"v11"):
        if AESGCM is None:
            raise ImportError("cryptography library is required to decrypt AES-GCM strings.")
            
        if not master_key:
            raise ValueError("Master key is required to decrypt v10/v11 strings.")
            
        try:
            # Struct: v10 (3 bytes) + IV (12 bytes) + Encrypted Payload + Tag
            iv = ciphertext[3:15]
            payload = ciphertext[15:]
            
            aesgcm = AESGCM(master_key)
            decrypted = aesgcm.decrypt(iv, payload, None)
            return decrypted.decode("utf-8", errors="replace")
        except Exception as e:
            return f"[Decryption Error (AES-GCM): {e}]"
    else:
        # Fallback to direct DPAPI decryption (older Chromium versions or simple strings)
        if IS_WINDOWS:
            try:
                decrypted = decrypt_dpapi(ciphertext)
                return decrypted.decode("utf-8", errors="replace")
            except Exception as e:
                return f"[Decryption Error (DPAPI): {e}]"
        else:
            return "[Decryption Error: Direct DPAPI decryption not supported on this OS]"
