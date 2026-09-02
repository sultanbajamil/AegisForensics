import os
import re
from typing import Dict, List, Set, Generator, Any

# Pre-compiled regular expressions for high-performance scanning
IPV4_REGEX = re.compile(br'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
EMAIL_REGEX = re.compile(br'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b')
URL_REGEX = re.compile(br'https?://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+')
AWS_KEY_REGEX = re.compile(br'\bAKIA[A-Z0-9]{16}\b')
PRIVATE_KEY_REGEX = re.compile(br'-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----')


def validate_ip(ip_bytes: bytes) -> bool:
    """Validates that a regex IP match has all octets <= 255 and is not trivial."""
    try:
        parts = [int(p) for p in ip_bytes.split(b'.')]
        if len(parts) != 4:
            return False
        # Ignore common internal loops and local broadcasts if desired, or keep all
        if parts[0] == 0 or parts[0] > 255:
            return False
        return all(0 <= p <= 255 for p in parts)
    except ValueError:
        return False


def carve_memory_generator(
    file_path: str, 
    chunk_size: int = 4 * 1024 * 1024,  # 4 MB chunks
    overlap_size: int = 64 * 1024       # 64 KB overlap
) -> Generator[Dict[str, Any], None, None]:
    """
    Generator that parses a memory dump file in chunks and yields findings and progress.
    Avoids loading the whole file into RAM.
    """
    if not os.path.exists(file_path):
        yield {"status": "error", "message": f"Memory dump file not found: {file_path}"}
        return

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        yield {"status": "error", "message": "Memory dump file is empty."}
        return

    # Deduplication sets
    ips: Set[str] = set()
    emails: Set[str] = set()
    urls: Set[str] = set()
    aws_keys: Set[str] = set()
    private_keys: Set[str] = set()

    yield {
        "status": "start",
        "file_size": file_size,
        "message": f"Scanning {file_size / (1024*1024):.2f} MB memory dump..."
    }

    bytes_read = 0
    with open(file_path, "rb") as f:
        while True:
            # Determine read size
            current_pos = f.tell()
            chunk = f.read(chunk_size)
            if not chunk:
                break

            chunk_len = len(chunk)
            bytes_read += chunk_len

            # Run regex scans (chunk is binary bytes)
            # 1. IP Addresses
            for ip in IPV4_REGEX.findall(chunk):
                if validate_ip(ip):
                    ips.add(ip.decode("ascii", errors="ignore"))

            # 2. Emails
            for email in EMAIL_REGEX.findall(chunk):
                emails.add(email.decode("ascii", errors="ignore").lower())

            # 3. URLs
            for url in URL_REGEX.findall(chunk):
                # Clean up trailing punctuation often caught in regexes
                clean_url = url.decode("ascii", errors="ignore").rstrip('.,;()[]{}!<>\"\'')
                urls.add(clean_url)

            # 4. AWS Keys
            for key in AWS_KEY_REGEX.findall(chunk):
                aws_keys.add(key.decode("ascii", errors="ignore"))

            # 5. Private Keys
            for pk in PRIVATE_KEY_REGEX.findall(chunk):
                private_keys.add(pk.decode("ascii", errors="ignore"))

            # Handle chunk overlap so we don't miss patterns split across boundaries
            if chunk_len == chunk_size:
                # Seek back overlap size
                f.seek(current_pos + chunk_size - overlap_size)

            # Yield progress update periodically (e.g. every chunk)
            progress = (bytes_read / file_size) * 100
            yield {
                "status": "progress",
                "progress": min(progress, 100.0),
                "counts": {
                    "ips": len(ips),
                    "emails": len(emails),
                    "urls": len(urls),
                    "aws_keys": len(aws_keys),
                    "private_keys": len(private_keys)
                }
            }

    # Yield final results
    yield {
        "status": "complete",
        "results": {
            "ips": sorted(list(ips)),
            "emails": sorted(list(emails)),
            "urls": sorted(list(urls))[:1000],  # Caps URLs to prevent massive arrays
            "aws_keys": sorted(list(aws_keys)),
            "private_keys": sorted(list(private_keys))
        }
    }
