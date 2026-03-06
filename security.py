"""
security.py — File security checks before processing
1. Malicious script/content detection
2. VirusTotal hash check
3. SIEM-compatible audit log export
"""
import os
import re
import hashlib
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ── MALICIOUS CONTENT PATTERNS ───────────────────────────────────

MALICIOUS_PATTERNS = {
    "sql_injection": [
        r"(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)",
        r"(DELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1)",
        r"(INSERT\s+INTO.*SELECT\s+\*)",
        r"(UNION\s+SELECT.*FROM)",
        r"(xp_cmdshell|exec\s*\(|execute\s*\()",
        r"(;\s*DROP|;\s*DELETE|;\s*TRUNCATE|;\s*ALTER)",
    ],
    "xss": [
        r"<script[^>]*>.*?</script>",
        r"javascript\s*:",
        r"on(load|click|mouseover|error|focus)\s*=",
        r"<iframe[^>]*>",
        r"document\.cookie",
        r"window\.location",
    ],
    "shell_commands": [
        r"(rm\s+-rf|rmdir\s+/s)",
        r"(wget|curl)\s+https?://",
        r"(bash|sh|cmd|powershell)\s+-c",
        r"(__import__\s*\(\s*['\"]os['\"]|subprocess\.call|os\.system)",
        r"(eval\s*\(|exec\s*\()",
        r"/etc/passwd|/etc/shadow",
    ],
    "path_traversal": [
        r"\.\./\.\./",
        r"%2e%2e%2f",
        r"\.\.\\",
    ],
}


def calculate_hashes(file_bytes: bytes) -> dict:
    """Calculate MD5, SHA1, SHA256 hashes of file."""
    return {
        "md5":    hashlib.md5(file_bytes).hexdigest(),
        "sha1":   hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }


def scan_for_malicious_content(file_bytes: bytes, filename: str) -> dict:
    """
    Scan file content for malicious patterns.
    Returns {safe: bool, threats: list, details: dict}
    """
    threats = []
    details = {}

    # Only scan text-based files
    ext = filename.rsplit(".", 1)[-1].lower()
    if ext in ("png", "jpg", "jpeg"):
        return {"safe": True, "threats": [], "details": {}}

    try:
        text = file_bytes.decode("utf-8", errors="replace")
    except Exception:
        return {"safe": True, "threats": [], "details": {}}

    for threat_type, patterns in MALICIOUS_PATTERNS.items():
        matches = []
        for pattern in patterns:
            found = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
            if found:
                matches.extend(found[:3])  # max 3 examples per pattern

        if matches:
            threats.append(threat_type)
            details[threat_type] = matches

    return {
        "safe": len(threats) == 0,
        "threats": threats,
        "details": details,
    }


def check_virustotal(file_bytes: bytes, hashes: dict) -> dict:
    """
    Check file hash against VirusTotal API.
    Returns {checked: bool, malicious: bool, stats: dict, link: str}
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            "checked": False,
            "reason": "No VirusTotal API key configured",
            "malicious": False,
            "stats": {},
            "link": ""
        }

    sha256 = hashes["sha256"]
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        # First check if hash already known to VT
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0) > 0
            return {
                "checked": True,
                "malicious": malicious,
                "stats": stats,
                "link": f"https://www.virustotal.com/gui/file/{sha256}",
                "source": "hash_lookup"
            }
        elif response.status_code == 404:
            # Hash not found — upload file for scanning
            files = {"file": file_bytes}
            upload_url = "https://www.virustotal.com/api/v3/files"
            upload_resp = requests.post(upload_url, headers=headers, files=files, timeout=30)

            if upload_resp.status_code == 200:
                analysis_id = upload_resp.json()["data"]["id"]
                return {
                    "checked": True,
                    "malicious": False,
                    "stats": {"status": "submitted"},
                    "link": f"https://www.virustotal.com/gui/file/{sha256}",
                    "source": "uploaded",
                    "analysis_id": analysis_id
                }
        return {
            "checked": False,
            "reason": f"VirusTotal returned status {response.status_code}",
            "malicious": False,
            "stats": {},
            "link": ""
        }

    except Exception as e:
        return {
            "checked": False,
            "reason": str(e),
            "malicious": False,
            "stats": {},
            "link": ""
        }


def full_security_scan(file_bytes: bytes, filename: str) -> dict:
    """
    Run complete security scan on a file.
    Returns full security report.
    """
    hashes = calculate_hashes(file_bytes)
    malicious_scan = scan_for_malicious_content(file_bytes, filename)
    vt_result = check_virustotal(file_bytes, hashes)

    safe = malicious_scan["safe"] and not vt_result.get("malicious", False)

    return {
        "safe": safe,
        "filename": filename,
        "file_size": len(file_bytes),
        "hashes": hashes,
        "malicious_content": malicious_scan,
        "virustotal": vt_result,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
    }


# ── SIEM-COMPATIBLE AUDIT LOG EXPORT ─────────────────────────────

def format_siem_log(log_entry: dict) -> dict:
    """
    Format a log entry in SIEM-compatible format (CEF/JSON).
    Compatible with Splunk, ELK, IBM QRadar.
    """
    return {
        "@timestamp": str(log_entry.get("timestamp", datetime.utcnow().isoformat())),
        "event": {
            "kind": "event",
            "category": "file" if log_entry.get("file_id") else "authentication",
            "action": log_entry.get("action", "unknown"),
            "outcome": "success",
        },
        "user": {
            "name": log_entry.get("username", "unknown"),
        },
        "file": {
            "name": log_entry.get("original_filename", ""),
        },
        "source": {
            "ip": log_entry.get("ip_address", ""),
        },
        "metadata": log_entry.get("details", {}),
        "host": {
            "name": "pii-sanitizer",
        },
        "tags": ["pii-sanitizer", "hackamined-2025"],
    }


def export_siem_logs(logs: list) -> str:
    """Export logs as SIEM-compatible NDJSON (one JSON per line)."""
    lines = []
    for log in logs:
        siem_log = format_siem_log(log)
        lines.append(json.dumps(siem_log))
    return "\n".join(lines)
