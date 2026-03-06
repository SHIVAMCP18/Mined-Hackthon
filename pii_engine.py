"""
pii_engine.py — Two-layer PII detection: Regex + Gemini API
Layer 1: Regex catches structured Indian PII (Aadhaar, PAN, phone, etc.)
Layer 2: Gemini API catches contextual PII (names, addresses, anything missed)
"""
import re
import os
import json
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

# ── REGEX PATTERNS (Indian PII) ──────────────────────────────────

REGEX_PATTERNS = {
    "aadhaar": (
        r"\b\d{4}\s?\d{4}\s?\d{4}\b",
        lambda m: m[:4] + " XXXX XXXX"
    ),
    "pan": (
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        lambda m: m[:2] + "XXX" + m[5:]
    ),
    "phone": (
        r"(?:\+91[\s\-]?)?[6-9]\d{9}\b",
        lambda m: m[:3] + "XXXXXX" + m[-2:] if len(m) >= 10 else "[PHONE]"
    ),
    "email": (
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        lambda m: m[0] + "***@" + m.split("@")[1] if "@" in m else "[EMAIL]"
    ),
    "ip_address": (
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        lambda m: "X.X.X.X"
    ),
    "passport": (
        r"\b[A-Z][0-9]{7}\b",
        lambda m: m[0] + "XXXXXXX"
    ),
    "ifsc": (
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        lambda m: m[:4] + "0XXXXXX"
    ),
    "account_number": (
        r"\b\d{9,18}\b",
        lambda m: "X" * (len(m) - 4) + m[-4:]
    ),
    "upi": (
        r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b",
        lambda m: m[0] + "***@" + m.split("@")[1] if "@" in m else "[UPI]"
    ),
    "device_id": (
        r"\b(?:android|ios)-[a-f0-9]{8,}\b",
        lambda m: m.split("-")[0] + "-XXXXXXXX"
    ),
    "fingerprint": (
        r"\bfp_hash_[a-f0-9]+\b",
        lambda m: "fp_hash_XXXXXXXX"
    ),
    "face_template": (
        r"\bface_tmp_[a-f0-9]+\b",
        lambda m: "face_tmp_XXXXXXXX"
    ),
    "credit_card": (
        r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
        lambda m: "XXXX XXXX XXXX " + m.replace(" ", "").replace("-", "")[-4:]
    ),
}


def regex_scan(text: str) -> tuple:
    detections = []
    masked = text

    for pii_type, (pattern, masker) in REGEX_PATTERNS.items():
        for match in re.finditer(pattern, masked, re.IGNORECASE):
            original = match.group()
            try:
                masked_val = masker(original)
            except Exception:
                masked_val = "[REDACTED]"
            detections.append({
                "pii_type": pii_type,
                "original_value": original,
                "masked_value": masked_val,
                "detection_method": "regex",
                "confidence": 1.0,
            })

    for d in detections:
        masked = masked.replace(d["original_value"], d["masked_value"], 1)

    return masked, detections


def gemini_scan(text: str, already_masked_types: list = None) -> tuple:
    skip_hint = ""
    if already_masked_types:
        skip_hint = f"These types were already masked: {', '.join(already_masked_types)}. Focus on remaining PII."

    prompt = f"""You are a PII detection expert. Analyze the text below and find remaining Personally Identifiable Information.

{skip_hint}

Look for:
- Full names or partial names of real people
- Physical addresses (street, city, state, pincode)
- Any other identifying information not already masked

Return ONLY a valid JSON array (no markdown, no explanation) with objects:
- "pii_type": "name" | "address" | "other"
- "original_value": exact text as it appears
- "masked_value": "[NAME REDACTED]" or "[ADDRESS REDACTED]" or "[REDACTED]"
- "confidence": 0.0 to 1.0

If nothing found, return: []

TEXT:
{text[:4000]}"""

    try:
        response = model.generate_content(prompt)
        raw = response.text.strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        detections = json.loads(raw)

        if not isinstance(detections, list):
            return text, []

        masked = text
        for d in detections:
            d["detection_method"] = "gemini_api"
            if d.get("original_value") and d.get("masked_value"):
                masked = masked.replace(d["original_value"], d["masked_value"])

        return masked, detections

    except Exception as e:
        print(f"[Gemini API error] {e}")
        return text, []


def full_scan(text: str) -> tuple:
    after_regex, regex_detections = regex_scan(text)
    regex_types = list({d["pii_type"] for d in regex_detections})
    after_gemini, gemini_detections = gemini_scan(after_regex, already_masked_types=regex_types)
    all_detections = regex_detections + gemini_detections
    return after_gemini, all_detections


def build_pii_summary(detections: list) -> dict:
    summary = {}
    for d in detections:
        t = d["pii_type"]
        summary[t] = summary.get(t, 0) + 1
    return summary
