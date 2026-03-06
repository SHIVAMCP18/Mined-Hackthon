"""
file_processor.py — Extract text from multiple formats, run PII scan, rebuild sanitized file
Uses pdfplumber instead of PyMuPDF (works on Mac M1/M2/M3 + Python 3.13)
"""
import io
import csv
import json

import pdfplumber
from docx import Document
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

from pii_engine import full_scan, build_pii_summary


def process_file(file_bytes: bytes, filename: str) -> tuple:
    ext = filename.rsplit(".", 1)[-1].lower()

    if ext == "pdf":
        return _process_pdf(file_bytes)
    elif ext == "docx":
        return _process_docx(file_bytes)
    elif ext in ("sql", "txt"):
        return _process_text(file_bytes)
    elif ext == "csv":
        return _process_csv(file_bytes)
    elif ext == "json":
        return _process_json(file_bytes)
    elif ext in ("png", "jpg", "jpeg"):
        return _process_image(file_bytes)
    else:
        return _process_text(file_bytes)


# ── PDF ──────────────────────────────────────────────────────────

def _process_pdf(file_bytes: bytes) -> tuple:
    all_detections = []
    full_masked_text = ""

    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            masked, detections = full_scan(text)
            all_detections.extend(detections)
            full_masked_text += masked + "\n\n"

    # Rebuild as a simple text-based PDF using reportlab
    out = io.BytesIO()
    doc = SimpleDocTemplate(out, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    for line in full_masked_text.split("\n"):
        if line.strip():
            try:
                story.append(Paragraph(line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), styles["Normal"]))
            except Exception:
                pass
    doc.build(story)

    summary = build_pii_summary(all_detections)
    return out.getvalue(), all_detections, summary


# ── DOCX ─────────────────────────────────────────────────────────

def _process_docx(file_bytes: bytes) -> tuple:
    doc = Document(io.BytesIO(file_bytes))
    all_detections = []

    for para in doc.paragraphs:
        if para.text.strip():
            for run in para.runs:
                if run.text.strip():
                    masked, detections = full_scan(run.text)
                    all_detections.extend(detections)
                    run.text = masked

    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    for run in para.runs:
                        if run.text.strip():
                            masked, detections = full_scan(run.text)
                            all_detections.extend(detections)
                            run.text = masked

    out = io.BytesIO()
    doc.save(out)
    summary = build_pii_summary(all_detections)
    return out.getvalue(), all_detections, summary


# ── SQL / TXT ────────────────────────────────────────────────────

def _process_text(file_bytes: bytes) -> tuple:
    text = file_bytes.decode("utf-8", errors="replace")
    masked, detections = full_scan(text)
    summary = build_pii_summary(detections)
    return masked.encode("utf-8"), detections, summary


# ── CSV ──────────────────────────────────────────────────────────

def _process_csv(file_bytes: bytes) -> tuple:
    text = file_bytes.decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    all_detections = []

    sanitized_rows = []
    for row in rows:
        sanitized_row = []
        for cell in row:
            if cell.strip():
                masked, detections = full_scan(cell)
                all_detections.extend(detections)
                sanitized_row.append(masked)
            else:
                sanitized_row.append(cell)
        sanitized_rows.append(sanitized_row)

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerows(sanitized_rows)
    summary = build_pii_summary(all_detections)
    return out.getvalue().encode("utf-8"), all_detections, summary


# ── JSON ─────────────────────────────────────────────────────────

def _process_json(file_bytes: bytes) -> tuple:
    text = file_bytes.decode("utf-8", errors="replace")
    masked, detections = full_scan(text)
    summary = build_pii_summary(detections)
    return masked.encode("utf-8"), detections, summary


# ── IMAGE ────────────────────────────────────────────────────────

def _process_image(file_bytes: bytes) -> tuple:
    """
    Try OCR with pytesseract if available, otherwise return placeholder.
    """
    try:
        import pytesseract
        from PIL import Image
        import io
        image = Image.open(io.BytesIO(file_bytes))
        text = pytesseract.image_to_string(image)
        masked, detections = full_scan(text)
        summary = build_pii_summary(detections)
        # Return original image bytes (we can't rewrite the image)
        return file_bytes, detections, summary
    except Exception:
        # pytesseract not available — return image as-is with note
        return file_bytes, [], {"note": "Install pytesseract for image OCR"}


# ── PREVIEW ──────────────────────────────────────────────────────

def extract_preview_text(file_bytes: bytes, filename: str, max_chars: int = 2000) -> str:
    ext = filename.rsplit(".", 1)[-1].lower()
    try:
        if ext == "pdf":
            with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                text = "\n".join(page.extract_text() or "" for page in pdf.pages)
                return text[:max_chars]
        elif ext == "docx":
            doc = Document(io.BytesIO(file_bytes))
            return "\n".join(p.text for p in doc.paragraphs)[:max_chars]
        else:
            return file_bytes.decode("utf-8", errors="replace")[:max_chars]
    except Exception:
        return "[Preview unavailable]"
