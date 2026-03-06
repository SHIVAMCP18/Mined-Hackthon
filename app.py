"""
app.py — Main Streamlit application
PII Sanitizer | Nirma HACKaMINeD 2025
"""
import uuid
import streamlit as st
import pandas as pd
from datetime import datetime

from auth import require_login, require_admin, is_admin, current_user, logout, show_login_page
from database import (
    get_all_files, get_file_by_id, create_file_record, update_file_record,
    save_pii_detections, get_pii_detections, get_audit_logs, log_action,
    get_all_users, create_user
)
from storage import upload_file, download_file, get_presigned_url, get_content_type
from file_processor import process_file, extract_preview_text
from pii_engine import build_pii_summary

# ── PAGE CONFIG ──────────────────────────────────────────────────

st.set_page_config(
    page_title="PII Sanitizer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── GLOBAL CSS ───────────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:ital,wght@0,300;0,400;0,500;0,600;1,400&display=swap');

/* Base */
html, body, [class*="css"] {
    font-family: 'DM Sans', sans-serif;
}
.stApp {
    background: #080b12;
    color: #e2e8f0;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0d1117 !important;
    border-right: 1px solid #1e2433;
}
section[data-testid="stSidebar"] * {
    color: #cbd5e1 !important;
}

/* Metric cards */
.metric-card {
    background: #0f1623;
    border: 1px solid #1e2d45;
    border-radius: 12px;
    padding: 20px 24px;
    text-align: center;
}
.metric-number {
    font-family: 'Space Mono', monospace;
    font-size: 36px;
    font-weight: 700;
    color: #ff3b64;
    line-height: 1;
}
.metric-label {
    font-size: 12px;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 6px;
}

/* Section headers */
.section-header {
    font-family: 'Space Mono', monospace;
    font-size: 13px;
    color: #ff3b64;
    text-transform: uppercase;
    letter-spacing: 2px;
    margin: 28px 0 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid #1e2433;
}

/* File row */
.file-row {
    background: #0f1623;
    border: 1px solid #1e2433;
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

/* Status badges */
.badge {
    font-size: 11px;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 20px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.badge-done     { background: #052e1a; color: #34d399; border: 1px solid #065f46; }
.badge-process  { background: #1c1a05; color: #fbbf24; border: 1px solid #92400e; }
.badge-admin    { background: #1a0525; color: #c084fc; border: 1px solid #7e22ce; }
.badge-standard { background: #051a26; color: #38bdf8; border: 1px solid #0369a1; }

/* PII type chip */
.pii-chip {
    display: inline-block;
    background: #1a0f1f;
    color: #f472b6;
    border: 1px solid #831843;
    border-radius: 6px;
    padding: 2px 8px;
    font-size: 11px;
    font-family: 'Space Mono', monospace;
    margin: 2px;
}

/* Diff view */
.diff-original {
    background: #1a0f0f;
    border-left: 3px solid #ef4444;
    padding: 12px 16px;
    border-radius: 0 8px 8px 0;
    font-family: 'Space Mono', monospace;
    font-size: 12px;
    white-space: pre-wrap;
    color: #fca5a5;
    line-height: 1.6;
}
.diff-sanitized {
    background: #0a1f0a;
    border-left: 3px solid #22c55e;
    padding: 12px 16px;
    border-radius: 0 8px 8px 0;
    font-family: 'Space Mono', monospace;
    font-size: 12px;
    white-space: pre-wrap;
    color: #86efac;
    line-height: 1.6;
}

/* Buttons */
.stButton > button {
    background: #ff3b64 !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-family: 'DM Sans', sans-serif !important;
    font-weight: 600 !important;
}
.stButton > button:hover {
    background: #e02d55 !important;
}

/* Upload area */
[data-testid="stFileUploader"] {
    border: 2px dashed #1e2d45 !important;
    border-radius: 12px !important;
    background: #0a0f1a !important;
}

/* Tables */
.stDataFrame {
    border-radius: 10px;
    overflow: hidden;
}

/* Page title */
.page-title {
    font-family: 'Space Mono', monospace;
    font-size: 28px;
    font-weight: 700;
    color: #f1f5f9;
    margin-bottom: 4px;
}
.page-subtitle {
    color: #475569;
    font-size: 14px;
    margin-bottom: 32px;
}
</style>
""", unsafe_allow_html=True)


# ── SIDEBAR ──────────────────────────────────────────────────────

def render_sidebar():
    user = current_user()
    with st.sidebar:
        st.markdown("""
        <div style="padding: 20px 0 24px; border-bottom: 1px solid #1e2433; margin-bottom: 20px;">
            <div style="font-family:'Space Mono',monospace; font-size:18px; color:#ff3b64; font-weight:700;">
                🔐 PII Sanitizer
            </div>
            <div style="font-size:11px; color:#475569; margin-top:4px; letter-spacing:1px; text-transform:uppercase;">
                HACKaMINeD 2025
            </div>
        </div>
        """, unsafe_allow_html=True)

        if user:
            role_badge = "badge-admin" if user["role"] == "admin" else "badge-standard"
            st.markdown(f"""
            <div style="margin-bottom:20px; padding:12px; background:#0a0f1a; border-radius:8px; border:1px solid #1e2433;">
                <div style="font-size:13px; font-weight:600;">{user['username']}</div>
                <div style="margin-top:4px;">
                    <span class="badge {role_badge}">{user['role']}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Navigation
            pages = ["📊 Dashboard", "📁 Files"]
            if is_admin():
                pages += ["⬆️ Upload", "🔍 Audit Logs", "👥 Users"]

            page = st.radio("Navigation", pages, label_visibility="collapsed")

            st.markdown("<div style='margin-top:auto; padding-top:40px;'>", unsafe_allow_html=True)
            if st.button("Sign Out", use_container_width=True):
                logout()

            return page.split(" ", 1)[1].strip()  # strip emoji

    return None


# ── DASHBOARD ────────────────────────────────────────────────────

def page_dashboard():
    st.markdown('<div class="page-title">Dashboard</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Overview of PII sanitization activity</div>', unsafe_allow_html=True)

    files = get_all_files()
    done_files = [f for f in files if f["status"] == "done"]
    total_pii = sum(f["pii_count"] or 0 for f in done_files)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="metric-card"><div class="metric-number">{len(files)}</div><div class="metric-label">Total Files</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="metric-card"><div class="metric-number">{len(done_files)}</div><div class="metric-label">Sanitized</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="metric-card"><div class="metric-number">{total_pii}</div><div class="metric-label">PII Items Found</div></div>', unsafe_allow_html=True)
    with c4:
        processing = len([f for f in files if f["status"] == "processing"])
        st.markdown(f'<div class="metric-card"><div class="metric-number">{processing}</div><div class="metric-label">Processing</div></div>', unsafe_allow_html=True)

    st.markdown('<div class="section-header">Recent Files</div>', unsafe_allow_html=True)

    if not files:
        st.info("No files uploaded yet. Admins can upload files from the Upload page.")
        return

    for f in files[:8]:
        pii_count = f["pii_count"] or 0
        status = f["status"]
        status_icon = "✅" if status == "done" else "⏳"
        uploader_info = f" · by **{f['uploader']}**" if is_admin() and f.get("uploader") else ""
        col1, col2 = st.columns([4, 1])
        with col1:
            st.markdown(f"**{f['original_filename']}**")
            st.caption(f"{f['file_type'].upper()} · {str(f['upload_time'])[:16]}{uploader_info}")
        with col2:
            st.markdown(f"🔴 **{pii_count} PII** {status_icon} `{status}`")
        st.divider()


# ── FILES PAGE ───────────────────────────────────────────────────

def page_files():
    st.markdown('<div class="page-title">Files</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Browse and download sanitized files</div>', unsafe_allow_html=True)

    files = get_all_files()
    done_files = [f for f in files if f["status"] == "done"]

    if not done_files:
        st.info("No sanitized files available yet.")
        return

    for f in done_files:
        with st.expander(f"📄 {f['original_filename']} — {f['pii_count']} PII items redacted"):
            col1, col2 = st.columns([3, 1])
            with col1:
                # PII summary chips
                if f.get("pii_summary"):
                    chips = "".join([
                        f'<span class="pii-chip">{k}: {v}</span>'
                        for k, v in f["pii_summary"].items()
                    ])
                    st.markdown(f'<div style="margin-bottom:12px;">{chips}</div>', unsafe_allow_html=True)

                # Show detections table
                if is_admin():
                    detections = get_pii_detections(str(f["id"]))
                    if detections:
                        df = pd.DataFrame(detections)[["pii_type", "masked_value", "detection_method"]]
                        df.columns = ["Type", "Masked As", "Method"]
                        st.dataframe(df, use_container_width=True, hide_index=True)

            with col2:
                st.markdown(f"**Format:** `{f['file_type'].upper()}`")
                st.markdown(f"**Uploaded:** {str(f['upload_time'])[:16]}")

                # Download sanitized file
                if f.get("sanitized_r2_key"):
                    try:
                        sanitized_bytes = download_file(f["sanitized_r2_key"])
                        st.download_button(
                            label="⬇️ Download Sanitized",
                            data=sanitized_bytes,
                            file_name=f"sanitized_{f['original_filename']}",
                            mime=get_content_type(f["original_filename"]),
                            use_container_width=True,
                            key=f"dl_{f['id']}"
                        )
                        log_action(current_user()["id"], "download", str(f["id"]),
                                   {"filename": f["original_filename"]})
                    except Exception as e:
                        st.error(f"Download error: {e}")

                # Admin: also show original
                if is_admin() and f.get("original_r2_key"):
                    try:
                        original_bytes = download_file(f["original_r2_key"])
                        st.download_button(
                            label="⬇️ Download Original",
                            data=original_bytes,
                            file_name=f["original_filename"],
                            mime=get_content_type(f["original_filename"]),
                            use_container_width=True,
                            key=f"dl_orig_{f['id']}"
                        )
                    except Exception as e:
                        st.error(f"Download error: {e}")


# ── UPLOAD PAGE (ADMIN ONLY) ─────────────────────────────────────

def page_upload():
    require_admin()
    st.markdown('<div class="page-title">Upload File</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Upload a file — PII will be automatically detected and masked</div>', unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "Drag and drop a file",
        type=["pdf", "docx", "sql", "csv", "txt", "json", "png", "jpg", "jpeg"],
        help="Supported: PDF, DOCX, SQL, CSV, TXT, JSON, Images"
    )

    if uploaded:
        file_bytes = uploaded.read()
        ext = uploaded.name.rsplit(".", 1)[-1].lower()

        col1, col2 = st.columns(2)
        with col1:
            st.markdown('<div class="section-header">Original Preview</div>', unsafe_allow_html=True)
            if ext in ("png", "jpg", "jpeg"):
                st.image(file_bytes, caption="Uploaded image", use_column_width=True)
                st.info("Image uploaded. OCR-based PII detection will run on sanitize.")
            else:
                preview = extract_preview_text(file_bytes, uploaded.name, max_chars=1500)
                st.markdown(f'<div class="diff-original">{preview}</div>', unsafe_allow_html=True)

        if st.button("🚀 Run PII Detection & Sanitize", use_container_width=True):
            with st.spinner("Scanning for PII (Regex + Claude AI)..."):
                try:
                    user = current_user()
                    file_id = str(uuid.uuid4())

                    # Upload original to R2
                    orig_key = f"originals/{file_id}/{uploaded.name}"
                    upload_file(file_bytes, orig_key, get_content_type(uploaded.name))

                    # Create DB record
                    db_file_id = create_file_record(
                        uploaded.name, ext, user["id"], orig_key
                    )

                    # Process file
                    sanitized_bytes, detections, pii_summary = process_file(file_bytes, uploaded.name)

                    # Upload sanitized to R2
                    san_key = f"sanitized/{file_id}/sanitized_{uploaded.name}"
                    upload_file(sanitized_bytes, san_key, get_content_type(uploaded.name))

                    # Update DB
                    update_file_record(db_file_id, san_key, len(detections), pii_summary)
                    save_pii_detections(db_file_id, detections)
                    log_action(user["id"], "upload", db_file_id,
                               {"filename": uploaded.name, "pii_count": len(detections)})

                    st.success(f"✅ Done! Found and masked **{len(detections)} PII items**.")

                    # Show results
                    if ext not in ("png", "jpg", "jpeg"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown('<div class="section-header">Original</div>', unsafe_allow_html=True)
                            original_preview = extract_preview_text(file_bytes, uploaded.name, 1500)
                            st.markdown(f'<div class="diff-original">{original_preview}</div>', unsafe_allow_html=True)
                        with col2:
                            st.markdown('<div class="section-header">Sanitized</div>', unsafe_allow_html=True)
                            sanitized_preview = extract_preview_text(sanitized_bytes, uploaded.name, 1500)
                            st.markdown(f'<div class="diff-sanitized">{sanitized_preview}</div>', unsafe_allow_html=True)
                    else:
                        st.image(file_bytes, caption="Original Image (PII detected via OCR)", use_container_width=True)

                    # PII breakdown
                    st.markdown('<div class="section-header">PII Breakdown</div>', unsafe_allow_html=True)
                    if pii_summary:
                        chips = "".join([f'<span class="pii-chip">{k}: {v}</span>' for k, v in pii_summary.items()])
                        st.markdown(f'<div>{chips}</div>', unsafe_allow_html=True)

                        df = pd.DataFrame(detections)[["pii_type", "original_value", "masked_value", "detection_method"]]
                        df.columns = ["Type", "Original", "Masked As", "Method"]
                        st.dataframe(df, use_container_width=True, hide_index=True)

                    # Download button
                    st.download_button(
                        "⬇️ Download Sanitized File",
                        data=sanitized_bytes,
                        file_name=f"sanitized_{uploaded.name}",
                        mime=get_content_type(uploaded.name),
                        use_container_width=True
                    )

                except Exception as e:
                    st.error(f"Error during processing: {e}")
                    raise e


# ── AUDIT LOGS PAGE (ADMIN ONLY) ─────────────────────────────────

def page_audit_logs():
    require_admin()
    st.markdown('<div class="page-title">Audit Logs</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Complete activity trail for compliance</div>', unsafe_allow_html=True)

    logs = get_audit_logs(limit=200)
    if not logs:
        st.info("No audit logs yet.")
        return

    df = pd.DataFrame(logs)
    display_cols = ["timestamp", "username", "action", "original_filename"]
    available = [c for c in display_cols if c in df.columns]
    df = df[available].copy()
    df.columns = ["Timestamp", "User", "Action", "File"][:len(available)]
    df["Timestamp"] = pd.to_datetime(df["Timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")

    # Filter
    col1, col2 = st.columns(2)
    with col1:
        action_filter = st.selectbox("Filter by Action", ["All"] + sorted(df["Action"].dropna().unique().tolist()))
    with col2:
        user_filter = st.selectbox("Filter by User", ["All"] + sorted(df["User"].dropna().unique().tolist()))

    filtered = df.copy()
    if action_filter != "All":
        filtered = filtered[filtered["Action"] == action_filter]
    if user_filter != "All":
        filtered = filtered[filtered["User"] == user_filter]

    st.dataframe(filtered, use_container_width=True, hide_index=True)


# ── USERS PAGE (ADMIN ONLY) ──────────────────────────────────────

def page_users():
    require_admin()
    st.markdown('<div class="page-title">User Management</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Manage user accounts and roles</div>', unsafe_allow_html=True)

    users = get_all_users()
    df = pd.DataFrame(users)[["username", "email", "role", "created_at", "is_active"]]
    df.columns = ["Username", "Email", "Role", "Created", "Active"]
    df["Created"] = pd.to_datetime(df["Created"]).dt.strftime("%Y-%m-%d")
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.markdown('<div class="section-header">Add New User</div>', unsafe_allow_html=True)
    with st.form("add_user"):
        c1, c2 = st.columns(2)
        with c1:
            new_username = st.text_input("Username")
            new_email    = st.text_input("Email")
        with c2:
            new_password = st.text_input("Password", type="password")
            new_role     = st.selectbox("Role", ["standard", "admin"])

        if st.form_submit_button("Create User", use_container_width=True):
            try:
                create_user(new_username, new_email, new_password, new_role)
                st.success(f"User '{new_username}' created successfully!")
                st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")


# ── MAIN ROUTER ──────────────────────────────────────────────────

def main():
    if not current_user():
        show_login_page()
        return

    page = render_sidebar()

    if page == "Dashboard":
        page_dashboard()
    elif page == "Files":
        page_files()
    elif page == "Upload":
        page_upload()
    elif page == "Audit Logs":
        page_audit_logs()
    elif page == "Users":
        page_users()


if __name__ == "__main__":
    main()
