#!/usr/bin/env python3
"""
filecp — Instant, Private, and Seamless File Sharing
A single-file, production-ready web application for secure session-based
file sharing across devices.
"""

import asyncio
import base64
import io
import mimetypes
import os
import secrets
import shutil
import string
import tempfile
import time
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path

import qrcode
import uvicorn
from cryptography.fernet import Fernet
from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    Response,
    StreamingResponse,
    FileResponse,
)

# ──────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────
APP_NAME = "SECURED MOBILE2PC ANY FILE SHARE"
APP_VERSION = "1.0.0"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8000))
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL", "")
MAX_UPLOAD_SIZE = 2000 * 1024 * 1024  # 2 GB total per session
MAX_SINGLE_FILE = 1000 * 1024 * 1024  # 1 GB per file
UPLOAD_DIR = Path(tempfile.gettempdir()) / "filecp_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ENCRYPTION_KEY = Fernet.generate_key()
CIPHER = Fernet(ENCRYPTION_KEY)
CLEANUP_INTERVAL = 15  # seconds between cleanup sweeps
SESSION_ID_LENGTH = 6

# ──────────────────────────────────────────────────────────────────────
# In-memory session store
# ──────────────────────────────────────────────────────────────────────
sessions: dict = {}


# ──────────────────────────────────────────────────────────────────────
# App initialization
# ──────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def _lifespan(app: FastAPI):
    task = asyncio.create_task(_cleanup_expired_sessions())
    yield
    task.cancel()


app = FastAPI(title=APP_NAME, version=APP_VERSION, docs_url=None, redoc_url=None, lifespan=_lifespan)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────
def _generate_session_id() -> str:
    alphabet = string.ascii_uppercase + string.digits
    while True:
        sid = "".join(secrets.choice(alphabet) for _ in range(SESSION_ID_LENGTH))
        if sid not in sessions:
            return sid


def _format_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def _get_file_icon(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    icons = {
        ".pdf": "picture_as_pdf",
        ".doc": "description", ".docx": "description",
        ".xls": "table_chart", ".xlsx": "table_chart",
        ".ppt": "slideshow", ".pptx": "slideshow",
        ".txt": "article", ".md": "article", ".csv": "article",
        ".zip": "folder_zip", ".rar": "folder_zip", ".7z": "folder_zip",
        ".tar": "folder_zip", ".gz": "folder_zip",
        ".mp4": "movie", ".avi": "movie", ".mkv": "movie", ".mov": "movie",
        ".mp3": "audio_file", ".wav": "audio_file", ".flac": "audio_file",
        ".ogg": "audio_file",
        ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
        ".svg": "image", ".webp": "image", ".bmp": "image",
        ".py": "code", ".js": "code", ".html": "code", ".css": "code",
        ".java": "code", ".cpp": "code", ".c": "code",
        ".json": "data_object", ".xml": "data_object",
        ".exe": "terminal", ".msi": "terminal",
    }
    return icons.get(ext, "insert_drive_file")


def _is_previewable_image(filename: str) -> bool:
    return Path(filename).suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg")


async def _cleanup_expired_sessions():
    while True:
        await asyncio.sleep(CLEANUP_INTERVAL)
        now = time.time()
        expired = [sid for sid, s in sessions.items() if now > s["expires_at"]]
        for sid in expired:
            session_dir = UPLOAD_DIR / sid
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            sessions.pop(sid, None)


# ──────────────────────────────────────────────────────────────────────
# API Endpoints
# ──────────────────────────────────────────────────────────────────────
@app.get("/logo.png")
async def get_logo():
    if os.path.exists("logo.png"):
        return FileResponse("logo.png")
    raise HTTPException(status_code=404, detail="Logo not found")

@app.get("/favicon.ico")
async def get_favicon():
    if os.path.exists("logo.png"):
        return FileResponse("logo.png")
    raise HTTPException(status_code=404, detail="Favicon not found")

@app.post("/api/upload")
async def api_upload(
    request: Request,
    files: list[UploadFile] = File(...),
    note: str = Form(""),
    duration: int = Form(10),
    session_id: str = Form(""),
):
    # Clamp duration between 1 and 1440 minutes (24 hours)
    duration = max(1, min(1440, duration))

    existing = False
    if session_id:
        sid = session_id.upper().strip()
        if sid not in sessions:
            raise HTTPException(404, "Session not found or expired.")
        if sessions[sid].get("status") == "CLOSED":
            raise HTTPException(410, "Session is closed.")
        if time.time() > sessions[sid]["expires_at"]:
            raise HTTPException(410, "Session has expired.")
        session_dir = UPLOAD_DIR / sid
        session_dir.mkdir(parents=True, exist_ok=True)
        existing = True
    else:
        sid = _generate_session_id()
        session_dir = UPLOAD_DIR / sid
        session_dir.mkdir(parents=True, exist_ok=True)

    file_list = []
    total_size = 0

    for upload in files:
        if not upload.filename:
            continue
        safe_name = Path(upload.filename).name
        if not safe_name:
            safe_name = "unnamed_file"
        content = await upload.read()
        file_size = len(content)

        if file_size > MAX_SINGLE_FILE:
            shutil.rmtree(session_dir, ignore_errors=True)
            raise HTTPException(400, f"File '{safe_name}' exceeds 200 MB limit.")

        total_size += file_size
        if total_size > MAX_UPLOAD_SIZE:
            shutil.rmtree(session_dir, ignore_errors=True)
            raise HTTPException(400, "Total upload size exceeds 500 MB limit.")

        encrypted = CIPHER.encrypt(content)
        file_path = session_dir / safe_name
        counter = 1
        while file_path.exists():
            stem = Path(safe_name).stem
            suffix = Path(safe_name).suffix
            file_path = session_dir / f"{stem}_{counter}{suffix}"
            counter += 1

        file_path.write_bytes(encrypted)

        file_list.append({
            "name": file_path.name,
            "original_name": safe_name,
            "size": file_size,
            "size_formatted": _format_size(file_size),
            "icon": _get_file_icon(safe_name),
            "is_image": _is_previewable_image(safe_name),
            "is_pdf": safe_name.lower().endswith(".pdf"),
            "mime": mimetypes.guess_type(safe_name)[0] or "application/octet-stream",
        })

    if not file_list:
        if not existing:
            shutil.rmtree(session_dir, ignore_errors=True)
        raise HTTPException(400, "No files were uploaded.")

    now = time.time()
    if existing:
        sessions[sid].update({
            "files": file_list,
            "note": note.strip()[:1000] if note else sessions[sid].get("note", ""),
            "expires_at": now + duration * 60,
            "duration_minutes": duration,
            "total_size": total_size,
            "total_size_formatted": _format_size(total_size),
            "waiting": False,
        })
    else:
        sessions[sid] = {
            "id": sid,
            "files": file_list,
            "note": note.strip()[:1000] if note else "",
            "created_at": now,
            "expires_at": now + duration * 60,
            "duration_minutes": duration,
            "total_size": total_size,
            "total_size_formatted": _format_size(total_size),
            "download_count": 0,
            "status": "ACTIVE",
        }

    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "session_id": sid,
        "expires_at": sessions[sid]["expires_at"],
        "file_count": len(file_list),
        "share_url": f"{base}/session/{sid}",
    })


@app.get("/api/session/{session_id}")
async def api_session_info(session_id: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    s = sessions[sid]
    if s.get("status") == "CLOSED":
        return JSONResponse({"status": "CLOSED"})
    if time.time() > s["expires_at"]:
        return JSONResponse({"status": "EXPIRED"})
    remaining = max(0, s["expires_at"] - time.time())
    return JSONResponse({
        "id": s["id"],
        "files": s["files"],
        "note": s["note"],
        "created_at": s["created_at"],
        "expires_at": s["expires_at"],
        "remaining_seconds": remaining,
        "duration_minutes": s["duration_minutes"],
        "total_size_formatted": s["total_size_formatted"],
        "download_count": s["download_count"],
        "status": s.get("status", "ACTIVE"),
    })


@app.get("/api/download/{session_id}/{filename}")
async def api_download_file(session_id: str, filename: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    s = sessions[sid]
    if s.get("status") == "CLOSED":
        return JSONResponse({"status": "CLOSED"})
    if time.time() > s["expires_at"]:
        return JSONResponse({"status": "EXPIRED"})

    valid_names = {f["name"] for f in s["files"]}
    if filename not in valid_names:
        raise HTTPException(404, "File not found in session.")

    file_path = UPLOAD_DIR / sid / filename
    if not file_path.exists():
        raise HTTPException(404, "File data not found.")

    try:
        file_path.resolve().relative_to(UPLOAD_DIR.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied.")

    encrypted = file_path.read_bytes()
    decrypted = CIPHER.decrypt(encrypted)

    s["download_count"] += 1
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    # Find original name for proper download filename
    original_name = filename
    for f in s["files"]:
        if f["name"] == filename:
            original_name = f["original_name"]
            break
    return Response(
        content=decrypted,
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{original_name}"',
            "Content-Length": str(len(decrypted)),
        },
    )


@app.get("/api/preview/{session_id}/{filename}")
async def api_preview_file(session_id: str, filename: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    s = sessions[sid]
    if s.get("status") == "CLOSED":
        return JSONResponse({"status": "CLOSED"})
    if time.time() > s["expires_at"]:
        return JSONResponse({"status": "EXPIRED"})

    valid_names = {f["name"] for f in s["files"]}
    if filename not in valid_names:
        raise HTTPException(404, "File not found in session.")

    file_path = UPLOAD_DIR / sid / filename
    if not file_path.exists():
        raise HTTPException(404, "File data not found.")

    try:
        file_path.resolve().relative_to(UPLOAD_DIR.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied.")

    encrypted = file_path.read_bytes()
    decrypted = CIPHER.decrypt(encrypted)
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return Response(content=decrypted, media_type=mime)


@app.get("/api/download-all/{session_id}")
async def api_download_all(session_id: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    s = sessions[sid]
    if s.get("status") == "CLOSED":
        return JSONResponse({"status": "CLOSED"})
    if time.time() > s["expires_at"]:
        return JSONResponse({"status": "EXPIRED"})

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in s["files"]:
            file_path = UPLOAD_DIR / sid / f["name"]
            if file_path.exists():
                encrypted = file_path.read_bytes()
                decrypted = CIPHER.decrypt(encrypted)
                zf.writestr(f["original_name"], decrypted)

    buf.seek(0)
    s["download_count"] += 1
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="filecp_{sid}.zip"'},
    )


@app.get("/api/qr/{session_id}")
async def api_qr_code(request: Request, session_id: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    base = RENDER_EXTERNAL_URL or str(request.base_url).rstrip("/")
    url = f"{base}/session/{sid}"
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0c1220", back_color="#f4efe4")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")



@app.post("/api/close-session/{session_id}")
async def api_close_session(session_id: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found.")
    sessions[sid]["status"] = "CLOSED"
    return JSONResponse({"success": True})

@app.post("/api/receive-session")
async def api_create_receive_session(duration: int = Form(10)):
    duration = max(1, min(1440, duration))
    sid = _generate_session_id()
    session_dir = UPLOAD_DIR / sid
    session_dir.mkdir(parents=True, exist_ok=True)
    now = time.time()
    sessions[sid] = {
        "id": sid,
        "files": [],
        "note": "",
        "created_at": now,
        "expires_at": now + duration * 60,
        "duration_minutes": duration,
        "total_size": 0,
        "total_size_formatted": _format_size(0),
        "download_count": 0,
            "status": "ACTIVE",
        "waiting": True,
    }
    return JSONResponse({"session_id": sid})


@app.get("/api/receive-qr/{session_id}")
async def api_receive_qr(request: Request, session_id: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found.")
    base = RENDER_EXTERNAL_URL or str(request.base_url).rstrip("/")
    url = f"{base}/send-to/{sid}"
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0c1220", back_color="#f4efe4")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# ──────────────────────────────────────────────────────────────────────
# Frontend Templates
# ──────────────────────────────────────────────────────────────────────

_SHARED_STYLES = """
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;700;800&display=swap');
  @import url('https://fonts.googleapis.com/icon?family=Material+Icons+Round');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg-primary: #000000;
    --bg-surface: #0a0a0a;
    --bg-surface-hover: #141414;
    --border-color: #333333;
    --border-light: #555555;
    
    --text-primary: #e0e0e0;
    --text-secondary: #a0a0a0;
    --text-muted: #666666;
    --text-bright: #ffffff;
    
    --accent: #ffffff;
    --success: #00ff66;
    --error: #ff3333;
    
    /* Pixel aesthetic: zero border radius */
    --radius-sm: 0px;
    --radius-md: 0px;
    --radius-lg: 0px;
    
    --transition: 0.15s ease-out;
    --font: 'Inter', sans-serif;
    --display-font: 'JetBrains Mono', monospace;
  }

  html { scroll-behavior: smooth; }
  body {
    font-family: var(--font);
    background-color: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
    overflow-x: hidden;
  }

  /* Glossy / Tech background effect */
  body::before {
    content: ''; position: fixed; inset: 0; pointer-events: none; z-index: -2;
    background: radial-gradient(circle at 50% -20%, rgba(255,255,255,0.03) 0%, transparent 60%);
  }

  a { color: var(--text-primary); text-decoration: none; transition: color var(--transition); }
  a:hover { color: var(--text-bright); }

  .material-icons-round { font-family: 'Material Icons Round'; vertical-align: middle; }

  .container { max-width: 1000px; margin: 0 auto; padding: 0 24px; }
  
  /* Chrome Text Effect */
  .text-chrome {
    background: linear-gradient(180deg, #ffffff 0%, #b3b3b3 40%, #808080 50%, #e6e6e6 60%, #ffffff 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    color: #fff; /* fallback */
    text-shadow: 0 2px 10px rgba(255,255,255,0.15);
  }

  .nav { display: none; } /* No top navigation */

  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 14px 28px; border-radius: var(--radius-sm);
    font-family: var(--display-font); font-size: 0.9rem; font-weight: 800;
    cursor: pointer; border: 1px solid var(--border-color); transition: all var(--transition);
    text-decoration: none; white-space: nowrap; text-transform: uppercase;
    background: var(--bg-primary); color: var(--text-primary);
    letter-spacing: 0.05em;
  }
  .btn-primary {
    background: var(--text-bright); color: var(--bg-primary); border-color: var(--text-bright);
  }
  .btn-primary:hover {
    background: #d4d4d4; color: var(--bg-primary); border-color: #d4d4d4;
    box-shadow: 0 0 15px rgba(255,255,255,0.2);
  }
  .btn-outline {
    background: transparent; color: var(--text-bright); border-color: var(--border-light);
  }
  .btn-outline:hover {
    border-color: var(--text-bright); background: rgba(255,255,255,0.05);
  }
  .btn-danger {
    background: transparent; color: var(--error); border-color: var(--error);
  }
  .btn-danger:hover {
    background: var(--error); color: var(--bg-primary);
  }
  .btn-sm { padding: 8px 16px; font-size: 0.8rem; }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; transform: none !important; box-shadow: none !important; }
  .btn .material-icons-round { font-size: 18px; }

  .card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: 32px;
  }
  
  .input-group { display: flex; flex-direction: column; gap: 8px; }
  .input-group label {
    font-size: 0.75rem; font-family: var(--display-font); color: var(--text-secondary);
    text-transform: uppercase; letter-spacing: 0.05em; font-weight: 700;
  }
  .input-field {
    padding: 12px 16px; border-radius: var(--radius-sm);
    background: var(--bg-primary); border: 1px solid var(--border-color);
    color: var(--text-bright); font-family: var(--display-font); font-size: 1rem;
    transition: all var(--transition); outline: none;
  }
  .input-field:focus { border-color: var(--text-bright); }

  .progress-bar { width: 100%; height: 2px; background: var(--border-color); overflow: hidden; }
  .progress-bar-fill { height: 100%; background: var(--text-bright); transition: width 0.2s linear; }

  @keyframes fadeInUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
  .animate-in { animation: fadeInUp 0.4s ease forwards; }

  .spinner {
    width: 20px; height: 20px; border: 2px solid var(--border-color);
    border-top-color: var(--text-primary); border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .toast-container { position: fixed; bottom: 24px; right: 24px; z-index: 9999; display: flex; flex-direction: column; gap: 12px; }
  .toast {
    display: flex; align-items: center; gap: 12px; padding: 12px 20px;
    background: var(--bg-surface); border: 1px solid var(--border-light);
    color: var(--text-bright); font-size: 0.85rem; font-family: var(--display-font);
    animation: fadeInUp 0.3s ease forwards; box-shadow: 0 10px 30px rgba(0,0,0,0.5);
  }

  .status-badge {
    display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px;
    font-family: var(--display-font); font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
    border: 1px solid var(--border-color); background: var(--bg-primary);
  }
  
  .code { font-family: var(--display-font); color: var(--text-bright); }
  h1, h2, h3 { font-family: var(--display-font); font-weight: 800; text-transform: uppercase; }

  /* Modal for preview */
  .modal-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,0.9); z-index: 10000;
    display: none; align-items: center; justify-content: center; padding: 24px;
    backdrop-filter: blur(4px);
  }
  .modal-overlay.active { display: flex; }
  .modal-content {
    max-width: 100%; max-height: 100%; display: flex; flex-direction: column; align-items: center; gap: 16px;
  }
  .modal-content img { max-width: 100%; max-height: 80vh; object-fit: contain; border: 1px solid var(--border-color); }
</style>
"""

_NAV_INNER = """"""

_TOAST_JS = """
<div class="toast-container" id="toastContainer"></div>
<script>
function showToast(message, type = 'success') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = 'toast';
  let icon = type === 'success' ? 'check' : (type === 'error' ? 'close' : 'info');
  let color = type === 'success' ? 'var(--success)' : (type === 'error' ? 'var(--error)' : 'var(--text-bright)');
  toast.innerHTML = '<span class="material-icons-round" style="color:'+color+'; font-size:16px;">' + icon + '</span><span>' + message + '</span>';
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateY(10px)'; toast.style.transition = '0.3s ease'; setTimeout(() => toast.remove(), 300); }, 3500);
}
</script>
"""

_WELCOME_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SECURED MOBILE2PC ANY FILE SHARE</title>
  """ + _SHARED_STYLES + """
  <style>
    .hero {
      min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center;
      text-align: center; padding: 60px 24px; position: relative; overflow: hidden;
    }
    
    .content-wrapper { position: relative; z-index: 1; display: flex; flex-direction: column; align-items: center; max-width: 800px; }
    
    .hero-title {
      font-size: clamp(2.5rem, 6vw, 4.5rem); line-height: 1.1; margin-bottom: 24px; letter-spacing: -0.02em;
    }
    
    .features-line {
      font-family: var(--display-font); font-size: 0.85rem; color: var(--text-secondary);
      margin-bottom: 48px; display: flex; flex-wrap: wrap; justify-content: center; gap: 16px;
      text-transform: uppercase; letter-spacing: 0.05em;
    }
    
    .quote-box { margin-bottom: 48px; }
    .quote-text { font-size: 1.2rem; font-style: italic; color: var(--text-bright); margin-bottom: 12px; font-weight: 500; }
    .quote-author { font-family: var(--display-font); font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em; }
  </style>
</head>
<body>
  <main class="hero">
    <div class="content-wrapper animate-in">
      <h1 class="hero-title text-chrome">SECURED MOBILE2PC<br>ANY FILE SHARE</h1>
      <div class="features-line">
        <span>[ SECURE FILE TRANSFER ]</span> <span>[ AUTO-EXPIRY QR SHARING ]</span> <span>[ CROSS-PLATFORM INSTANT SHARING ]</span>
      </div>
      
      <div class="quote-box">
        <div class="quote-text">"Simplicity is prerequisite for reliability."</div>
        <div class="quote-author">— Edsger W. Dijkstra</div>
      </div>
      
      <a href="/dashboard" class="btn btn-primary" style="padding: 18px 48px; font-size: 1.1rem;">
        GET STARTED
      </a>
    </div>
  </main>
</body>
</html>"""

_DASHBOARD_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard — SECURED MOBILE2PC ANY FILE SHARE</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px 24px; }
    .page-title { font-size: 1.2rem; color: var(--text-secondary); margin-bottom: 48px; text-transform: uppercase; letter-spacing: 0.1em; }
    
    .action-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 32px; max-width: 900px; width: 100%; }
    @media (max-width: 700px) { .action-grid { grid-template-columns: 1fr; } }
    
    .action-card {
      display: flex; flex-direction: column; align-items: flex-start;
      padding: 48px; text-decoration: none; color: var(--text-primary);
      border: 1px solid var(--border-color); background: var(--bg-surface);
      transition: all var(--transition); position: relative; overflow: hidden;
    }
    .action-card::after {
      content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 2px;
      background: var(--text-bright); transform: scaleX(0); transform-origin: left; transition: transform var(--transition);
    }
    .action-card:hover { border-color: var(--border-light); background: var(--bg-surface-hover); transform: translateY(-4px); }
    .action-card:hover::after { transform: scaleX(1); }
    
    .action-icon { font-size: 40px; color: var(--text-bright); margin-bottom: 24px; }
    .action-card h2 { font-size: 1.6rem; text-transform: uppercase; margin-bottom: 16px; letter-spacing: 0.05em; }
    
    .action-features { list-style: none; display: flex; flex-direction: column; gap: 12px; font-size: 0.9rem; color: var(--text-secondary); }
    .action-features li { display: flex; align-items: center; gap: 8px; }
    .action-features li .material-icons-round { font-size: 16px; color: var(--text-muted); }
  </style>
</head>
<body>
  <main class="page container">
    <div class="page-title animate-in text-chrome">SECURED MOBILE2PC // SELECT MODE</div>
    
    <div class="action-grid animate-in" style="animation-delay: 0.1s;">
      <a href="/send" class="action-card">
        <span class="material-icons-round action-icon">upload</span>
        <h2 class="text-chrome">SEND FILE</h2>
        <ul class="action-features">
          <li><span class="material-icons-round">arrow_right</span> Create a secure session</li>
          <li><span class="material-icons-round">arrow_right</span> Generate a QR code</li>
          <li><span class="material-icons-round">arrow_right</span> Connect a mobile device</li>
          <li><span class="material-icons-round">arrow_right</span> Send one or multiple files</li>
        </ul>
      </a>
      <a href="/receive" class="action-card">
        <span class="material-icons-round action-icon">download</span>
        <h2 class="text-chrome">RECEIVE FILE</h2>
        <ul class="action-features">
          <li><span class="material-icons-round">arrow_right</span> Create a receiving session</li>
          <li><span class="material-icons-round">arrow_right</span> Generate a QR code</li>
          <li><span class="material-icons-round">arrow_right</span> Connect a mobile device</li>
          <li><span class="material-icons-round">arrow_right</span> Receive one or multiple files</li>
        </ul>
      </a>
    </div>
  </main>
</body>
</html>"""

_SEND_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Send File — SECURED MOBILE2PC ANY FILE SHARE</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 40px 24px; }
    .header { text-align: center; margin-bottom: 32px; }
    .header h1 { font-size: 1.8rem; margin-bottom: 8px; }
    
    .drop-zone {
      width: 100%; max-width: 600px; border: 2px dashed var(--border-color);
      padding: 48px 24px; text-align: center; cursor: pointer; background: var(--bg-surface);
      transition: all var(--transition); border-top: 2px solid var(--text-bright);
    }
    .drop-zone:hover { border-color: var(--text-bright); }
    
    .file-list-preview { width: 100%; max-width: 600px; margin-top: 16px; margin-bottom: 16px; font-family: var(--display-font); font-size: 0.85rem; text-align: left; }
    
    .qr-card { max-width: 700px; width: 100%; display: none; flex-direction: column; align-items: center; gap: 24px; }
    .qr-image-wrapper { background: #fff; padding: 16px; border: 4px solid var(--text-primary); }
    .qr-image-wrapper img { display: block; width: 240px; height: 240px; }
    
    .status-bar { font-family: var(--display-font); font-size: 0.9rem; color: var(--text-secondary); text-transform: uppercase; margin-top: 8px; }
    
    .activity-list { width: 100%; max-width: 600px; display: flex; flex-direction: column; gap: 8px; }
    .activity-item {
      padding: 12px 16px; background: var(--bg-primary); border: 1px solid var(--border-color);
      border-left: 2px solid var(--success); font-family: var(--display-font);
    }
    .activity-title { font-weight: 800; color: var(--text-bright); margin-bottom: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .activity-meta { font-size: 0.75rem; color: var(--text-muted); }
  </style>
</head>
<body>
  <main class="page container">
    <div class="header animate-in">
      <h1 class="text-chrome">SEND FILES</h1>
    </div>

    <div id="mainUI" class="animate-in" style="width: 100%; display: flex; flex-direction: column; align-items: center;">
      <form id="uploadForm" class="drop-zone" style="display: block;">
        <span class="material-icons-round" style="font-size:48px; color:var(--text-bright); margin-bottom:16px;">upload_file</span>
        <h3 style="margin-bottom:8px;">TAP TO SELECT FILES</h3>
        <input type="file" id="fileInput" multiple style="display:none">
        
        <div class="input-group" style="margin-top: 24px; text-align: left; max-width: 200px; margin-left: auto; margin-right: auto;" onclick="event.stopPropagation()">
          <label>Session Expiry (Minutes)</label>
          <input type="number" id="durationInput" class="input-field" value="10" min="1" max="1440">
        </div>
      </form>
      
      <div style="width:100%; max-width:600px; margin-top:24px; display:none;" id="uploadControls">
        <div class="file-list-preview" id="fileListPreview"></div>
        <button class="btn btn-primary" id="uploadBtn" style="width:100%;">CREATE SESSION & SEND</button>
        <div class="progress-bar" style="margin-top:16px; display:none;" id="progressContainer">
          <div class="progress-bar-fill" id="progressFill" style="width:0%"></div>
        </div>
      </div>
      
      <div style="width:100%; max-width:600px; margin-top:24px; display:none; text-align: center;" id="addMoreContainer">
        <button class="btn btn-outline" style="width:100%; border-style: dashed;" onclick="resetForm()">
          <span class="material-icons-round">add</span> ADD MORE FILE
        </button>
      </div>

      <div class="qr-card animate-in" id="qrCard" style="margin-top: 32px;">
        <div class="qr-image-wrapper">
          <img id="qrImage" src="" alt="QR Code">
        </div>
        <p style="font-family: var(--display-font); font-size: 0.9rem; color: var(--text-secondary);">SCAN WITH MOBILE DEVICE</p>
        
        <div class="status-badge" id="statusBar">
          <span class="material-icons-round" style="font-size: 14px; color: var(--success);">swap_horiz</span>
          SESSION ACTIVE <span id="countdown"></span>
        </div>

        <button class="btn btn-danger" style="margin-top: 16px; width: 100%; max-width: 400px;" onclick="closeSession()" id="closeBtn">
          CLOSE SESSION
        </button>
      </div>

      <div class="activity-list" id="activityList" style="margin-top: 32px;"></div>
    </div>
  </main>

  """ + _TOAST_JS + """
  <script>
    const form = document.getElementById('uploadForm');
    const input = document.getElementById('fileInput');
    let selectedFiles = [];
    let sessionId = null;
    let pollInterval = null;
    let isClosed = false;

    form.addEventListener('click', () => { if(!isClosed) input.click(); });
    input.addEventListener('change', () => {
      if(input.files.length > 0) {
        selectedFiles = Array.from(input.files);
        document.getElementById('fileListPreview').innerHTML = selectedFiles.map(f => `<div>- ${f.name}</div>`).join('');
        document.getElementById('uploadControls').style.display = 'block';
        if (!sessionId) {
          form.style.display = 'none';
        } else {
          document.getElementById('addMoreContainer').style.display = 'none';
        }
      }
    });

    document.getElementById('uploadBtn').addEventListener('click', async () => {
      if(!selectedFiles.length || isClosed) return;
      const btn = document.getElementById('uploadBtn');
      btn.disabled = true;
      document.getElementById('progressContainer').style.display = 'block';
      
      const formData = new FormData();
      selectedFiles.forEach(f => formData.append('files', f));
      formData.append('duration', document.getElementById('durationInput').value || 10);
      if (sessionId) formData.append('session_id', sessionId);
      
      try {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload');
        xhr.upload.onprogress = e => {
          if(e.lengthComputable) {
            document.getElementById('progressFill').style.width = (e.loaded/e.total*100)+'%';
          }
        };
        xhr.onload = () => {
          if(xhr.status >= 200 && xhr.status < 300) {
            const data = JSON.parse(xhr.responseText);
            if (!sessionId) {
              sessionId = data.session_id;
              document.getElementById('qrImage').src = '/api/qr/' + sessionId;
              document.getElementById('qrCard').style.display = 'flex';
              document.getElementById('uploadForm').style.display = 'none';
              startPolling();
            }
            
            document.getElementById('uploadControls').style.display = 'none';
            document.getElementById('addMoreContainer').style.display = 'block';
            
            const activityList = document.getElementById('activityList');
            selectedFiles.forEach(f => {
              const el = document.createElement('div');
              el.className = 'activity-item animate-in';
              el.innerHTML = `
                <div class="activity-title">${f.name}</div>
                <div class="activity-meta">SENT SUCCESSFULLY — JUST NOW</div>
              `;
              activityList.prepend(el);
            });
            showToast('Files sent successfully!');
          } else {
            showToast('Upload failed', 'error');
            btn.disabled = false;
          }
        };
        xhr.onerror = () => { showToast('Network error', 'error'); btn.disabled = false; };
        xhr.send(formData);
      } catch(e) { showToast('Upload failed', 'error'); btn.disabled = false; }
    });

    function resetForm() {
      if(isClosed) return;
      selectedFiles = [];
      input.value = '';
      document.getElementById('progressFill').style.width = '0%';
      document.getElementById('progressContainer').style.display = 'none';
      document.getElementById('addMoreContainer').style.display = 'none';
      document.getElementById('uploadBtn').textContent = 'UPLOAD MORE FILES';
      document.getElementById('uploadBtn').disabled = false;
      
      // we don't unhide the original form fully since we have session ID, 
      // but we trigger the file input.
      input.click();
    }

    function startPolling() {
      pollInterval = setInterval(async () => {
        try {
          const res = await fetch('/api/session/' + sessionId);
          const data = await res.json();
          if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
            document.getElementById('statusBar').innerHTML = '<span class="material-icons-round" style="font-size: 14px; color: var(--error);">block</span> SESSION ' + data.status;
            document.getElementById('statusBar').style.borderColor = 'var(--error)';
            document.getElementById('qrImage').style.opacity = '0.1';
            document.getElementById('closeBtn').style.display = 'none';
            document.getElementById('addMoreContainer').style.display = 'none';
            isClosed = true;
            clearInterval(pollInterval);
            return;
          }
          if (data.remaining_seconds !== undefined) {
            let m = Math.floor(data.remaining_seconds / 60);
            let s = Math.floor(data.remaining_seconds % 60).toString().padStart(2, '0');
            document.getElementById('countdown').textContent = '[' + m + ':' + s + ']';
          }
        } catch(e){}
      }, 2000);
    }

    async function closeSession() {
      try {
        await fetch('/api/close-session/' + sessionId, { method: 'POST' });
        document.getElementById('statusBar').innerHTML = '<span class="material-icons-round" style="font-size: 14px; color: var(--error);">block</span> SESSION CLOSED';
        document.getElementById('statusBar').style.borderColor = 'var(--error)';
        document.getElementById('qrImage').style.opacity = '0.1';
        document.getElementById('closeBtn').style.display = 'none';
        document.getElementById('addMoreContainer').style.display = 'none';
        isClosed = true;
        clearInterval(pollInterval);
        showToast('Session closed', 'success');
      } catch(e) {}
    }
  </script>
</body>
</html>"""

_RECEIVE_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Receive File — SECURED MOBILE2PC ANY FILE SHARE</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 60px 24px; }
    .header { text-align: center; margin-bottom: 40px; }
    .header h1 { font-size: 2rem; margin-bottom: 8px; }
    .header p { color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.85rem; }
    
    .setup-card { max-width: 400px; width: 100%; text-align: center; border-top: 2px solid var(--text-bright); }
    .qr-card { max-width: 700px; width: 100%; display: none; flex-direction: column; align-items: center; gap: 24px; }
    
    .qr-image-wrapper { background: #fff; padding: 16px; border: 4px solid var(--text-primary); }
    .qr-image-wrapper img { display: block; width: 240px; height: 240px; }
    
    .status-bar { margin-top: 8px; margin-bottom: 8px; text-transform: uppercase; }
    
    .file-list { width: 100%; display: flex; flex-direction: column; gap: 12px; }
    .file-item { 
      display: flex; justify-content: space-between; align-items: center; padding: 16px; 
      background: var(--bg-surface); border: 1px solid var(--border-color);
      border-left: 2px solid var(--success);
    }
    
    @media (max-width: 500px) {
      .file-item { flex-direction: column; align-items: flex-start; gap: 12px; }
      .file-item-actions { width: 100%; display: flex; gap: 8px; }
      .file-item-actions .btn { flex: 1; }
    }
  </style>
</head>
<body>
  <main class="page container">
    <div class="header animate-in">
      <h1 class="text-chrome">RECEIVE FILE</h1>
      <p>GENERATE A SECURE QR SESSION TO RECEIVE FILES</p>
    </div>

    <div class="card setup-card animate-in" id="setupCard">
      <div class="input-group" style="margin-bottom: 24px; text-align: left;">
        <label>Session Expiry (Minutes)</label>
        <input type="number" id="expiryInput" class="input-field" value="10" min="1" max="1440">
      </div>
      <button class="btn btn-primary" style="width:100%; padding: 16px;" id="genBtn" onclick="createSession()">
        GENERATE QR CODE
      </button>
    </div>

    <div class="qr-card animate-in" id="qrCard">
      <div class="qr-image-wrapper">
        <img id="qrImage" src="" alt="QR Code">
      </div>
      <p style="font-family: var(--display-font); font-size: 0.9rem; color: var(--text-secondary);">SCAN WITH MOBILE DEVICE</p>
      
      <div class="status-badge" id="statusBar">
        <span class="material-icons-round" style="font-size: 14px; color: var(--text-muted);">hourglass_empty</span>
        WAITING FOR CONNECTION... <span id="countdown"></span>
      </div>

      <div class="file-list" id="fileList"></div>

      <button class="btn btn-danger" style="margin-top: 24px; width: 100%; max-width: 400px;" onclick="closeSession()" id="closeBtn">
        CLOSE SESSION
      </button>
    </div>
  </main>

  <div class="modal-overlay" id="imageModal" onclick="this.classList.remove('active')">
    <div class="modal-content" onclick="event.stopPropagation()">
      <img id="modalImage" src="" alt="Preview">
      <button class="btn btn-outline" onclick="document.getElementById('imageModal').classList.remove('active')">Close Preview</button>
    </div>
  </div>

  """ + _TOAST_JS + """
  <script>
    const SESSION_ID_EL = null;
    let sessionId = null;
    let pollInterval = null;
    let knownFiles = new Set();

    async function createSession() {
      const btn = document.getElementById('genBtn');
      const duration = parseInt(document.getElementById('expiryInput').value) || 10;
      if (duration < 1) { showToast('Invalid duration', 'error'); return; }
      
      btn.disabled = true; btn.textContent = 'GENERATING...';
      
      const formData = new FormData();
      formData.append('duration', duration);
      
      try {
        const res = await fetch('/api/receive-session', { method: 'POST', body: formData });
        if (!res.ok) throw new Error('Failed');
        const data = await res.json();
        sessionId = data.session_id;
        
        document.getElementById('setupCard').style.display = 'none';
        document.getElementById('qrImage').src = '/api/receive-qr/' + sessionId;
        document.getElementById('qrCard').style.display = 'flex';
        
        startPolling();
      } catch (e) {
        showToast('Failed to create session', 'error');
        btn.disabled = false; btn.textContent = 'GENERATE QR CODE';
      }
    }

    function startPolling() {
      pollInterval = setInterval(async () => {
        try {
          const res = await fetch('/api/session/' + sessionId);
          const data = await res.json();
          
          if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
            document.getElementById('statusBar').innerHTML = '<span class="material-icons-round" style="font-size: 14px; color: var(--error);">block</span> SESSION ' + data.status;
            document.getElementById('statusBar').style.borderColor = 'var(--error)';
            document.getElementById('qrImage').style.opacity = '0.1';
            document.getElementById('closeBtn').style.display = 'none';
            clearInterval(pollInterval);
            return;
          }
          
          if (data.remaining_seconds !== undefined) {
            let m = Math.floor(data.remaining_seconds / 60);
            let s = Math.floor(data.remaining_seconds % 60).toString().padStart(2, '0');
            document.getElementById('countdown').textContent = '[' + m + ':' + s + ']';
          }

          if (data.files && data.files.length > 0) {
            const list = document.getElementById('fileList');
            data.files.forEach(f => {
              if (!knownFiles.has(f.name)) {
                knownFiles.add(f.name);
                const el = document.createElement('div');
                el.className = 'file-item animate-in';
                
                let actions = '';
                if (f.is_image) {
                  actions += `<button class="btn btn-outline btn-sm" onclick="previewImage('/api/preview/${sessionId}/${encodeURIComponent(f.name)}')">PREVIEW</button>`;
                }
                actions += `<a href="/api/download/${sessionId}/${encodeURIComponent(f.name)}" class="btn btn-primary btn-sm" download="${f.original_name}">DOWNLOAD</a>`;
                
                el.innerHTML = `
                  <div style="min-width: 0; overflow: hidden;">
                    <div style="font-weight:800; font-family:var(--display-font); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${f.original_name}</div>
                    <div style="font-size:0.75rem; color:var(--text-muted); font-family:var(--display-font);">${f.size_formatted} — RECEIVED JUST NOW</div>
                  </div>
                  <div class="file-item-actions" style="display:flex; gap:8px; flex-shrink:0;">${actions}</div>
                `;
                list.appendChild(el);
              }
            });
            document.getElementById('statusBar').innerHTML = '<span class="material-icons-round" style="font-size: 14px; color: var(--success);">swap_horiz</span> CONNECTION ACTIVE <span id="countdown"></span>';
            document.getElementById('statusBar').style.borderColor = 'var(--success)';
          }
        } catch (e) {}
      }, 2000);
    }

    function previewImage(url) {
      document.getElementById('modalImage').src = url;
      document.getElementById('imageModal').classList.add('active');
    }

    async function closeSession() {
      try {
        await fetch('/api/close-session/' + sessionId, { method: 'POST' });
        document.getElementById('statusBar').innerHTML = '<span class="material-icons-round" style="font-size: 14px; color: var(--error);">block</span> SESSION CLOSED';
        document.getElementById('statusBar').style.borderColor = 'var(--error)';
        document.getElementById('qrImage').style.opacity = '0.1';
        document.getElementById('closeBtn').style.display = 'none';
        clearInterval(pollInterval);
        showToast('Session closed', 'success');
      } catch(e) {
        showToast('Error closing session', 'error');
      }
    }
  </script>
</body>
</html>"""

_SEND_TO_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Send Files — SECURED MOBILE2PC ANY FILE SHARE</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 40px 24px; }
    .header { text-align: center; margin-bottom: 32px; }
    .header h1 { font-size: 1.8rem; margin-bottom: 8px; }
    
    .status-alert {
      display: none; width: 100%; max-width: 600px; padding: 16px; margin-bottom: 24px;
      border: 1px solid var(--error); background: rgba(255,51,51,0.1); color: var(--error);
      text-align: center; font-family: var(--display-font); font-weight: 800;
    }
    
    .drop-zone {
      width: 100%; max-width: 600px; border: 2px dashed var(--border-color);
      padding: 48px 24px; text-align: center; cursor: pointer; background: var(--bg-surface);
      transition: all var(--transition); border-top: 2px solid var(--text-bright);
    }
    .drop-zone:hover { border-color: var(--text-bright); }
    
    .file-list-preview { width: 100%; max-width: 600px; margin-bottom: 16px; font-family: var(--display-font); font-size: 0.85rem; text-align: left; }
    
    .activity-list { width: 100%; max-width: 600px; margin-top: 32px; display: flex; flex-direction: column; gap: 8px; }
    .activity-item {
      padding: 12px 16px; background: var(--bg-primary); border: 1px solid var(--border-color);
      border-left: 2px solid var(--success); font-family: var(--display-font);
    }
    .activity-title { font-weight: 800; color: var(--text-bright); margin-bottom: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .activity-meta { font-size: 0.75rem; color: var(--text-muted); }
  </style>
</head>
<body>
  <main class="page container">
    <div class="header animate-in">
      <h1 class="text-chrome">SEND FILES</h1>
    </div>

    <div class="status-alert" id="statusAlert">SESSION CLOSED</div>

    <div id="mainUI" class="animate-in" style="width: 100%; display: flex; flex-direction: column; align-items: center;">
      <form id="uploadForm" class="drop-zone" style="display: block;">
        <span class="material-icons-round" style="font-size:48px; color:var(--text-bright); margin-bottom:16px;">upload_file</span>
        <h3 style="margin-bottom:8px;">TAP TO SELECT FILES</h3>
        <input type="file" id="fileInput" multiple style="display:none">
      </form>
      
      <div style="width:100%; max-width:600px; margin-top:24px; display:none;" id="uploadControls">
        <div class="file-list-preview" id="fileListPreview"></div>
        <button class="btn btn-primary" id="uploadBtn" style="width:100%;">UPLOAD FILES</button>
        <div class="progress-bar" style="margin-top:16px; display:none;" id="progressContainer">
          <div class="progress-bar-fill" id="progressFill" style="width:0%"></div>
        </div>
      </div>
      
      <div style="width:100%; max-width:600px; margin-top:24px; display:none; text-align: center;" id="addMoreContainer">
        <button class="btn btn-outline" style="width:100%; border-style: dashed;" onclick="resetForm()">
          <span class="material-icons-round">add</span> ADD MORE FILE
        </button>
      </div>

      <div class="activity-list" id="activityList"></div>
    </div>
  </main>

  """ + _TOAST_JS + """
  <script>
    const SESSION_ID = '{{SESSION_ID}}';
    let isClosed = false;
    let selectedFiles = [];

    setInterval(async () => {
      try {
        const res = await fetch('/api/session/' + SESSION_ID);
        const data = await res.json();
        if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
          isClosed = true;
          document.getElementById('statusAlert').style.display = 'block';
          document.getElementById('statusAlert').textContent = 'SESSION ' + data.status;
          document.getElementById('mainUI').style.display = 'none';
        }
      } catch(e){}
    }, 2000);

    const form = document.getElementById('uploadForm');
    const input = document.getElementById('fileInput');
    
    form.addEventListener('click', () => { if(!isClosed) input.click(); });
    input.addEventListener('change', () => {
      if(input.files.length > 0) {
        selectedFiles = Array.from(input.files);
        document.getElementById('fileListPreview').innerHTML = selectedFiles.map(f => `<div>- ${f.name}</div>`).join('');
        document.getElementById('uploadControls').style.display = 'block';
        form.style.display = 'none';
        document.getElementById('addMoreContainer').style.display = 'none';
      }
    });

    document.getElementById('uploadBtn').addEventListener('click', async () => {
      if(!selectedFiles.length || isClosed) return;
      const btn = document.getElementById('uploadBtn');
      btn.disabled = true;
      document.getElementById('progressContainer').style.display = 'block';
      
      const formData = new FormData();
      selectedFiles.forEach(f => formData.append('files', f));
      formData.append('session_id', SESSION_ID);
      formData.append('duration', 10);
      
      try {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload');
        xhr.upload.onprogress = e => {
          if(e.lengthComputable) {
            document.getElementById('progressFill').style.width = (e.loaded/e.total*100)+'%';
          }
        };
        xhr.onload = () => {
          if(xhr.status >= 200 && xhr.status < 300) {
            document.getElementById('uploadControls').style.display = 'none';
            document.getElementById('addMoreContainer').style.display = 'block';
            
            // Append to activity log
            const activityList = document.getElementById('activityList');
            selectedFiles.forEach(f => {
              const el = document.createElement('div');
              el.className = 'activity-item animate-in';
              el.innerHTML = `
                <div class="activity-title">${f.name}</div>
                <div class="activity-meta">SENT SUCCESSFULLY — JUST NOW</div>
              `;
              activityList.prepend(el);
            });
            
            showToast('Files sent successfully!');
          } else {
            showToast('Upload failed', 'error');
            btn.disabled = false;
          }
        };
        xhr.onerror = () => { showToast('Network error', 'error'); btn.disabled = false; };
        xhr.send(formData);
      } catch(e) {
        showToast('Upload failed', 'error');
        btn.disabled = false;
      }
    });

    function resetForm() {
      if(isClosed) return;
      selectedFiles = [];
      input.value = '';
      document.getElementById('progressFill').style.width = '0%';
      document.getElementById('progressContainer').style.display = 'none';
      document.getElementById('addMoreContainer').style.display = 'none';
      document.getElementById('uploadBtn').disabled = false;
      document.getElementById('uploadForm').style.display = 'block';
    }
  </script>
</body>
</html>"""

_SESSION_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Download — SECURED MOBILE2PC ANY FILE SHARE</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { padding: 40px 24px; min-height: 100vh; display: flex; flex-direction: column; align-items: center; }
    .header { text-align: center; margin-bottom: 40px; }
    .header h1 { font-size: 1.8rem; margin-bottom: 8px; }
    
    .status-alert {
      display: none; width: 100%; max-width: 600px; padding: 16px; margin-bottom: 24px;
      border: 1px solid var(--error); background: rgba(255,51,51,0.1); color: var(--error);
      text-align: center; font-family: var(--display-font); font-weight: 800;
    }
    
    .files-container { width: 100%; max-width: 600px; display: flex; flex-direction: column; gap: 16px; }
    .file-card {
      display: flex; justify-content: space-between; align-items: center; padding: 20px;
      background: var(--bg-surface); border: 1px solid var(--border-color);
      border-left: 2px solid var(--success);
    }
    @media (max-width: 500px) {
      .file-card { flex-direction: column; align-items: flex-start; gap: 16px; }
      .file-card-actions { width: 100%; display: flex; gap: 8px; }
      .file-card-actions .btn { flex: 1; }
    }
  </style>
</head>
<body>
  <main class="page container">
    <div class="header animate-in">
      <h1 class="text-chrome">DOWNLOAD FILES</h1>
    </div>

    <div class="status-alert animate-in" id="statusAlert"></div>

    <div class="files-container" id="filesContainer">
      <!-- loaded via JS -->
    </div>
  </main>

  <div class="modal-overlay" id="imageModal" onclick="this.classList.remove('active')">
    <div class="modal-content" onclick="event.stopPropagation()">
      <img id="modalImage" src="" alt="Preview">
      <button class="btn btn-outline" onclick="document.getElementById('imageModal').classList.remove('active')">Close Preview</button>
    </div>
  </div>

  """ + _TOAST_JS + """
  <script>
    const SESSION_ID = window.location.pathname.split('/').pop().toUpperCase();
    let knownFiles = new Set();
    
    function previewImage(url) {
      document.getElementById('modalImage').src = url;
      document.getElementById('imageModal').classList.add('active');
    }
    
    setInterval(async () => {
      try {
        const res = await fetch('/api/session/' + SESSION_ID);
        const data = await res.json();
        if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
          document.getElementById('statusAlert').innerHTML = '<span class="material-icons-round" style="font-size: 14px;">block</span> SESSION ' + data.status;
          document.getElementById('statusAlert').style.display = 'block';
          return;
        }
        
        if (data.files && data.files.length > 0) {
          const container = document.getElementById('filesContainer');
          data.files.forEach(f => {
            if (!knownFiles.has(f.name)) {
              knownFiles.add(f.name);
              const el = document.createElement('div');
              el.className = 'file-card animate-in';
              
              let actions = '';
              if (f.is_image) {
                actions += `<button class="btn btn-outline btn-sm" onclick="previewImage('/api/preview/${SESSION_ID}/${encodeURIComponent(f.name)}')">PREVIEW</button>`;
              }
              actions += `<a href="/api/download/${SESSION_ID}/${encodeURIComponent(f.name)}" class="btn btn-primary btn-sm" download="${f.original_name}">DOWNLOAD</a>`;
              
              el.innerHTML = `
                <div style="min-width: 0; overflow: hidden;">
                  <div style="font-weight:800; font-family:var(--display-font); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${f.original_name}</div>
                  <div style="font-size:0.75rem; color:var(--text-muted); font-family:var(--display-font);">${f.size_formatted} — RECEIVED JUST NOW</div>
                </div>
                <div class="file-card-actions" style="display:flex; gap:8px; flex-shrink:0;">${actions}</div>
              `;
              container.appendChild(el);
            }
          });
        }
      } catch(e){}
    }, 2000);
  </script>
</body>
</html>"""

# ──────────────────────────────────────────────────────────────────────
# Page Routes
# ──────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def page_welcome():
    return _WELCOME_PAGE


@app.get("/dashboard", response_class=HTMLResponse)
async def page_dashboard():
    return _DASHBOARD_PAGE


@app.get("/send", response_class=HTMLResponse)
async def page_send():
    return _SEND_PAGE


@app.get("/receive", response_class=HTMLResponse)
async def page_receive():
    return _RECEIVE_PAGE


@app.get("/send-to/{session_id}", response_class=HTMLResponse)
async def page_send_to(session_id: str):
    sid = session_id.upper().strip()
    return _SEND_TO_PAGE.replace("{{SESSION_ID}}", sid)


@app.get("/session/{session_id}", response_class=HTMLResponse)
async def page_session(session_id: str):
    return _SESSION_PAGE


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    url = RENDER_EXTERNAL_URL or f"http://localhost:{PORT}"
    print(f"\n  {APP_NAME} v{APP_VERSION}")
    print(f"  {url}\n")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
