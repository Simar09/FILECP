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
APP_NAME = "Secure Mobile to PC"
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
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap');
  @import url('https://fonts.googleapis.com/icon?family=Material+Icons+Round');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg-primary: #000000;
    --bg-secondary: #0a0a0a;
    --bg-surface: #111111;
    --bg-surface-hover: #1a1a1a;
    --border-color: rgba(255, 255, 255, 0.1);
    --border-light: rgba(255, 255, 255, 0.2);
    --text-primary: #f0f0f0;
    --text-secondary: #a0a0a0;
    --text-muted: #666666;
    --text-bright: #ffffff;
    
    --accent: #ffffff;
    --accent-hover: #dddddd;
    --accent-subtle: rgba(255, 255, 255, 0.1);
    
    --success: #00ff66;
    --error: #ff3333;
    
    --radius-sm: 0px;
    --radius-md: 4px;
    --radius-lg: 8px;
    --transition: 0.2s ease-in-out;
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

  a { color: var(--text-primary); text-decoration: none; transition: color var(--transition); }
  a:hover { color: var(--text-bright); }

  .material-icons-round { font-family: 'Material Icons Round'; vertical-align: middle; }

  .container { max-width: 1000px; margin: 0 auto; padding: 0 32px; }
  .text-center { text-align: center; }

  .nav {
    display: none; /* Removed unnecessary top branding */
  }

  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 10px;
    padding: 12px 24px; border-radius: var(--radius-sm);
    font-family: var(--display-font); font-size: 0.9rem; font-weight: 700;
    cursor: pointer; border: 1px solid var(--border-color); transition: all var(--transition);
    text-decoration: none; white-space: nowrap; text-transform: uppercase;
    background: transparent; color: var(--text-primary);
  }
  .btn-primary {
    background: var(--text-primary);
    color: var(--bg-primary);
    border-color: var(--text-primary);
  }
  .btn-primary:hover {
    background: var(--text-bright);
    color: var(--bg-primary);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(255, 255, 255, 0.1);
  }
  .btn-outline {
    background: transparent; color: var(--text-primary);
    border-color: var(--border-color);
  }
  .btn-outline:hover {
    border-color: var(--text-bright); color: var(--text-bright);
    background: rgba(255,255,255,0.05);
  }
  .btn-danger {
    background: transparent; color: var(--error);
    border-color: var(--error);
  }
  .btn-danger:hover {
    background: var(--error); color: var(--bg-primary);
  }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none !important; box-shadow: none !important; }
  .btn .material-icons-round { font-size: 18px; }

  .card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: 32px;
    transition: transform var(--transition), border-color var(--transition);
  }
  .card-hover:hover {
    border-color: var(--border-light);
    transform: translateY(-2px);
  }

  .chip {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 6px 12px; border-radius: var(--radius-sm);
    font-size: 0.8rem; font-family: var(--display-font);
    background: var(--bg-surface); border: 1px solid var(--border-color);
    color: var(--text-secondary); text-transform: uppercase;
  }
  .chip .material-icons-round { font-size: 14px; color: var(--text-primary); }

  .input-group { display: flex; flex-direction: column; gap: 8px; }
  .input-group label {
    font-size: 0.75rem; font-family: var(--display-font); color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 0.05em;
  }
  .input-field {
    padding: 12px 16px; border-radius: var(--radius-sm);
    background: var(--bg-surface); border: 1px solid var(--border-color);
    color: var(--text-primary); font-family: var(--font); font-size: 1rem;
    transition: all var(--transition); outline: none;
  }
  .input-field:focus {
    border-color: var(--text-bright);
    background: var(--bg-surface-hover);
  }
  .input-field::placeholder { color: var(--text-muted); }

  .progress-bar {
    width: 100%; height: 4px; border-radius: var(--radius-sm);
    background: var(--bg-surface); overflow: hidden;
  }
  .progress-bar-fill {
    height: 100%; background: var(--text-primary);
    transition: width 0.3s ease;
  }

  @keyframes fadeInUp {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .animate-in { animation: fadeInUp 0.4s ease forwards; }

  .spinner {
    width: 20px; height: 20px; border: 2px solid var(--border-color);
    border-top-color: var(--text-primary); border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .toast-container {
    position: fixed; bottom: 24px; right: 24px; z-index: 9999;
    display: flex; flex-direction: column; gap: 12px;
  }
  .toast {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 16px; border-radius: var(--radius-sm);
    background: var(--bg-secondary); border: 1px solid var(--border-color);
    color: var(--text-primary); font-size: 0.9rem; font-family: var(--display-font);
    animation: fadeInUp 0.3s ease forwards;
  }
  
  .code { font-family: var(--display-font); color: var(--text-bright); }

  h1, h2, h3 { font-family: var(--display-font); font-weight: 700; }
</style>
"""

_NAV_INNER = """
<!-- Navigation removed as per requirements -->
"""

_TOAST_JS = """
<div class="toast-container" id="toastContainer"></div>
<script>
function showToast(message, type = 'success') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = 'toast';
  let icon = type === 'success' ? 'check_circle' : (type === 'error' ? 'error' : 'info');
  let color = type === 'success' ? 'var(--success)' : (type === 'error' ? 'var(--error)' : 'var(--text-primary)');
  toast.innerHTML = '<span class="material-icons-round" style="color:'+color+'">' + icon + '</span><span>' + message + '</span>';
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
  <title>Secure Mobile to PC — Secure File Sharing</title>
  """ + _SHARED_STYLES + """
  <style>
    .hero {
      min-height: 100vh;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      text-align: center; padding: 60px 24px; position: relative; overflow: hidden;
    }
    
    /* Falling pixel icons animation */
    .bg-icons {
      position: absolute; top: 0; left: 0; width: 100%; height: 100%;
      pointer-events: none; z-index: 0; overflow: hidden;
    }
    .bg-icon {
      position: absolute; top: -50px; color: rgba(255,255,255,0.03);
      font-family: 'Material Icons Round'; font-size: 32px;
      animation: fall linear infinite;
    }
    @keyframes fall {
      to { transform: translateY(110vh); }
    }
    @media (prefers-reduced-motion: reduce) {
      .bg-icon { animation: none; display: none; }
    }

    .content-wrapper { position: relative; z-index: 1; display: flex; flex-direction: column; align-items: center; }

    .hero-title {
      font-size: clamp(2.5rem, 6vw, 4.5rem);
      color: var(--text-bright); margin-bottom: 24px;
      letter-spacing: -0.02em; text-transform: uppercase;
    }
    .features-line {
      font-family: var(--display-font); font-size: 0.9rem; color: var(--text-secondary);
      margin-bottom: 48px; display: flex; flex-wrap: wrap; justify-content: center; gap: 12px;
      text-transform: uppercase;
    }
    .quote-box {
      margin-bottom: 48px; max-width: 600px;
    }
    .quote-text {
      font-size: 1.1rem; font-style: italic; color: var(--text-primary); margin-bottom: 12px;
    }
    .quote-author {
      font-family: var(--display-font); font-size: 0.85rem; color: var(--text-muted);
    }
  </style>
</head>
<body>
  <div class="bg-icons" id="bgIcons"></div>
  <main class="hero">
    <div class="content-wrapper animate-in">
      <h1 class="hero-title">Secure Mobile to PC</h1>
      <div class="features-line">
        <span>Secure file transfer</span> &bull; <span>Auto-expiry QR sharing</span> &bull; <span>Cross-platform instant sharing</span>
      </div>
      
      <div class="quote-box">
        <div class="quote-text">"Simplicity is prerequisite for reliability."</div>
        <div class="quote-author">— Edsger W. Dijkstra</div>
      </div>
      
      <a href="/dashboard" class="btn btn-primary" style="padding: 16px 40px; font-size: 1rem;">
        Get Started
      </a>
    </div>
  </main>
  
  <script>
    // Generate falling icons
    const icons = ['qr_code_2', 'lock', 'shield', 'timer', 'smartphone', 'desktop_windows', 'folder', 'upload', 'cloud_download', 'network_wifi'];
    const container = document.getElementById('bgIcons');
    if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      for(let i=0; i<30; i++) {
        let el = document.createElement('div');
        el.className = 'bg-icon';
        el.textContent = icons[Math.floor(Math.random() * icons.length)];
        el.style.left = Math.random() * 100 + 'vw';
        el.style.fontSize = (20 + Math.random() * 40) + 'px';
        el.style.opacity = (0.02 + Math.random() * 0.05).toString();
        el.style.animationDuration = (10 + Math.random() * 20) + 's';
        el.style.animationDelay = (Math.random() * -20) + 's';
        container.appendChild(el);
      }
    }
  </script>
</body>
</html>"""

_DASHBOARD_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard — Secure Mobile to PC</title>
  """ + _SHARED_STYLES + """
  <style>
    .page {
      min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px 24px;
    }
    .page-title {
      font-size: 1.2rem; color: var(--text-secondary); margin-bottom: 48px; text-transform: uppercase; letter-spacing: 0.1em;
    }
    .action-grid {
      display: grid; grid-template-columns: 1fr 1fr; gap: 32px; max-width: 800px; width: 100%;
    }
    @media (max-width: 600px) { .action-grid { grid-template-columns: 1fr; } }
    .action-card {
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      gap: 24px; padding: 64px 32px; text-decoration: none; color: var(--text-primary);
      border: 1px solid var(--border-color); border-radius: var(--radius-sm);
      background: var(--bg-secondary); transition: all var(--transition);
    }
    .action-card:hover {
      border-color: var(--text-bright); background: var(--bg-surface-hover); transform: translateY(-4px);
    }
    .action-icon {
      font-size: 48px; color: var(--text-bright);
    }
    .action-card h2 { font-size: 1.5rem; text-transform: uppercase; margin-bottom: 8px; }
  </style>
</head>
<body>
  <main class="page container">
    <div class="page-title animate-in">What would you like to do?</div>
    <div class="action-grid animate-in">
      <a href="/send" class="action-card">
        <span class="material-icons-round action-icon">upload_file</span>
        <h2>Send File</h2>
      </a>
      <a href="/receive" class="action-card">
        <span class="material-icons-round action-icon">download</span>
        <h2>Receive File</h2>
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
  <title>Send File — Secure Mobile to PC</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 40px 24px; }
    .header { text-align: center; margin-bottom: 40px; }
    .header h1 { font-size: 2rem; text-transform: uppercase; margin-bottom: 8px; }
    
    .drop-zone {
      width: 100%; max-width: 600px; border: 2px dashed var(--border-color);
      border-radius: var(--radius-sm); padding: 48px 24px; text-align: center;
      cursor: pointer; background: var(--bg-surface); transition: all var(--transition);
    }
    .drop-zone:hover { border-color: var(--text-bright); }
    
    .qr-card { max-width: 600px; width: 100%; display: none; flex-direction: column; align-items: center; gap: 24px; }
    .qr-image-wrapper { background: #fff; padding: 16px; border-radius: var(--radius-sm); border: 4px solid var(--text-primary); }
    .qr-image-wrapper img { display: block; width: 240px; height: 240px; }
    
    .status-bar { font-family: var(--display-font); font-size: 0.9rem; color: var(--text-secondary); text-transform: uppercase; }
  </style>
</head>
<body>
  <main class="page container">
    <div class="header animate-in">
      <h1>Send File</h1>
    </div>

    <form id="uploadForm" class="animate-in drop-zone" style="display: block;">
      <span class="material-icons-round" style="font-size:48px; color:var(--text-bright); margin-bottom:16px;">upload_file</span>
      <h3 style="margin-bottom:8px;">Select file to send</h3>
      <input type="file" id="fileInput" style="display:none">
      
      <div class="input-group" style="margin-top: 24px; text-align: left; max-width: 200px; margin-left: auto; margin-right: auto;" onclick="event.stopPropagation()">
        <label>Session Expiry</label>
        <select id="durationInput" class="input-field" style="appearance: auto;">
          <option value="5">5 Minutes</option>
          <option value="10" selected>10 Minutes</option>
          <option value="30">30 Minutes</option>
        </select>
      </div>
    </form>
    
    <div style="width:100%; max-width:600px; margin-top:16px; display:none;" id="uploadControls">
      <div id="fileList" style="margin-bottom:16px; font-family:var(--display-font); font-size:0.9rem; text-align:center;"></div>
      <button class="btn btn-primary" id="uploadBtn" style="width:100%;">Create Session</button>
      <div class="progress-bar" style="margin-top:16px; display:none;" id="progressContainer">
        <div class="progress-bar-fill" id="progressFill" style="width:0%"></div>
      </div>
    </div>

    <div class="qr-card animate-in" id="qrCard">
      <div class="qr-image-wrapper">
        <img id="qrImage" src="" alt="QR Code">
      </div>
      <p style="font-family: var(--display-font); font-size: 0.9rem;">Scan this QR code to download</p>
      
      <div class="status-bar" id="statusBar">
        Session active <span id="countdown"></span>
      </div>

      <button class="btn btn-danger" style="margin-top: 24px;" onclick="closeSession()" id="closeBtn">
        Close Session
      </button>
    </div>
  </main>

  """ + _TOAST_JS + """
  <script>
    const form = document.getElementById('uploadForm');
    const input = document.getElementById('fileInput');
    let selectedFile = null;
    let sessionId = null;
    let pollInterval = null;

    form.addEventListener('click', () => input.click());
    input.addEventListener('change', () => {
      if(input.files.length > 0) {
        selectedFile = input.files[0];
        document.getElementById('fileList').textContent = selectedFile.name;
        document.getElementById('uploadControls').style.display = 'block';
      }
    });

    document.getElementById('uploadBtn').addEventListener('click', async () => {
      if(!selectedFile) return;
      const btn = document.getElementById('uploadBtn');
      btn.disabled = true;
      document.getElementById('progressContainer').style.display = 'block';
      
      const formData = new FormData();
      formData.append('files', selectedFile);
      formData.append('duration', document.getElementById('durationInput').value);
      
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
            sessionId = data.session_id;
            document.getElementById('uploadForm').style.display = 'none';
            document.getElementById('uploadControls').style.display = 'none';
            document.getElementById('qrImage').src = '/api/qr/' + sessionId;
            document.getElementById('qrCard').style.display = 'flex';
            startPolling();
          } else {
            showToast('Upload failed', 'error');
            btn.disabled = false;
          }
        };
        xhr.onerror = () => { showToast('Network error', 'error'); btn.disabled = false; };
        xhr.send(formData);
      } catch(e) { showToast('Upload failed', 'error'); btn.disabled = false; }
    });

    function startPolling() {
      pollInterval = setInterval(async () => {
        try {
          const res = await fetch('/api/session/' + sessionId);
          const data = await res.json();
          if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
            document.getElementById('statusBar').textContent = 'Session ' + data.status;
            document.getElementById('qrImage').style.opacity = '0.2';
            document.getElementById('closeBtn').style.display = 'none';
            clearInterval(pollInterval);
            return;
          }
          if (data.remaining_seconds !== undefined) {
            let m = Math.floor(data.remaining_seconds / 60);
            let s = Math.floor(data.remaining_seconds % 60).toString().padStart(2, '0');
            document.getElementById('countdown').textContent = '(' + m + ':' + s + ')';
          }
        } catch(e){}
      }, 2000);
    }

    async function closeSession() {
      try {
        await fetch('/api/close-session/' + sessionId, { method: 'POST' });
        document.getElementById('statusBar').textContent = 'Session CLOSED';
        document.getElementById('qrImage').style.opacity = '0.2';
        document.getElementById('closeBtn').style.display = 'none';
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
  <title>Receive File — Secure Mobile to PC</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 60px 24px; }
    .header { text-align: center; margin-bottom: 40px; }
    .header h1 { font-size: 2rem; text-transform: uppercase; margin-bottom: 8px; }
    .header p { color: var(--text-muted); }
    
    .setup-card { max-width: 400px; width: 100%; text-align: center; }
    .qr-card { max-width: 600px; width: 100%; display: none; flex-direction: column; align-items: center; gap: 24px; }
    
    .qr-image-wrapper { background: #fff; padding: 16px; border-radius: var(--radius-sm); border: 4px solid var(--text-primary); }
    .qr-image-wrapper img { display: block; width: 240px; height: 240px; }
    
    .file-list { width: 100%; margin-top: 32px; display: flex; flex-direction: column; gap: 12px; }
    .file-item { display: flex; justify-content: space-between; align-items: center; padding: 16px; background: var(--bg-surface); border: 1px solid var(--border-color); }
    
    .status-bar { margin-top: 16px; font-family: var(--display-font); font-size: 0.9rem; color: var(--text-secondary); text-transform: uppercase; }
  </style>
</head>
<body>
  <main class="page container">
    <div class="header animate-in">
      <h1>Receive File</h1>
      <p>Generate a QR code to securely receive files</p>
    </div>

    <div class="card setup-card animate-in" id="setupCard">
      <div class="input-group" style="margin-bottom: 24px; text-align: left;">
        <label>Session Expiry</label>
        <select id="expirySelect" class="input-field" style="appearance: auto;">
          <option value="5">5 Minutes</option>
          <option value="10" selected>10 Minutes</option>
          <option value="15">15 Minutes</option>
          <option value="30">30 Minutes</option>
          <option value="60">1 Hour</option>
        </select>
      </div>
      <button class="btn btn-primary" style="width:100%; padding: 16px;" id="genBtn" onclick="createSession()">
        Generate QR Code
      </button>
    </div>

    <div class="qr-card animate-in" id="qrCard">
      <div class="qr-image-wrapper">
        <img id="qrImage" src="" alt="QR Code">
      </div>
      <p style="font-family: var(--display-font); font-size: 0.9rem;">Scan this QR code with your mobile device</p>
      
      <div class="status-bar" id="statusBar">
        Waiting for connection... <span id="countdown"></span>
      </div>

      <div class="file-list" id="fileList"></div>

      <button class="btn btn-danger" style="margin-top: 24px;" onclick="closeSession()" id="closeBtn">
        Close Session
      </button>
    </div>
  </main>
  
  """ + _TOAST_JS + """
  <script>
    let sessionId = null;
    let pollInterval = null;
    let knownFiles = new Set();

    async function createSession() {
      const btn = document.getElementById('genBtn');
      const duration = document.getElementById('expirySelect').value;
      btn.disabled = true; btn.textContent = 'Generating...';
      
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
        btn.disabled = false; btn.textContent = 'Generate QR Code';
      }
    }

    function startPolling() {
      pollInterval = setInterval(async () => {
        try {
          const res = await fetch('/api/session/' + sessionId);
          const data = await res.json();
          
          if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
            document.getElementById('statusBar').textContent = 'Session ' + data.status;
            document.getElementById('qrImage').style.opacity = '0.2';
            document.getElementById('closeBtn').style.display = 'none';
            clearInterval(pollInterval);
            return;
          }
          
          if (data.remaining_seconds !== undefined) {
            let m = Math.floor(data.remaining_seconds / 60);
            let s = Math.floor(data.remaining_seconds % 60).toString().padStart(2, '0');
            document.getElementById('countdown').textContent = '(' + m + ':' + s + ')';
          }

          if (data.files && data.files.length > 0) {
            const list = document.getElementById('fileList');
            data.files.forEach(f => {
              if (!knownFiles.has(f.name)) {
                knownFiles.add(f.name);
                const el = document.createElement('div');
                el.className = 'file-item animate-in';
                el.innerHTML = `
                  <div>
                    <div style="font-weight:700;">${f.original_name}</div>
                    <div style="font-size:0.8rem; color:var(--text-muted)">${f.size_formatted}</div>
                  </div>
                  <a href="/api/download/${sessionId}/${encodeURIComponent(f.name)}" class="btn btn-primary" download="${f.original_name}">Download</a>
                `;
                list.appendChild(el);
              }
            });
            document.getElementById('statusBar').textContent = 'Connection active ';
          }
        } catch (e) {}
      }, 2000);
    }

    async function closeSession() {
      try {
        await fetch('/api/close-session/' + sessionId, { method: 'POST' });
        document.getElementById('statusBar').textContent = 'Session CLOSED';
        document.getElementById('qrImage').style.opacity = '0.2';
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
  <title>Send Files — Secure Mobile to PC</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 40px 24px; }
    .header { text-align: center; margin-bottom: 40px; }
    .header h1 { font-size: 1.8rem; text-transform: uppercase; margin-bottom: 8px; }
    
    .drop-zone {
      width: 100%; max-width: 500px; border: 2px dashed var(--border-color);
      border-radius: var(--radius-sm); padding: 48px 24px; text-align: center;
      cursor: pointer; background: var(--bg-surface); transition: all var(--transition);
    }
    .drop-zone:hover { border-color: var(--text-bright); }
    
    .status-alert {
      display: none; width: 100%; max-width: 500px; padding: 16px; margin-bottom: 24px;
      border: 1px solid var(--error); background: rgba(255,51,51,0.1); color: var(--error);
      text-align: center; font-family: var(--display-font); font-weight: 700;
    }
    
    .success-panel {
      display: none; width: 100%; max-width: 500px; text-align: center;
      padding: 48px 24px; border: 1px solid var(--success); background: rgba(0,255,102,0.05);
      border-radius: var(--radius-sm); margin-top: 24px;
    }
    .success-panel h2 { color: var(--success); margin-bottom: 24px; }
  </style>
</head>
<body>
  <main class="page container">
    <div class="header animate-in">
      <h1>Send File</h1>
    </div>

    <div class="status-alert" id="statusAlert">Session Closed</div>

    <form id="uploadForm" class="animate-in drop-zone" style="display: block;">
      <span class="material-icons-round" style="font-size:48px; color:var(--text-bright); margin-bottom:16px;">upload_file</span>
      <h3 style="margin-bottom:8px;">Tap to select file</h3>
      <p style="font-size:0.85rem; color:var(--text-muted);">or drag and drop here</p>
      <input type="file" id="fileInput" style="display:none">
    </form>
    
    <div style="width:100%; max-width:500px; margin-top:16px; display:none;" id="uploadControls">
      <div id="fileList" style="margin-bottom:16px; font-family:var(--display-font); font-size:0.9rem;"></div>
      <button class="btn btn-primary" id="uploadBtn" style="width:100%;">Upload File</button>
      <div class="progress-bar" style="margin-top:16px; display:none;" id="progressContainer">
        <div class="progress-bar-fill" id="progressFill" style="width:0%"></div>
      </div>
    </div>

    <div class="success-panel animate-in" id="successPanel">
      <h2>File Sent Successfully</h2>
      <button class="btn btn-outline" onclick="resetForm()">Send More</button>
    </div>
  </main>

  """ + _TOAST_JS + """
  <script>
    const SESSION_ID = '{{SESSION_ID}}';
    let pollInterval = null;
    let selectedFile = null;
    let isClosed = false;

    // Check session status continuously
    setInterval(async () => {
      try {
        const res = await fetch('/api/session/' + SESSION_ID);
        const data = await res.json();
        if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
          isClosed = true;
          document.getElementById('statusAlert').style.display = 'block';
          document.getElementById('statusAlert').textContent = 'Session ' + data.status;
          document.getElementById('uploadForm').style.display = 'none';
          document.getElementById('uploadControls').style.display = 'none';
          document.getElementById('successPanel').style.display = 'none';
        }
      } catch(e){}
    }, 2000);

    const form = document.getElementById('uploadForm');
    const input = document.getElementById('fileInput');
    
    form.addEventListener('click', () => { if(!isClosed) input.click(); });
    input.addEventListener('change', () => {
      if(input.files.length > 0) {
        selectedFile = input.files[0];
        document.getElementById('fileList').textContent = selectedFile.name;
        document.getElementById('uploadControls').style.display = 'block';
        form.style.display = 'none';
      }
    });

    document.getElementById('uploadBtn').addEventListener('click', async () => {
      if(!selectedFile || isClosed) return;
      const btn = document.getElementById('uploadBtn');
      btn.disabled = true;
      document.getElementById('progressContainer').style.display = 'block';
      
      const formData = new FormData();
      formData.append('files', selectedFile);
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
            document.getElementById('successPanel').style.display = 'block';
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
      selectedFile = null;
      input.value = '';
      document.getElementById('progressFill').style.width = '0%';
      document.getElementById('progressContainer').style.display = 'none';
      document.getElementById('successPanel').style.display = 'none';
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
  <title>Download — Secure Mobile to PC</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { padding: 40px 24px; min-height: 100vh; display: flex; flex-direction: column; align-items: center; }
    .header { text-align: center; margin-bottom: 40px; }
    .header h1 { font-size: 1.8rem; text-transform: uppercase; margin-bottom: 8px; }
    
    .status-alert {
      display: none; width: 100%; max-width: 500px; padding: 16px; margin-bottom: 24px;
      border: 1px solid var(--error); background: rgba(255,51,51,0.1); color: var(--error);
      text-align: center; font-family: var(--display-font); font-weight: 700;
    }
    
    .files-container { width: 100%; max-width: 500px; display: flex; flex-direction: column; gap: 16px; }
    .file-card {
      display: flex; justify-content: space-between; align-items: center; padding: 24px;
      background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm);
    }
  </style>
</head>
<body>
  <main class="page container">
    <div class="header animate-in">
      <h1>Download File</h1>
    </div>

    <div class="status-alert animate-in" id="statusAlert"></div>

    <div class="files-container animate-in" id="filesContainer">
      <!-- loaded via JS -->
    </div>
  </main>

  """ + _TOAST_JS + """
  <script>
    const SESSION_ID = window.location.pathname.split('/').pop().toUpperCase();
    
    async function loadSession() {
      try {
        const res = await fetch('/api/session/' + SESSION_ID);
        const data = await res.json();
        
        if(data.status === 'CLOSED' || data.status === 'EXPIRED') {
          document.getElementById('statusAlert').textContent = 'Session ' + data.status;
          document.getElementById('statusAlert').style.display = 'block';
          return;
        }
        
        if (data.files && data.files.length > 0) {
          const container = document.getElementById('filesContainer');
          container.innerHTML = data.files.map(f => `
            <div class="file-card">
              <div>
                <div style="font-weight:700; margin-bottom:4px; font-family:var(--display-font);">${f.original_name}</div>
                <div style="font-size:0.8rem; color:var(--text-muted);">${f.size_formatted}</div>
              </div>
              <a href="/api/download/${SESSION_ID}/${encodeURIComponent(f.name)}" class="btn btn-primary" download="${f.original_name}">Download</a>
            </div>
          `).join('');
        }
      } catch(e) {
        document.getElementById('statusAlert').textContent = 'Error loading session';
        document.getElementById('statusAlert').style.display = 'block';
      }
    }
    
    loadSession();
    
    setInterval(async () => {
      try {
        const res = await fetch('/api/session/' + SESSION_ID);
        const data = await res.json();
        if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
          document.getElementById('statusAlert').textContent = 'Session ' + data.status;
          document.getElementById('statusAlert').style.display = 'block';
          document.getElementById('filesContainer').style.display = 'none';
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
