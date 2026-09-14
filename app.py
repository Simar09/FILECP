#!/usr/bin/env python3
"""
MOBILE2PC — Secured Crypto AnyFile Share
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
    BackgroundTasks,
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
APP_NAME = "MOBILE2PC — Secured Crypto AnyFile Share"
APP_VERSION = "2.0.0"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8000))
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL", "")
MAX_UPLOAD_SIZE = 500 * 1024 * 1024   # 500 MB total per session
MAX_SINGLE_FILE = 500 * 1024 * 1024   # 500 MB per file
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
        ".mp4": "movie", ".avi": "movie", ".mkv": "movie", ".mov": "movie", ".webm": "movie",
        ".mp3": "audio_file", ".wav": "audio_file", ".flac": "audio_file",
        ".ogg": "audio_file", ".aac": "audio_file",
        ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
        ".svg": "image", ".webp": "image", ".bmp": "image",
        ".py": "code", ".js": "code", ".html": "code", ".css": "code",
        ".java": "code", ".cpp": "code", ".c": "code", ".ts": "code",
        ".json": "data_object", ".xml": "data_object",
        ".exe": "terminal", ".msi": "terminal", ".bin": "terminal",
    }
    return icons.get(ext, "insert_drive_file")


def _is_previewable_image(filename: str) -> bool:
    return Path(filename).suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg")


def _is_previewable_video(filename: str) -> bool:
    return Path(filename).suffix.lower() in (".mp4", ".webm", ".mov")


def _is_previewable_audio(filename: str) -> bool:
    return Path(filename).suffix.lower() in (".mp3", ".wav", ".ogg", ".aac", ".flac")


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

@app.get("/healthz")
async def healthz():
    return JSONResponse({"status": "ok"})

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
    # For existing sessions, check accumulated size
    existing_total = sessions[sid]["total_size"] if existing else 0

    for upload in files:
        if not upload.filename:
            continue
        safe_name = Path(upload.filename).name
        if not safe_name:
            safe_name = "unnamed_file"
        content = await upload.read()
        file_size = len(content)

        if file_size > MAX_SINGLE_FILE:
            if not existing:
                shutil.rmtree(session_dir, ignore_errors=True)
            raise HTTPException(400, f"File '{safe_name}' exceeds 500 MB limit.")

        total_size += file_size
        if (existing_total + total_size) > MAX_UPLOAD_SIZE:
            if not existing:
                shutil.rmtree(session_dir, ignore_errors=True)
            raise HTTPException(400, "File limit reached. No more files can be shared.")

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
            "is_video": _is_previewable_video(safe_name),
            "is_audio": _is_previewable_audio(safe_name),
            "is_pdf": safe_name.lower().endswith(".pdf"),
            "mime": mimetypes.guess_type(safe_name)[0] or "application/octet-stream",
        })

    if not file_list:
        if not existing:
            shutil.rmtree(session_dir, ignore_errors=True)
        raise HTTPException(400, "No files were uploaded.")

    now = time.time()
    if existing:
        # FIXED: Append files to existing session instead of replacing
        sessions[sid]["files"].extend(file_list)
        sessions[sid]["total_size"] += total_size
        sessions[sid]["total_size_formatted"] = _format_size(sessions[sid]["total_size"])
        if note:
            sessions[sid]["note"] = note.strip()[:1000]
        sessions[sid]["waiting"] = False
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
        "file_count": len(sessions[sid]["files"]),
        "files": sessions[sid]["files"],
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
        "note": s.get("note", ""),
        "created_at": s["created_at"],
        "expires_at": s["expires_at"],
        "remaining_seconds": remaining,
        "duration_minutes": s["duration_minutes"],
        "total_size_formatted": s["total_size_formatted"],
        "download_count": s["download_count"],
        "status": s.get("status", "ACTIVE"),
        "waiting": s.get("waiting", False),
    })


@app.get("/api/download/{session_id}/{filename}")
async def api_download_file(session_id: str, filename: str):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    s = sessions[sid]
    if s.get("status") == "CLOSED":
        raise HTTPException(410, "Session is closed.")
    if time.time() > s["expires_at"]:
        raise HTTPException(410, "Session has expired.")

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
        raise HTTPException(410, "Session is closed.")
    if time.time() > s["expires_at"]:
        raise HTTPException(410, "Session has expired.")

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
async def api_download_all(session_id: str, background_tasks: BackgroundTasks):
    sid = session_id.upper().strip()
    if sid not in sessions:
        raise HTTPException(404, "Session not found or expired.")
    s = sessions[sid]
    if s.get("status") == "CLOSED":
        raise HTTPException(410, "Session is closed.")
    if time.time() > s["expires_at"]:
        raise HTTPException(410, "Session has expired.")

    fd, temp_path = tempfile.mkstemp(suffix=".zip", prefix=f"mobile2pc_{sid}_")
    os.close(fd)

    def build_zip():
        with zipfile.ZipFile(temp_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in s["files"]:
                file_path = UPLOAD_DIR / sid / f["name"]
                if file_path.exists():
                    encrypted = file_path.read_bytes()
                    decrypted = CIPHER.decrypt(encrypted)
                    zf.writestr(f["original_name"], decrypted)

    build_zip()

    s["download_count"] += 1
    
    def cleanup_temp_file(path: str):
        try:
            os.remove(path)
        except Exception:
            pass

    background_tasks.add_task(cleanup_temp_file, temp_path)

    return FileResponse(
        path=temp_path,
        media_type="application/zip",
        filename=f"mobile2pc_{sid}.zip",
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
    img = qr.make_image(fill_color="#000000", back_color="#ffffff")
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
        "mode": "receive"
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
    img = qr.make_image(fill_color="#000000", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# ──────────────────────────────────────────────────────────────────────
# Frontend Design System
# ──────────────────────────────────────────────────────────────────────

_SHARED_STYLES = """
<style>
  @import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700;800&display=swap');
  @import url('https://fonts.googleapis.com/icon?family=Material+Icons+Round');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg-surface: rgba(255, 255, 255, 0.04);
    --bg-surface-2: rgba(255, 255, 255, 0.06);
    --bg-surface-hover: rgba(255, 255, 255, 0.08);
    --border-color: rgba(255, 255, 255, 0.1);
    --border-light: rgba(255, 255, 255, 0.15);
    --border-light: #2a2a2a;
    --border-bright: #444444;

    --text-primary: #ffffff;
    --text-secondary: rgba(255, 255, 255, 0.85);
    --text-muted: rgba(255, 255, 255, 0.65);
    --text-bright: #ffffff;

    --accent: #ffffff;
    --accent-glow: rgba(255,255,255,0.08);
    --success: #00ff66;
    --success-dim: rgba(0,255,102,0.12);
    --error: #ff3333;
    --error-dim: rgba(255,51,51,0.10);
    --warning: #ffaa00;

    --radius: 4px;
    --transition: 0.15s ease-out;

    --font-mono: 'JetBrains Mono', monospace;
    --font-body: 'Inter', sans-serif;
  }

  html { scroll-behavior: smooth; }
  body {
    font-family: var(--font-body);
    background-color: #050505;
    background-image:
      radial-gradient(circle at 15% 20%, rgba(138, 43, 226, 0.18), transparent 45%),
      radial-gradient(circle at 85% 25%, rgba(0, 255, 255, 0.15), transparent 45%),
      radial-gradient(circle at 30% 80%, rgba(255, 215, 0, 0.12), transparent 40%),
      radial-gradient(circle at 75% 75%, rgba(0, 255, 128, 0.12), transparent 45%),
      radial-gradient(circle at 50% 50%, rgba(0, 102, 255, 0.15), transparent 50%);
    background-attachment: fixed;
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
    overflow-x: hidden;
  }

  /* Subtle grid background */
  body::before {
    content: '';
    position: fixed; inset: 0;
    pointer-events: none; z-index: -1;
    background-image:
      linear-gradient(rgba(255,255,255,0.012) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,0.012) 1px, transparent 1px);
    background-size: 24px 24px;
  }



  a { color: var(--text-primary); text-decoration: none; transition: color var(--transition); }
  a:hover { color: var(--text-bright); }

  .material-icons-round { font-family: 'Material Icons Round'; vertical-align: middle; }

  /* Focus states for accessibility */
  *:focus-visible {
    outline: 2px solid var(--text-bright);
    outline-offset: 2px;
  }

  .container { max-width: 680px; margin: 0 auto; padding: 0 20px; }

  /* Pure white text globally */
  .text-chrome {
    color: #ffffff;
  }

  /* ── Typography ── */
  h1, h2, h3 {
    font-family: var(--font-body);
    font-weight: 600;
    text-transform: uppercase;
    line-height: 1.6;
  }
  h1 { font-size: clamp(1.2rem, 3vw, 1.8rem); letter-spacing: 0.02em; }
  h2 { font-size: clamp(1rem, 2vw, 1.2rem); letter-spacing: 0.02em; }
  h3 { font-size: clamp(0.9rem, 1.5vw, 1rem); }

  .section-label {
    font-family: var(--font-body);
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 12px;
    line-height: 1.8;
  }

  /* ── Buttons ── */
  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 14px 24px; border-radius: 8px; /* Rounded corners */
    font-family: var(--font-body); font-size: 0.9rem; font-weight: 600;
    cursor: pointer; transition: all var(--transition);
    border: 1px solid rgba(255, 255, 255, 0.1); 
    text-transform: uppercase; letter-spacing: 0.05em;
    background: rgba(255, 255, 255, 0.03); /* Glass-like surface */
    color: var(--text-bright);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
    backdrop-filter: blur(8px);
    text-decoration: none; white-space: nowrap;
    line-height: 1.6;
  }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; pointer-events: none; }
  .btn:hover { 
    border-color: rgba(255, 255, 255, 0.3); 
    background: rgba(255, 255, 255, 0.08); 
    box-shadow: 0 4px 16px rgba(255, 255, 255, 0.1);
  }

  .btn-primary {
    background: linear-gradient(180deg, rgba(255,255,255,0.15) 0%, rgba(255,255,255,0.05) 100%);
    border: 1px solid rgba(255, 255, 255, 0.4);
    color: #fff;
    box-shadow: 0 0 15px rgba(255, 255, 255, 0.1);
  }
  .btn-primary:hover {
    background: linear-gradient(180deg, rgba(255,255,255,0.2) 0%, rgba(255,255,255,0.1) 100%);
    border-color: rgba(255, 255, 255, 0.8);
    box-shadow: 0 0 25px rgba(255, 255, 255, 0.2);
  }

  .btn-outline {
    background: rgba(255, 255, 255, 0.03); color: var(--text-primary);
    border-color: rgba(255, 255, 255, 0.15);
  }
  .btn-outline:hover {
    border-color: var(--text-bright); background: var(--accent-glow);
  }

  .btn-danger {
    background: transparent; color: var(--error); border-color: rgba(255,51,51,0.3);
  }
  .btn-danger:hover {
    background: var(--error); color: var(--bg-primary); border-color: var(--error);
    box-shadow: 0 0 20px rgba(255,51,51,0.2);
  }

  .btn-sm { padding: 10px 16px; font-size: 0.8rem; }
  .btn:disabled { opacity: 0.35; cursor: not-allowed; pointer-events: none; }
  .btn .material-icons-round { font-size: 16px; }

  .btn-row { display: flex; gap: 12px; margin-top: 16px; }
  .btn-row .btn { flex: 1; }

  /* ── Cards ── */
  .card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    padding: 28px;
    position: relative;
  }
  .card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0;
    height: 1px; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.08), transparent);
  }

  /* ── Inputs ── */
  .input-field {
    padding: 12px 14px;
    margin-bottom: 24px;
    background: var(--bg-surface); border: 1px solid var(--border-color);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border-radius: 12px;
    color: var(--text-bright); font-family: var(--font-mono); font-size: 0.9rem;
    transition: all var(--transition); outline: none; width: 100%;
  }
  .input-field:focus { border-color: var(--border-bright); box-shadow: 0 0 0 1px var(--border-light); }

  select.input-field {
    appearance: none; -webkit-appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%23808080' stroke-width='2' fill='none'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 12px center;
    padding-right: 36px;
    cursor: pointer;
    font-family: var(--font-body); font-size: 0.9rem; font-weight: 500;
    line-height: 1.6;
  }

  /* ── Drop Zone ── */
  .drop-zone {
    width: 100%;
    border: 2px dashed var(--border-light); border-radius: 12px;
    padding: 48px 24px; text-align: center; cursor: pointer;
    background: var(--bg-surface); transition: all var(--transition);
    position: relative;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
  }
  .drop-zone::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0;
    height: 2px; background: var(--text-bright);
  }
  .drop-zone:hover { border-color: var(--border-bright); background: var(--bg-surface-hover); }
  .drop-zone.drag-over {
    border-color: var(--text-bright); border-style: solid;
    background: rgba(255,255,255,0.03);
    box-shadow: inset 0 0 30px rgba(255,255,255,0.03);
  }
  .drop-zone-icon { font-size: 40px; color: var(--text-muted); margin-bottom: 16px; }
  .drop-zone-title { font-family: var(--font-body); font-size: 1rem; font-weight: 600; color: var(--text-secondary);
    text-transform: uppercase; margin-bottom: 8px; line-height: 1.8; }
  .drop-zone-sub { font-size: 0.85rem; color: var(--text-muted); }

  /* ── File List Items ── */
  .file-list { display: flex; flex-direction: column; }
  .file-item {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 14px; background: var(--bg-surface);
    border: 1px solid var(--border-color); border-radius: 8px;
    margin-bottom: 8px;
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    font-family: var(--font-mono); font-size: 0.8rem;
    transition: background var(--transition);
  }
  .file-item:first-child { border-top: 1px solid var(--border-color); }
  .file-item:hover { background: var(--bg-surface-hover); }
  .file-item-icon { color: var(--text-muted); font-size: 18px; flex-shrink: 0; }
  .file-item-name {
    flex: 1; min-width: 0; white-space: nowrap; overflow: hidden;
    text-overflow: ellipsis; color: var(--text-bright); font-weight: 500;
  }
  .file-item-size { color: var(--text-secondary); font-size: 0.75rem; flex-shrink: 0; }
  .file-item-ext {
    font-family: var(--font-body); font-size: 0.7rem; font-weight: 600;
    padding: 3px 6px; background: rgba(255,255,255,0.04); border-radius: 4px;
    border: 1px solid var(--border-color); color: var(--text-muted);
    text-transform: uppercase; flex-shrink: 0; line-height: 1.6;
  }
  .file-item-remove {
    background: none; border: none; color: var(--text-muted);
    cursor: pointer; font-size: 18px; padding: 2px; flex-shrink: 0;
    transition: color var(--transition); display: flex; align-items: center;
  }
  .file-item-remove:hover { color: var(--error); }
  .file-summary {
    font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);
    padding: 10px 14px; background: var(--bg-surface); border: 1px solid var(--border-color);
    border-top: none;
  }

  /* ── Duration Selector ── */
  .duration-row {
    display: flex; gap: 12px; align-items: stretch;
  }
  .duration-row .input-field:first-child { flex: 0 0 100px; text-align: center; }
  .duration-row select.input-field { flex: 1; }
  .duration-error {
    font-family: var(--font-body); font-size: 0.8rem; font-weight: 500; color: var(--error);
    margin-top: 8px; line-height: 1.6; display: none;
  }

  /* ── QR Panel ── */
  .qr-panel { display: flex; flex-direction: column; align-items: center; gap: 16px; margin-bottom: 24px; }
  .qr-frame {
    background: #ffffff; padding: 16px;
    border-radius: 8px; margin-bottom: 16px;
    display: inline-block;
    box-shadow: 0 0 40px rgba(255,255,255,0.06);
    position: relative;
  }
  .qr-frame::before {
    content: ''; position: absolute; top: -7px; left: -7px;
    width: 14px; height: 14px;
    border-top: 3px solid var(--text-bright);
    border-left: 3px solid var(--text-bright);
  }
  .qr-frame::after {
    content: ''; position: absolute; bottom: -7px; right: -7px;
    width: 14px; height: 14px;
    border-bottom: 3px solid var(--text-bright);
    border-right: 3px solid var(--text-bright);
  }
  .qr-frame img { display: block; width: 220px; height: 220px; image-rendering: pixelated; }
  .qr-label {
    font-family: var(--font-body); font-size: 0.85rem; font-weight: 600;
    color: var(--text-muted); text-transform: uppercase;
    letter-spacing: 0.04em; line-height: 1.8;
  }

  /* ── Status Badge ── */
  .status-badge {
    display: inline-flex; align-items: center; gap: 8px; padding: 10px 18px;
    font-family: var(--font-body); font-size: 0.85rem; font-weight: 600; text-transform: uppercase;
    border: 1px solid var(--border-color); background: var(--bg-surface); border-radius: 20px;
    letter-spacing: 0.02em; line-height: 1.6; margin-bottom: 20px;
  }
  .status-dot {
    width: 6px; height: 6px; display: inline-block;
  }
  .status-dot.active { background: var(--success); box-shadow: 0 0 6px var(--success); }
  .status-dot.waiting { background: var(--warning); animation: blink 1.5s ease-in-out infinite; }
  .status-dot.closed { background: var(--error); }
  @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }

  /* ── Empty State ── */
  .empty-state {
    text-align: center; padding: 40px 20px; color: var(--text-muted);
  }
  .empty-state .material-icons-round { font-size: 36px; margin-bottom: 12px; display: block; }
  .empty-state-title {
    font-family: var(--font-body); font-size: 1rem; font-weight: 600;
    text-transform: uppercase; margin-bottom: 8px; line-height: 1.8;
    color: var(--text-secondary);
  }
  .empty-state-sub { font-size: 0.8rem; color: var(--text-muted); }

  /* ── Session Ended Overlay ── */
  .session-ended {
    position: fixed; inset: 0; z-index: 9999;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    background: var(--bg-primary); text-align: center; padding: 24px;
  }
  .session-ended .material-icons-round { font-size: 48px; color: var(--error); margin-bottom: 16px; }
  .session-ended h2 {
    font-family: var(--font-body); font-size: 1.2rem; font-weight: 600;
    margin-bottom: 16px; color: var(--error); line-height: 1.8;
  }
  .session-ended p { color: var(--text-secondary); margin-bottom: 8px; font-size: 0.85rem; }
  .session-ended .sub { color: var(--text-muted); font-size: 0.75rem; }

  /* ── Progress Bar ── */
  .progress-bar { width: 100%; height: 3px; background: var(--border-color); overflow: hidden; margin-top: 12px; }
  .progress-bar-fill { height: 100%; background: var(--text-bright); transition: width 0.2s linear; width: 0%; }

  /* ── Modal ── */
  .modal-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,0.92); z-index: 10000;
    display: none; align-items: center; justify-content: center; padding: 24px;
    backdrop-filter: blur(4px);
  }
  .modal-overlay.active { display: flex; }
  .modal-content {
    background: var(--bg-surface); border: 1px solid var(--border-light);
    padding: 24px; border-radius: 12px; text-align: center; max-width: 90%;
    box-shadow: 0 10px 40px rgba(0,0,0,0.8);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    display: flex; flex-direction: column;
    align-items: center; gap: 16px;
  }
  .modal-content img { max-width: 100%; max-height: 80vh; object-fit: contain; border: 1px solid var(--border-color); }
  .modal-content video { max-width: 100%; max-height: 80vh; border: 1px solid var(--border-color); background: #000; }
  .modal-content audio { width: 100%; max-width: 400px; }

  /* ── Toast ── */
  .toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 10001; display: flex; flex-direction: column; gap: 10px; }
  .toast {
    display: flex; align-items: center; gap: 10px; padding: 12px 18px;
    background: var(--bg-surface); border: 1px solid var(--border-light);
    color: var(--text-bright); font-size: 0.8rem; font-family: var(--font-mono);
    box-shadow: 0 8px 24px rgba(0,0,0,0.6);
    animation: slideUp 0.3s ease forwards;
  }

  /* ── Animations ── */
  @keyframes fadeInUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes slideUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
  .animate-in { animation: fadeInUp 0.4s ease forwards; }

  /* ── Back Link ── */
  .back-link {
    font-family: var(--font-body); font-size: 0.85rem; font-weight: 600;
    color: var(--text-muted); text-transform: uppercase;
    letter-spacing: 0.04em; margin-bottom: 24px; display: inline-block;
    transition: color var(--transition); line-height: 1.8;
  }
  .back-link:hover { color: var(--text-bright); }

  /* ── Spinner ── */
  .spinner {
    width: 18px; height: 18px; border: 2px solid var(--border-color);
    border-top-color: var(--text-primary);
    animation: spin 0.8s linear infinite; display: inline-block;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── File Card (mobile) ── */
  .file-card {
    background: var(--bg-surface); border: 1px solid var(--border-color);
    padding: 16px; margin-bottom: 8px; position: relative;
    border-left: 2px solid var(--success);
  }
  .file-card-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
  .file-card-icon { color: var(--text-muted); font-size: 22px; }
  .file-card-info { flex: 1; min-width: 0; }
  .file-card-name {
    font-family: var(--font-mono); font-weight: 700; font-size: 0.85rem;
    color: var(--text-bright); white-space: nowrap; overflow: hidden;
    text-overflow: ellipsis;
  }
  .file-card-meta {
    font-size: 0.7rem; color: var(--text-muted); font-family: var(--font-mono);
    display: flex; align-items: center; gap: 8px; margin-top: 2px;
  }
  .file-card-actions { display: flex; gap: 8px; margin-top: 12px; }
  .file-card-actions .btn { flex: 1; }

  /* ── Responsive ── */
  @media (max-width: 600px) {
    .container { padding: 0 16px; }
    .card { padding: 20px; }
    .drop-zone { padding: 32px 16px; }
    .qr-frame img { width: 180px; height: 180px; }
    .btn-row { flex-direction: column; }
    h1 { font-size: 0.8rem; }
  }
</style>
"""

_TOAST_JS = """
<div class="toast-container" id="toastContainer"></div>
<script>
function showToast(message, type = 'success') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = 'toast';
  let icon = type === 'success' ? 'check_circle' : (type === 'error' ? 'error' : 'info');
  let color = type === 'success' ? 'var(--success)' : (type === 'error' ? 'var(--error)' : 'var(--text-bright)');
  toast.innerHTML = '<span class="material-icons-round" style="color:'+color+'; font-size:16px;">' + icon + '</span><span>' + message + '</span>';
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateY(10px)'; toast.style.transition = '0.3s ease'; setTimeout(() => toast.remove(), 300); }, 3500);
}

function toggleZoom(e, img) {
  if (img.style.transform === 'scale(2)') {
    img.style.transform = 'scale(1)';
    img.style.cursor = 'zoom-in';
  } else {
    const rect = img.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 100;
    const y = ((e.clientY - rect.top) / rect.height) * 100;
    img.style.transformOrigin = `${x}% ${y}%`;
    img.style.transform = 'scale(2)';
    img.style.cursor = 'zoom-out';
  }
}

const FileDownloadService = {
  async download(url, suggestedName) {
    try {
      showToast('Preparing download...', 'info');
      const res = await fetch(url);
      if (!res.ok) throw new Error('Download failed');
      
      let filename = suggestedName;
      const disposition = res.headers.get('Content-Disposition');
      if (disposition && disposition.indexOf('filename=') !== -1) {
        const match = disposition.match(/filename="?([^"]+)"?/);
        if (match && match[1]) filename = match[1];
      }

      const blob = await res.blob();
      
      if (window.showSaveFilePicker) {
        try {
          const handle = await window.showSaveFilePicker({
            suggestedName: filename
          });
          const writable = await handle.createWritable();
          await writable.write(blob);
          await writable.close();
          showToast('File saved successfully', 'success');
          return;
        } catch (err) {
          if (err.name !== 'AbortError') {
            showToast('Unable to save the file. Please try again.', 'error');
          } else {
            showToast('Save cancelled', 'info');
          }
          return;
        }
      } else {
        // Fallback for browsers that don't support showSaveFilePicker
        this.saveLocally(url, filename);
      }
    } catch (e) {
      showToast(e.message || 'Download failed', 'error');
    }
  },
  
  async saveLocally(url, suggestedName) {
    try {
      showToast('Starting download...', 'info');
      const res = await fetch(url);
      if (!res.ok) throw new Error('Download failed');
      
      let filename = suggestedName;
      const disposition = res.headers.get('Content-Disposition');
      if (disposition && disposition.indexOf('filename=') !== -1) {
        const match = disposition.match(/filename="?([^"]+)"?/);
        if (match && match[1]) filename = match[1];
      }

      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = objectUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(objectUrl);
      }, 100);
      showToast('Download complete', 'success');
    } catch (e) {
      showToast(e.message || 'Download failed', 'error');
    }
  }
};
</script>
"""

# ──────────────────────────────────────────────────────────────────────
# Page Templates
# ──────────────────────────────────────────────────────────────────────

_WELCOME_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="MOBILE2PC — Secured Crypto AnyFile Share. Transfer any file securely between mobile and PC using encrypted QR-code sessions.">
  <title>MOBILE2PC — Secured Crypto AnyFile Share</title>
  """ + _SHARED_STYLES + """
  <style>
    body {
      /* Uses global shared background */
    }
    .hero {
      min-height: 100vh; display: flex; flex-direction: column;
      align-items: center; justify-content: center;
      text-align: center; padding: 60px 24px;
      position: relative;
    }
    .hero::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.35);
      z-index: 0;
    }
    .content-wrapper {
      position: relative; z-index: 1;
      display: flex; flex-direction: column; align-items: center;
      max-width: 900px;
    }
    .hero-brand {
      font-family: "Times New Roman", Times, serif;
      font-size: clamp(48pt, 8vw, 72pt);
      font-weight: bold;
      line-height: 1.1;
      margin-bottom: 8px;
      color: #ffffff;
      text-align: center;
      text-shadow: 0 4px 12px rgba(0,0,0,0.5);
    }
    .hero-subbrand {
      font-family: "Times New Roman", Times, serif;
      font-size: clamp(36pt, 6vw, 48pt);
      font-weight: bold;
      line-height: 1.2;
      margin-bottom: 40px;
      color: #ffffff;
      text-align: center;
      text-shadow: 0 4px 12px rgba(0,0,0,0.5);
    }
    .features-list {
      font-family: "Times New Roman", Times, serif;
      font-size: clamp(12pt, 1.8vw, 20pt);
      color: #ffffff;
      margin-bottom: 56px;
      display: flex;
      flex-direction: row;
      flex-wrap: nowrap;
      white-space: nowrap;
      justify-content: center;
      align-items: center;
      gap: 12px;
      text-align: center;
    }
    .features-list span {
      white-space: nowrap;
    }
    .features-list .bullet {
      margin: 0 8px;
    }
    .hero-quote {
      font-family: "Times New Roman", Times, serif;
      font-size: clamp(16pt, 3vw, 24pt);
      color: #ffffff;
      margin-bottom: 48px;
      font-style: italic;
      text-align: center;
    }
    .hero-quote-author {
      display: block;
      margin-top: 12px;
      font-style: normal;
      font-size: clamp(14pt, 2.5vw, 20pt);
    }
    .hero-cta {
      padding: 18px 48px; font-size: 0.6rem;
    }
  </style>
</head>
<body>
  <main class="hero">
    <div class="content-wrapper animate-in">
      <div class="hero-brand">Mobile2PC</div>
      <div class="hero-subbrand">Secured Crypto AnyFile Share</div>

      <div class="features-list">
        <span>Encrypted Transfer</span><span class="bullet">&bull;</span>
        <span>QR Session</span><span class="bullet">&bull;</span>
        <span>Any File Type</span><span class="bullet">&bull;</span>
        <span>Cross Platform</span>
      </div>

      <div class="hero-quote">
        "Simplicity is prerequisite for reliability."
        <span class="hero-quote-author">&mdash; Edsger W. Dijkstra</span>
      </div>

      <a href="/dashboard" class="btn btn-primary hero-cta">
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
  <title>Dashboard — MOBILE2PC</title>
  """ + _SHARED_STYLES + """
  <style>
    .page {
      min-height: 100vh; display: flex; flex-direction: column;
      align-items: center; justify-content: center; padding: 40px 24px;
    }
    .page-brand {
      font-family: var(--font-body); font-size: 1.2rem; font-weight: 600;
      color: var(--text-muted); text-transform: uppercase;
      letter-spacing: 0.08em; margin-bottom: 8px; line-height: 2;
    }
    .page-title {
      font-family: var(--font-body); font-size: 1.5rem; font-weight: bold;
      color: var(--text-bright); margin-bottom: 48px;
      text-transform: none; letter-spacing: normal; line-height: 1.5;
    }
    .action-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; max-width: 740px; width: 100%; }
    @media (max-width: 600px) { .action-grid { grid-template-columns: 1fr; } }

    .action-card {
      display: flex; flex-direction: column; align-items: flex-start;
      padding: 24px; border-radius: 12px;
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      text-decoration: none; color: var(--text-primary);
      box-shadow: 0 4px 12px rgba(0,0,0,0.5);
      transition: all var(--transition); position: relative; overflow: hidden;
    }
    .action-card:hover {
      border-color: var(--border-light); background: var(--bg-surface-hover);
      box-shadow: 0 8px 24px rgba(0,0,0,0.8);
      transform: translateY(-2px);
    }

    .action-icon { font-size: 32px; color: var(--text-bright); margin-bottom: 20px; }
    .action-card h2 {
      font-family: var(--font-body); font-size: 1.4rem; font-weight: 600;
      color: var(--text-bright);
      text-transform: none; margin-bottom: 16px; letter-spacing: normal;
      line-height: 1.2;
    }
    .action-features {
      list-style: none; display: flex; flex-direction: column; gap: 10px;
      font-size: 0.95rem; color: var(--text-secondary); font-family: var(--font-body);
    }
    .action-features li { display: flex; align-items: center; gap: 8px; }
    .action-features li .material-icons-round { font-size: 16px; color: var(--text-muted); }
  </style>
</head>
<body>
  <main class="page">
    <div class="page-brand animate-in">MOBILE2PC</div>
    <div class="page-title animate-in">Choose what you want to do</div>

    <div class="action-grid animate-in" style="animation-delay: 0.1s;">
      <a href="/send" class="action-card" id="sendCard">
        <span class="material-icons-round action-icon">upload</span>
        <h2 class="text-chrome">Send File</h2>
        <ul class="action-features">
          <li><span class="material-icons-round">chevron_right</span> Select files or folders</li>
          <li><span class="material-icons-round">chevron_right</span> Generate QR session</li>
          <li><span class="material-icons-round">chevron_right</span> Mobile downloads via QR</li>
          <li><span class="material-icons-round">chevron_right</span> Add files mid-session</li>
        </ul>
      </a>
      <a href="/receive" class="action-card" id="receiveCard">
        <span class="material-icons-round action-icon">download</span>
        <h2 class="text-chrome">Receive File</h2>
        <ul class="action-features">
          <li><span class="material-icons-round">chevron_right</span> Generate receive session</li>
          <li><span class="material-icons-round">chevron_right</span> Mobile uploads via QR</li>
          <li><span class="material-icons-round">chevron_right</span> Preview & download</li>
          <li><span class="material-icons-round">chevron_right</span> Any file type accepted</li>
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
  <title>Send File — MOBILE2PC</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 32px 20px; }
    .header { text-align: center; margin-bottom: 28px; width: 100%; max-width: 620px; }
    .header h1 { color: var(--text-bright); font-family: var(--font-body); font-weight: bold; }
    .state-panel { width: 100%; max-width: 620px; }
    .sent-file-list { margin-bottom: 16px; }
    .add-more-section { margin-bottom: 16px; }
    .add-more-section .section-label { margin-top: 16px; }
  </style>
</head>
<body>
  <main class="page container">
    <div class="header animate-in">
      <a href="/dashboard" class="back-link">← DASHBOARD</a>
      <h1 class="text-chrome">SEND FILES</h1>
    </div>

    <!-- ═══ STATE: EMPTY ═══ -->
    <div class="state-panel animate-in" id="stateEmpty">
      <div class="drop-zone" id="dropZone">
        <span class="material-icons-round drop-zone-icon">cloud_upload</span>
        <div class="drop-zone-title">Drag & Drop Files Here</div>
        <div class="drop-zone-sub">or click to select files</div>
        <input type="file" id="fileInput" multiple style="display:none">
      </div>
    </div>

    <!-- ═══ STATE: FILES SELECTED ═══ -->
    <div class="state-panel" id="stateFilesSelected" style="display:none">
      <div class="section-label">SELECTED FILES</div>
      <div class="file-list" id="fileList"></div>
      <div class="file-summary" id="fileSummary"></div>

      <div style="margin-top: 12px;">
        <div class="drop-zone" id="dropZoneAdd" style="padding: 20px 16px; border-top-width: 1px;">
          <div class="drop-zone-sub" style="font-size: 0.75rem;">+ Drop more files or click to add</div>
          <input type="file" id="fileInputAdd" multiple style="display:none">
        </div>
      </div>

      <div class="btn-row">
        <button class="btn btn-primary" id="continueBtn" onclick="continueToConfig()">CONTINUE</button>
        <button class="btn btn-outline" onclick="cancelSelection()">CANCEL</button>
      </div>
    </div>

    <!-- ═══ STATE: SESSION CONFIG ═══ -->
    <div class="state-panel" id="stateSessionConfig" style="display:none">
      <div class="card">
        <div class="section-label">SESSION DURATION</div>
        <div class="duration-row">
          <input type="number" id="durationValue" class="input-field" value="30" min="1" max="60">
          <select id="durationUnit" class="input-field">
            <option value="minutes">MINUTES</option>
            <option value="hours">HOURS</option>
          </select>
        </div>
        <div class="duration-error" id="durationError"></div>

        <div class="section-label" style="margin-top: 20px; margin-bottom: 0;">
          FILES: <span id="configFileCount">0</span> &nbsp;|&nbsp;
          TOTAL: <span id="configFileSize">0 B</span>
        </div>
      </div>

      <div class="btn-row">
        <button class="btn btn-primary" id="createQrBtn" onclick="createQRCode()">
          CREATE QR CODE
        </button>
        <button class="btn btn-outline" onclick="backToFiles()">BACK</button>
      </div>
      <div class="progress-bar" id="createProgress" style="display:none">
        <div class="progress-bar-fill" id="createProgressFill"></div>
      </div>
    </div>

    <!-- ═══ STATE: QR ACTIVE ═══ -->
    <div class="state-panel" id="stateQrActive" style="display:none">
      <div class="qr-panel">
        <div class="qr-frame">
          <img id="qrImage" src="" alt="QR Code">
        </div>
        <div class="qr-label">SCAN WITH MOBILE DEVICE</div>
      </div>

      <div style="text-align:center; margin-bottom: 20px;">
        <div class="status-badge" id="statusBadge">
          <span class="status-dot active"></span>
          SESSION ACTIVE <span id="countdown"></span>
        </div>
      </div>

      <div class="section-label">FILES IN SESSION</div>
      <div class="file-list sent-file-list" id="sentFileList"></div>

      <input type="file" id="addFileInput" multiple style="display:none">

      <div class="add-more-section" id="addMoreSection" style="display:none">
        <div class="section-label">ADDITIONAL FILES</div>
        <div class="file-list" id="additionalFileList"></div>
        <div class="btn-row">
          <button class="btn btn-primary btn-sm" onclick="uploadAdditionalFiles()" id="uploadAddBtn">UPLOAD</button>
          <button class="btn btn-outline btn-sm" onclick="cancelAdditionalFiles()">CANCEL</button>
        </div>
        <div class="progress-bar" id="addProgress" style="display:none">
          <div class="progress-bar-fill" id="addProgressFill"></div>
        </div>
      </div>

      <button class="btn btn-outline" id="addMoreBtn" onclick="addMoreFiles()" style="width:100%; border-style: dashed;">
        <span class="material-icons-round">add</span> ADD MORE FILES
      </button>

      <button class="btn btn-danger" onclick="closeSession()" id="closeBtn" style="width:100%; margin-top: 12px;">
        CLOSE SESSION
      </button>
    </div>
  </main>

  """ + _TOAST_JS + """
  <script>
    /* ── State Management ── */
    let selectedFiles = [];
    let sessionId = null;
    let sentFiles = [];
    let additionalFiles = [];
    let pollInterval = null;
    let sessionExpiresAt = null;
    let durationMinutes = 30;

    function showState(state) {
      ['stateEmpty','stateFilesSelected','stateSessionConfig','stateQrActive'].forEach(id => {
        document.getElementById(id).style.display = 'none';
      });
      document.getElementById('state' + state).style.display = 'block';
    }

    function formatSize(bytes) {
      const units = ['B','KB','MB','GB','TB'];
      let i = 0;
      let size = bytes;
      while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
      return size.toFixed(1) + ' ' + units[i];
    }

    function getExt(name) {
      const parts = name.split('.');
      return parts.length > 1 ? parts.pop().toUpperCase() : '—';
    }

    function getIcon(name) {
      const ext = name.split('.').pop().toLowerCase();
      const map = {
        pdf:'picture_as_pdf', doc:'description', docx:'description',
        xls:'table_chart', xlsx:'table_chart', ppt:'slideshow', pptx:'slideshow',
        txt:'article', md:'article', csv:'article',
        zip:'folder_zip', rar:'folder_zip', '7z':'folder_zip', tar:'folder_zip', gz:'folder_zip',
        mp4:'movie', avi:'movie', mkv:'movie', mov:'movie', webm:'movie',
        mp3:'audio_file', wav:'audio_file', flac:'audio_file', ogg:'audio_file',
        png:'image', jpg:'image', jpeg:'image', gif:'image', svg:'image', webp:'image', bmp:'image',
        py:'code', js:'code', html:'code', css:'code', java:'code', ts:'code', cpp:'code',
        json:'data_object', xml:'data_object',
        exe:'terminal', msi:'terminal', bin:'terminal',
      };
      return map[ext] || 'insert_drive_file';
    }

    /* ── File Selection (Empty State) ── */
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    let dragCounter = 0;

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragenter', e => { e.preventDefault(); dragCounter++; dropZone.classList.add('drag-over'); });
    dropZone.addEventListener('dragleave', () => { dragCounter--; if (dragCounter === 0) dropZone.classList.remove('drag-over'); });
    dropZone.addEventListener('dragover', e => e.preventDefault());
    dropZone.addEventListener('drop', e => { e.preventDefault(); dragCounter = 0; dropZone.classList.remove('drag-over'); handleFiles(e.dataTransfer.files); });
    fileInput.addEventListener('change', () => { if (fileInput.files.length) handleFiles(fileInput.files); });

    /* ── File Selection (Add more in FilesSelected state) ── */
    const dropZoneAdd = document.getElementById('dropZoneAdd');
    const fileInputAdd = document.getElementById('fileInputAdd');
    let dragCounterAdd = 0;

    dropZoneAdd.addEventListener('click', e => { e.stopPropagation(); fileInputAdd.click(); });
    dropZoneAdd.addEventListener('dragenter', e => { e.preventDefault(); e.stopPropagation(); dragCounterAdd++; dropZoneAdd.classList.add('drag-over'); });
    dropZoneAdd.addEventListener('dragleave', e => { e.stopPropagation(); dragCounterAdd--; if (dragCounterAdd === 0) dropZoneAdd.classList.remove('drag-over'); });
    dropZoneAdd.addEventListener('dragover', e => { e.preventDefault(); e.stopPropagation(); });
    dropZoneAdd.addEventListener('drop', e => { e.preventDefault(); e.stopPropagation(); dragCounterAdd = 0; dropZoneAdd.classList.remove('drag-over'); handleFiles(e.dataTransfer.files); });
    fileInputAdd.addEventListener('change', () => { if (fileInputAdd.files.length) handleFiles(fileInputAdd.files); });

    function handleFiles(newFiles) {
      for (const file of newFiles) {
        if (!selectedFiles.some(f => f.name === file.name && f.size === file.size && f.lastModified === file.lastModified)) {
          selectedFiles.push(file);
        }
      }
      renderFileList();
      if (selectedFiles.length > 0) showState('FilesSelected');
    }

    function removeFile(index) {
      selectedFiles.splice(index, 1);
      renderFileList();
      if (selectedFiles.length === 0) {
        showState('Empty');
        fileInput.value = '';
        fileInputAdd.value = '';
      }
    }

    function renderFileList() {
      const list = document.getElementById('fileList');
      const totalSize = selectedFiles.reduce((a, f) => a + f.size, 0);
      list.innerHTML = selectedFiles.map((f, i) => `
        <div class="file-item">
          <span class="material-icons-round file-item-icon">${getIcon(f.name)}</span>
          <span class="file-item-name" title="${f.name}">${f.name}</span>
          <span class="file-item-size">${formatSize(f.size)}</span>
          <span class="file-item-ext">${getExt(f.name)}</span>
          <button class="file-item-remove" onclick="removeFile(${i})" title="Remove file" aria-label="Remove ${f.name}">
            <span class="material-icons-round">close</span>
          </button>
        </div>
      `).join('');
      document.getElementById('fileSummary').textContent =
        selectedFiles.length + ' file' + (selectedFiles.length !== 1 ? 's' : '') + ' — ' + formatSize(totalSize);
    }

    /* ── Continue / Cancel ── */
    function continueToConfig() {
      if (!selectedFiles.length) return;
      document.getElementById('configFileCount').textContent = selectedFiles.length;
      document.getElementById('configFileSize').textContent =
        formatSize(selectedFiles.reduce((a, f) => a + f.size, 0));
      showState('SessionConfig');
    }

    function cancelSelection() {
      selectedFiles = [];
      fileInput.value = '';
      fileInputAdd.value = '';
      showState('Empty');
    }

    function backToFiles() {
      showState('FilesSelected');
    }

    /* ── Duration Validation ── */
    function validateDuration() {
      const val = parseInt(document.getElementById('durationValue').value);
      const unit = document.getElementById('durationUnit').value;
      const errEl = document.getElementById('durationError');

      if (isNaN(val) || val < 1 || val > 60) {
        errEl.textContent = 'ENTER A VALUE BETWEEN 1 AND 60';
        errEl.style.display = 'block';
        return null;
      }
      if (unit === 'hours' && val > 24) {
        errEl.textContent = 'MAXIMUM 24 HOURS (1440 MINUTES)';
        errEl.style.display = 'block';
        return null;
      }
      errEl.style.display = 'none';
      return unit === 'hours' ? val * 60 : val;
    }

    /* ── Create QR Code ── */
    async function createQRCode() {
      if (!selectedFiles.length) return;
      const minutes = validateDuration();
      if (minutes === null) return;
      durationMinutes = minutes;

      const btn = document.getElementById('createQrBtn');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> CREATING...';
      document.getElementById('createProgress').style.display = 'block';

      const formData = new FormData();
      selectedFiles.forEach(f => formData.append('files', f));
      formData.append('duration', minutes);

      try {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload');
        xhr.upload.onprogress = e => {
          if (e.lengthComputable) {
            document.getElementById('createProgressFill').style.width = (e.loaded / e.total * 100) + '%';
          }
        };
        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            const data = JSON.parse(xhr.responseText);
            sessionId = data.session_id;
            sentFiles = data.files || [];
            sessionExpiresAt = data.expires_at;

            document.getElementById('qrImage').src = '/api/qr/' + sessionId;
            renderSentFileList();
            showState('QrActive');
            startPolling();
            showToast('Session created — QR code ready');
          } else {
            let msg = 'Upload failed';
            try { msg = JSON.parse(xhr.responseText).detail || msg; } catch(e) {}
            showToast(msg, 'error');
            btn.disabled = false;
            btn.textContent = 'CREATE QR CODE';
          }
          document.getElementById('createProgress').style.display = 'none';
          document.getElementById('createProgressFill').style.width = '0%';
        };
        xhr.onerror = () => {
          showToast('NETWORK ERROR — Check your connection', 'error');
          btn.disabled = false;
          btn.textContent = 'CREATE QR CODE';
          document.getElementById('createProgress').style.display = 'none';
        };
        xhr.send(formData);
      } catch (e) {
        showToast('Upload failed', 'error');
        btn.disabled = false;
        btn.textContent = 'CREATE QR CODE';
      }
    }

    function renderSentFileList() {
      const list = document.getElementById('sentFileList');
      list.innerHTML = sentFiles.map(f => `
        <div class="file-item">
          <span class="material-icons-round file-item-icon">${f.icon}</span>
          <span class="file-item-name">${f.original_name}</span>
          <span class="file-item-size">${f.size_formatted}</span>
          <span class="file-item-ext">${f.original_name.split('.').pop().toUpperCase()}</span>
        </div>
      `).join('');
    }

    /* ── Add More Files (QR Active State) ── */
    const addFileInput = document.getElementById('addFileInput');
    addFileInput.addEventListener('change', () => {
      if (addFileInput.files.length) {
        additionalFiles = Array.from(addFileInput.files);
        renderAdditionalFileList();
        document.getElementById('addMoreSection').style.display = 'block';
        document.getElementById('addMoreBtn').style.display = 'none';
      }
    });

    function addMoreFiles() {
      addFileInput.value = '';
      addFileInput.click();
    }

    function renderAdditionalFileList() {
      const list = document.getElementById('additionalFileList');
      list.innerHTML = additionalFiles.map((f, i) => `
        <div class="file-item">
          <span class="material-icons-round file-item-icon">${getIcon(f.name)}</span>
          <span class="file-item-name">${f.name}</span>
          <span class="file-item-size">${formatSize(f.size)}</span>
          <span class="file-item-ext">${getExt(f.name)}</span>
        </div>
      `).join('');
    }

    function cancelAdditionalFiles() {
      additionalFiles = [];
      addFileInput.value = '';
      document.getElementById('addMoreSection').style.display = 'none';
      document.getElementById('addMoreBtn').style.display = 'block';
    }

    async function uploadAdditionalFiles() {
      if (!additionalFiles.length || !sessionId) return;
      const btn = document.getElementById('uploadAddBtn');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span>';
      document.getElementById('addProgress').style.display = 'block';

      const formData = new FormData();
      additionalFiles.forEach(f => formData.append('files', f));
      formData.append('session_id', sessionId);
      formData.append('duration', durationMinutes);

      try {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload');
        xhr.upload.onprogress = e => {
          if (e.lengthComputable) {
            document.getElementById('addProgressFill').style.width = (e.loaded / e.total * 100) + '%';
          }
        };
        xhr.onload = () => {
          document.getElementById('addProgress').style.display = 'none';
          document.getElementById('addProgressFill').style.width = '0%';
          if (xhr.status >= 200 && xhr.status < 300) {
            const data = JSON.parse(xhr.responseText);
            sentFiles = data.files || sentFiles;
            renderSentFileList();
            cancelAdditionalFiles();
            showToast('Files added to session');
          } else {
            let msg = 'Upload failed';
            try { msg = JSON.parse(xhr.responseText).detail || msg; } catch(e) {}
            showToast(msg, 'error');
          }
          btn.disabled = false;
          btn.textContent = 'UPLOAD';
        };
        xhr.onerror = () => {
          showToast('NETWORK ERROR', 'error');
          btn.disabled = false;
          btn.textContent = 'UPLOAD';
          document.getElementById('addProgress').style.display = 'none';
        };
        xhr.send(formData);
      } catch (e) {
        showToast('Upload failed', 'error');
        btn.disabled = false;
        btn.textContent = 'UPLOAD';
      }
    }

    /* ── Polling ── */
    function startPolling() {
      pollInterval = setInterval(async () => {
        try {
          const res = await fetch('/api/session/' + sessionId);
          const data = await res.json();
          if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
            document.getElementById('statusBadge').innerHTML =
              '<span class="status-dot closed"></span> SESSION ' + data.status;
            document.getElementById('qrImage').style.opacity = '0.15';
            document.getElementById('closeBtn').style.display = 'none';
            document.getElementById('addMoreBtn').style.display = 'none';
            document.getElementById('addMoreSection').style.display = 'none';
            clearInterval(pollInterval);
            return;
          }
          if (data.remaining_seconds !== undefined) {
            const m = Math.floor(data.remaining_seconds / 60);
            const s = Math.floor(data.remaining_seconds % 60).toString().padStart(2, '0');
            document.getElementById('countdown').textContent = '[' + m + ':' + s + ']';
          }
        } catch (e) {}
      }, 2000);
    }

    /* ── Close Session ── */
    async function closeSession() {
      try {
        await fetch('/api/close-session/' + sessionId, { method: 'POST' });
        clearInterval(pollInterval);
        showToast('Session closed');
        setTimeout(() => { window.location.href = '/dashboard'; }, 1000);
      } catch (e) {
        showToast('Error closing session', 'error');
      }
    }
  </script>
</body>
</html>"""

_RECEIVE_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Receive File — MOBILE2PC</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 32px 20px; }
    .header { text-align: center; margin-bottom: 28px; width: 100%; max-width: 620px; }
    .header h1 { color: var(--text-bright); font-family: var(--font-body); font-weight: bold; }
    .header p { color: var(--text-muted); font-family: var(--font-body); font-size: 0.85rem; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.06em; margin-top: 8px; line-height: 2; }
    .content { width: 100%; max-width: 620px; }
    .setup-card { border-top: 2px solid var(--text-bright); }
    .qr-section { display: none; flex-direction: column; align-items: center; width: 100%; }
    .received-files { margin-top: 20px; width: 100%; }
  </style>
</head>
<body>
  <main class="page container">
    <div class="header animate-in">
      <a href="/dashboard" class="back-link">← DASHBOARD</a>
      <h1 class="text-chrome">RECEIVE FILES</h1>
      <p>Generate a secure QR session to receive files</p>
    </div>

    <div class="content">
      <!-- STATE: SESSION CONFIG -->
      <div class="state-panel" id="stateSessionConfig">
        <div class="card setup-card animate-in">
          <div class="section-label">SESSION DURATION</div>
          <div class="duration-row">
            <input type="number" id="durationValue" class="input-field" value="30" min="1" max="60">
            <select id="durationUnit" class="input-field">
              <option value="minutes">MINUTES</option>
              <option value="hours">HOURS</option>
            </select>
          </div>
          <div class="duration-error" id="durationError"></div>
  
          <button class="btn btn-primary" style="width:100%; margin-top: 24px;" id="genBtn" onclick="createSession()">
            GENERATE QR CODE
          </button>
        </div>
      </div>

      <!-- STATE: QR ACTIVE -->
      <div class="state-panel animate-in" id="stateQrActive" style="display:none">
        <div class="qr-panel">
          <div class="qr-frame">
            <img id="qrImage" src="" alt="QR Code">
          </div>
          <div class="qr-label">SCAN WITH MOBILE TO SEND FILES</div>
        </div>

        <div class="status-badge" id="statusBadge">
          <span class="status-dot waiting"></span>
          WAITING FOR CONNECTION... <span id="countdown"></span>
        </div>

        <div class="empty-state" id="emptyState">
          <span class="material-icons-round">hourglass_empty</span>
          <div class="empty-state-title">Waiting for files</div>
          <div class="empty-state-sub">Scan the QR code with your mobile device to begin</div>
        </div>

        <div class="received-files" id="fileList"></div>

        <a id="downloadAllBtn" class="btn btn-outline" style="display:none; width: 100%; margin-top: 16px;" href="#">
          <span class="material-icons-round">download</span> DOWNLOAD ALL (ZIP)
        </a>

        <button class="btn btn-danger" style="width: 100%; margin-top: 24px;" onclick="closeSession()" id="closeBtn">
          CLOSE SESSION
        </button>
      </div>
    </div>
  </main>

  <div class="modal-overlay" id="previewModal" onclick="closeModal()">
    <div class="modal-content" onclick="event.stopPropagation()">
      <img id="modalImage" src="" alt="Preview" style="display:none; cursor: zoom-in; transition: transform 0.2s;" onclick="toggleZoom(event, this)">
      <video id="modalVideo" controls style="display:none"></video>
      <audio id="modalAudio" controls style="display:none; width:100%; max-width:400px;"></audio>
      <button class="btn btn-outline btn-sm" onclick="closeModal()">CLOSE PREVIEW</button>
    </div>
  </div>

  """ + _TOAST_JS + """
  <script>
    let sessionId = null;
    let pollInterval = null;
    let knownFiles = new Set();

    function validateDuration() {
      const val = parseInt(document.getElementById('durationValue').value);
      const unit = document.getElementById('durationUnit').value;
      const errEl = document.getElementById('durationError');
      if (isNaN(val) || val < 1 || val > 60) {
        errEl.textContent = 'ENTER A VALUE BETWEEN 1 AND 60';
        errEl.style.display = 'block';
        return null;
      }
      if (unit === 'hours' && val > 24) {
        errEl.textContent = 'MAXIMUM 24 HOURS';
        errEl.style.display = 'block';
        return null;
      }
      errEl.style.display = 'none';
      return unit === 'hours' ? val * 60 : val;
    }

    function showState(state) {
      document.getElementById('stateSessionConfig').style.display = (state === 'SessionConfig') ? 'block' : 'none';
      document.getElementById('stateQrActive').style.display = (state === 'QrActive') ? 'block' : 'none';
    }

    async function createSession() {
      const minutes = validateDuration();
      if (minutes === null) return;

      const btn = document.getElementById('genBtn');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> GENERATING...';

      const formData = new FormData();
      formData.append('duration', minutes);

      try {
        const res = await fetch('/api/receive-session', { method: 'POST', body: formData });
        if (!res.ok) throw new Error('Failed');
        const data = await res.json();
        sessionId = data.session_id;

        document.getElementById('qrImage').src = '/api/receive-qr/' + sessionId;
        showState('QrActive');
        startPolling();
        showToast('Receive session created - QR code ready');

      } catch (e) {
        showToast('Failed to create session', 'error');
        btn.disabled = false;
        btn.textContent = 'GENERATE QR CODE';
      }
    }

    function startPolling() {
      pollInterval = setInterval(async () => {
        try {
          const res = await fetch('/api/session/' + sessionId);
          const data = await res.json();

          if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
            document.getElementById('statusBadge').innerHTML =
              '<span class="status-dot closed"></span> SESSION ' + data.status;
            document.getElementById('qrImage').style.opacity = '0.15';
            document.getElementById('closeBtn').style.display = 'none';
            clearInterval(pollInterval);
            return;
          }

          if (data.remaining_seconds !== undefined) {
            const m = Math.floor(data.remaining_seconds / 60);
            const s = Math.floor(data.remaining_seconds % 60).toString().padStart(2, '0');
            document.getElementById('countdown').textContent = '[' + m + ':' + s + ']';
          }

          if (data.waiting === false && (!data.files || data.files.length === 0)) {
            document.getElementById('statusBadge').innerHTML =
              '<span class="status-dot active"></span> CONNECTION ESTABLISHED <span id="countdown"></span>';
            document.getElementById('emptyState').querySelector('.empty-state-title').textContent = 'READY TO RECEIVE FILES';
          }

          if (data.files && data.files.length > 0) {
            document.getElementById('emptyState').style.display = 'none';
            const list = document.getElementById('fileList');
            data.files.forEach(f => {
              if (!knownFiles.has(f.name)) {
                knownFiles.add(f.name);
                const el = document.createElement('div');
                el.className = 'file-card animate-in';

                let actions = '';
                if (f.is_image) {
                  actions += `<button class="btn btn-outline btn-sm" onclick="showPreview('image', '/api/preview/${sessionId}/${encodeURIComponent(f.name)}')">PREVIEW</button>`;
                } else if (f.is_video) {
                  actions += `<button class="btn btn-outline btn-sm" onclick="showPreview('video', '/api/preview/${sessionId}/${encodeURIComponent(f.name)}')">PREVIEW</button>`;
                } else if (f.is_audio) {
                  actions += `<button class="btn btn-outline btn-sm" onclick="showPreview('audio', '/api/preview/${sessionId}/${encodeURIComponent(f.name)}')">PREVIEW</button>`;
                }
                const btnId = 'dlBtn-' + f.name.replace(/[^a-zA-Z0-9]/g, '');
                actions += `<button id="${btnId}" class="btn btn-primary btn-sm" onclick="FileDownloadService.download('/api/download/${sessionId}/${encodeURIComponent(f.name)}', '${f.original_name.replace(/'/g, "\\'")}')">DOWNLOAD</button>`;

                el.innerHTML = `
                  <div class="file-card-header">
                    <span class="material-icons-round file-card-icon">${f.icon}</span>
                    <div class="file-card-info">
                      <div class="file-card-name">${f.original_name}</div>
                      <div class="file-card-meta">
                        <span>${f.size_formatted}</span>
                        <span class="file-item-ext">${f.original_name.split('.').pop().toUpperCase()}</span>
                      </div>
                    </div>
                  </div>
                  <div class="file-card-actions">${actions}</div>
                `;
                list.appendChild(el);
              }
            });
            document.getElementById('statusBadge').innerHTML =
              '<span class="status-dot active"></span> CONNECTION ACTIVE <span id="countdown"></span>';

            if (data.files.length > 1) {
              const dlAllBtn = document.getElementById('downloadAllBtn');
              dlAllBtn.style.display = 'inline-flex';
              dlAllBtn.onclick = function(e) {
                e.preventDefault();
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = '/api/download-all/' + sessionId;
                document.body.appendChild(a);
                a.click();
                setTimeout(() => { document.body.removeChild(a); }, 100);
                showToast('Starting download...', 'info');
              };
            }
          }
        } catch (e) {}
      }, 2000);
    }

    function showPreview(type, url) {
      const modal = document.getElementById('previewModal');
      const img = document.getElementById('modalImage');
      const vid = document.getElementById('modalVideo');
      const aud = document.getElementById('modalAudio');
      img.style.display = 'none';
      vid.style.display = 'none';
      aud.style.display = 'none';
      if (type === 'image') { img.src = url; img.style.display = 'block'; }
      else if (type === 'video') { vid.src = url; vid.style.display = 'block'; }
      else if (type === 'audio') { aud.src = url; aud.style.display = 'block'; }
      modal.classList.add('active');
    }

    function closeModal() {
      const modal = document.getElementById('previewModal');
      modal.classList.remove('active');
      const img = document.getElementById('modalImage');
      img.style.transform = 'scale(1)';
      img.style.cursor = 'zoom-in';
      document.getElementById('modalVideo').pause();
      document.getElementById('modalVideo').src = '';
      document.getElementById('modalAudio').pause();
      document.getElementById('modalAudio').src = '';
    }

    async function closeSession() {
      try {
        await fetch('/api/close-session/' + sessionId, { method: 'POST' });
        clearInterval(pollInterval);
        showToast('Session closed');
        setTimeout(() => { window.location.href = '/dashboard'; }, 1000);
      } catch (e) {
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Send Files — MOBILE2PC</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 24px 16px; }
    .mobile-brand {
      font-family: var(--font-body); font-size: 1.2rem; font-weight: 600;
      text-align: center; margin-bottom: 4px; line-height: 2;
    }
    .mobile-brand-sub {
      font-family: var(--font-body); font-size: 0.75rem; font-weight: 600;
      color: var(--text-muted); text-align: center; margin-bottom: 24px;
      text-transform: uppercase; letter-spacing: 0.06em; line-height: 2.2;
    }
    .mobile-status {
      font-family: var(--font-body); font-size: 0.85rem; font-weight: 600;
      color: var(--text-secondary); text-transform: uppercase;
      letter-spacing: 0.04em; margin-bottom: 20px; line-height: 2;
      text-align: center;
    }
    .content { width: 100%; max-width: 500px; }
    .drop-zone { padding: 40px 20px; min-height: 140px; }
    .activity-item {
      padding: 12px 14px; background: var(--bg-surface); border: 1px solid var(--border-color);
      border-left: 2px solid var(--success); font-family: var(--font-mono);
      margin-bottom: 6px;
    }
    .activity-title { font-weight: 700; color: var(--text-bright); font-size: 0.8rem;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-bottom: 2px; }
    .activity-meta { font-size: 0.7rem; color: var(--text-muted); }
  </style>
</head>
<body>
  <main class="page">
    <div class="mobile-brand text-chrome animate-in">MOBILE2PC</div>
    <div class="mobile-brand-sub animate-in">Secured Crypto AnyFile Share</div>

    <div id="sessionEndedOverlay" class="session-ended" style="display:none">
      <span class="material-icons-round">block</span>
      <h2 id="endedTitle">SESSION CLOSED</h2>
      <p id="endedMessage">This transfer session has been closed by the receiver.</p>
      <p class="sub">The files in this session are no longer available for upload.</p>
    </div>

    <div id="mainContent" class="content animate-in">
      <div class="mobile-status" id="sessionStatus">SESSION: {{SESSION_ID}}</div>

      <div id="uploadForm" class="drop-zone" style="display: block;">
        <span class="material-icons-round drop-zone-icon">cloud_upload</span>
        <div class="drop-zone-title">Tap to Select Files</div>
        <div class="drop-zone-sub">Select any files to send to the PC</div>
        <input type="file" id="fileInput" multiple style="display:none">
      </div>

      <div id="uploadControls" style="display:none; width:100%; margin-top: 16px;">
        <div class="section-label">SELECTED FILES</div>
        <div class="file-list" id="fileListPreview"></div>
        <div class="file-summary" id="fileSummary"></div>
        <div class="btn-row" style="margin-top: 12px;">
          <button class="btn btn-primary" id="uploadBtn">SEND FILES</button>
          <button class="btn btn-outline" onclick="cancelSelection()">CANCEL</button>
        </div>
        <div class="progress-bar" id="progressContainer" style="display:none">
          <div class="progress-bar-fill" id="progressFill"></div>
        </div>
      </div>

      <div id="addMoreContainer" style="display:none; width:100%; margin-top: 16px;">
        <button class="btn btn-outline" style="width:100%; border-style: dashed;" onclick="resetForm()">
          <span class="material-icons-round">add</span> SEND MORE FILES
        </button>
      </div>

      <div id="activityList" style="margin-top: 20px;"></div>
    </div>
  </main>

  """ + _TOAST_JS + """
  <script>
    const SESSION_ID = '{{SESSION_ID}}';
    let isClosed = false;
    let selectedFiles = [];

    function formatSize(bytes) {
      const units = ['B','KB','MB','GB'];
      let i = 0; let size = bytes;
      while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
      return size.toFixed(1) + ' ' + units[i];
    }

    function getExt(name) {
      const parts = name.split('.');
      return parts.length > 1 ? parts.pop().toUpperCase() : '—';
    }

    function getIcon(name) {
      const ext = name.split('.').pop().toLowerCase();
      const map = {
        pdf:'picture_as_pdf', doc:'description', docx:'description',
        xls:'table_chart', xlsx:'table_chart',
        mp4:'movie', mov:'movie', webm:'movie',
        mp3:'audio_file', wav:'audio_file',
        png:'image', jpg:'image', jpeg:'image', gif:'image', webp:'image',
        zip:'folder_zip', rar:'folder_zip',
        exe:'terminal', py:'code', js:'code',
      };
      return map[ext] || 'insert_drive_file';
    }

    /* ── Session status polling ── */
    const statusPoll = setInterval(async () => {
      try {
        const res = await fetch('/api/session/' + SESSION_ID);
        const data = await res.json();
        if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
          isClosed = true;
          clearInterval(statusPoll);
          document.getElementById('mainContent').style.display = 'none';
          const overlay = document.getElementById('sessionEndedOverlay');
          overlay.style.display = 'flex';
          document.getElementById('endedTitle').textContent = 'SESSION ' + data.status;
          document.getElementById('endedMessage').textContent =
            data.status === 'CLOSED'
              ? 'This transfer session has been closed by the receiver.'
              : 'This transfer session has expired.';
        }
      } catch(e){}
    }, 2000);

    /* ── File selection ── */
    const form = document.getElementById('uploadForm');
    const input = document.getElementById('fileInput');
    let dragCounter = 0;

    form.addEventListener('click', () => { if(!isClosed) input.click(); });
    form.addEventListener('dragenter', e => { e.preventDefault(); dragCounter++; form.classList.add('drag-over'); });
    form.addEventListener('dragleave', () => { dragCounter--; if (dragCounter === 0) form.classList.remove('drag-over'); });
    form.addEventListener('dragover', e => e.preventDefault());
    form.addEventListener('drop', e => {
      e.preventDefault(); dragCounter = 0; form.classList.remove('drag-over');
      if (!isClosed && e.dataTransfer.files.length) {
        selectedFiles = Array.from(e.dataTransfer.files);
        showSelectedFiles();
      }
    });

    input.addEventListener('change', () => {
      if(input.files.length > 0 && !isClosed) {
        selectedFiles = Array.from(input.files);
        showSelectedFiles();
      }
    });

    function showSelectedFiles() {
      const totalSize = selectedFiles.reduce((a, f) => a + f.size, 0);
      document.getElementById('fileListPreview').innerHTML = selectedFiles.map(f => `
        <div class="file-item">
          <span class="material-icons-round file-item-icon">${getIcon(f.name)}</span>
          <span class="file-item-name">${f.name}</span>
          <span class="file-item-size">${formatSize(f.size)}</span>
          <span class="file-item-ext">${getExt(f.name)}</span>
        </div>
      `).join('');
      document.getElementById('fileSummary').textContent =
        selectedFiles.length + ' file' + (selectedFiles.length !== 1 ? 's' : '') + ' — ' + formatSize(totalSize);
      document.getElementById('uploadControls').style.display = 'block';
      form.style.display = 'none';
      document.getElementById('addMoreContainer').style.display = 'none';
    }

    function cancelSelection() {
      selectedFiles = [];
      input.value = '';
      document.getElementById('uploadControls').style.display = 'none';
      document.getElementById('progressContainer').style.display = 'none';
      document.getElementById('progressFill').style.width = '0%';
      document.getElementById('uploadBtn').disabled = false;
      document.getElementById('uploadBtn').textContent = 'SEND FILES';
      form.style.display = 'block';
    }

    /* ── Upload ── */
    document.getElementById('uploadBtn').addEventListener('click', async () => {
      if(!selectedFiles.length || isClosed) return;
      const btn = document.getElementById('uploadBtn');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> SENDING...';
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
          document.getElementById('progressContainer').style.display = 'none';
          document.getElementById('progressFill').style.width = '0%';
          if(xhr.status >= 200 && xhr.status < 300) {
            document.getElementById('uploadControls').style.display = 'none';
            document.getElementById('addMoreContainer').style.display = 'block';

            const activityList = document.getElementById('activityList');
            selectedFiles.forEach(f => {
              const el = document.createElement('div');
              el.className = 'activity-item animate-in';
              el.innerHTML = `
                <div class="activity-title">${f.name}</div>
                <div class="activity-meta">SENT SUCCESSFULLY — ${formatSize(f.size)}</div>
              `;
              activityList.prepend(el);
            });
            showToast('Files sent successfully!');
          } else {
            let msg = 'TRANSFER FAILED';
            try { msg = JSON.parse(xhr.responseText).detail || msg; } catch(e) {}
            showToast(msg, 'error');
            btn.disabled = false;
            btn.textContent = 'SEND FILES';
          }
        };
        xhr.onerror = () => {
          showToast('NETWORK ERROR — Check your connection', 'error');
          btn.disabled = false;
          btn.textContent = 'SEND FILES';
          document.getElementById('progressContainer').style.display = 'none';
        };
        xhr.send(formData);
      } catch(e) {
        showToast('Upload failed', 'error');
        btn.disabled = false;
        btn.textContent = 'SEND FILES';
      }
    });

    function resetForm() {
      if(isClosed) return;
      selectedFiles = [];
      input.value = '';
      document.getElementById('progressContainer').style.display = 'none';
      document.getElementById('progressFill').style.width = '0%';
      document.getElementById('addMoreContainer').style.display = 'none';
      document.getElementById('uploadBtn').disabled = false;
      document.getElementById('uploadBtn').textContent = 'SEND FILES';
      form.style.display = 'block';
    }
  </script>
</body>
</html>"""

_SESSION_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Download — MOBILE2PC</title>
  """ + _SHARED_STYLES + """
  <style>
    .page { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 24px 16px; }
    .mobile-brand {
      font-family: var(--font-body); font-size: 1.2rem; font-weight: 600;
      text-align: center; margin-bottom: 4px; line-height: 2;
    }
    .mobile-brand-sub {
      font-family: var(--font-body); font-size: 0.75rem; font-weight: 600;
      color: var(--text-muted); text-align: center; margin-bottom: 24px;
      text-transform: uppercase; letter-spacing: 0.06em; line-height: 2.2;
    }
    .mobile-status {
      font-family: var(--font-body); font-size: 0.85rem; font-weight: 600;
      color: var(--text-secondary); text-transform: uppercase;
      letter-spacing: 0.04em; margin-bottom: 20px; line-height: 2;
      text-align: center;
    }
    .content { width: 100%; max-width: 500px; }
    .download-all-btn { width: 100%; margin-top: 16px; }
    .file-card { margin-bottom: 10px; }
  </style>
</head>
<body>
  <main class="page">
    <div class="mobile-brand text-chrome animate-in">MOBILE2PC</div>
    <div class="mobile-brand-sub animate-in">Secured Crypto AnyFile Share</div>

    <div id="sessionEndedOverlay" class="session-ended" style="display:none">
      <span class="material-icons-round">block</span>
      <h2 id="endedTitle">SESSION CLOSED</h2>
      <p id="endedMessage">This transfer session has been closed by the sender.</p>
      <p class="sub">The files in this session are no longer available.</p>
    </div>

    <div id="mainContent" class="content animate-in">
      <div class="mobile-status" id="sessionStatus">
        <span class="status-dot active" style="margin-right: 4px;"></span>
        SESSION ACTIVE <span id="countdown"></span>
      </div>

      <div class="empty-state" id="emptyState">
        <span class="material-icons-round">hourglass_empty</span>
        <div class="empty-state-title">Loading files...</div>
        <div class="empty-state-sub">Waiting for session data</div>
      </div>

      <div id="filesContainer"></div>

      <a id="downloadAllBtn" class="btn btn-outline download-all-btn" style="display:none" href="#">
        <span class="material-icons-round">download</span> DOWNLOAD ALL (ZIP)
      </a>
    </div>
  </main>

  <div class="modal-overlay" id="previewModal" onclick="closePreview()">
    <div class="modal-content" onclick="event.stopPropagation()">
      <img id="previewImage" src="" alt="Preview" style="display:none; cursor: zoom-in; transition: transform 0.2s;" onclick="toggleZoom(event, this)">
      <video id="previewVideo" controls style="display:none"></video>
      <audio id="previewAudio" controls style="display:none; width:100%; max-width:400px;"></audio>
      <button class="btn btn-outline btn-sm" onclick="closePreview()">CLOSE PREVIEW</button>
    </div>
  </div>

  <div class="modal-overlay" id="downloadModal" onclick="closeDownloadModal()">
    <div class="modal-content" style="background: var(--bg-surface); padding: 24px; border: 1px solid var(--border-color); min-width: 280px; backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);" onclick="event.stopPropagation()">
      <h2 style="font-family: var(--font-body); font-size: 1.1rem; font-weight: 600; color: var(--text-bright); margin-bottom: 24px; text-align: center; line-height: 2;">DOWNLOAD FILE</h2>
      <a id="downloadLocallyBtn" href="#" class="btn btn-primary" style="width: 100%; margin-bottom: 12px; font-weight: 500;">
        <span class="material-icons-round">download</span> SAVE LOCALLY
      </a>
      <a id="downloadDeviceBtn" href="#" class="btn btn-outline" style="width: 100%; margin-bottom: 12px; font-weight: 500;">
        <span class="material-icons-round">smartphone</span> SAVE TO DEVICE
      </a>
      <button class="btn btn-outline" style="width: 100%; margin-bottom: 12px; color: var(--text-bright);" onclick="alert('Google Drive integration is not currently configured. This will be implemented in a future update.');">
        <span class="material-icons-round">cloud_upload</span> SAVE TO GOOGLE DRIVE
      </button>
      <button class="btn btn-danger" style="width: 100%;" onclick="closeDownloadModal()">
        CANCEL
      </button>
    </div>
  </div>

  """ + _TOAST_JS + """
  <script>
    const SESSION_ID = window.location.pathname.split('/').pop().toUpperCase();
    let knownFiles = new Set();
    let sessionEnded = false;

    function showDownloadModal(encodedName, encodedOriginalName) {
      const modal = document.getElementById('downloadModal');
      const locallyBtn = document.getElementById('downloadLocallyBtn');
      const deviceBtn = document.getElementById('downloadDeviceBtn');
      
      locallyBtn.onclick = function(e) {
        e.preventDefault();
        FileDownloadService.saveLocally('/api/download/' + SESSION_ID + '/' + encodedName, decodeURIComponent(encodedOriginalName));
        closeDownloadModal();
      };
      
      deviceBtn.onclick = function(e) {
        e.preventDefault();
        FileDownloadService.download('/api/download/' + SESSION_ID + '/' + encodedName, decodeURIComponent(encodedOriginalName));
        closeDownloadModal();
      };
      modal.classList.add('active');
    }

    function closeDownloadModal() {
      document.getElementById('downloadModal').classList.remove('active');
    }

    function showPreview(type, url) {
      const modal = document.getElementById('previewModal');
      const img = document.getElementById('previewImage');
      const vid = document.getElementById('previewVideo');
      const aud = document.getElementById('previewAudio');
      img.style.display = 'none'; vid.style.display = 'none'; aud.style.display = 'none';

      if (type === 'image') { img.src = url; img.style.display = 'block'; }
      else if (type === 'video') { vid.src = url; vid.style.display = 'block'; }
      else if (type === 'audio') { aud.src = url; aud.style.display = 'block'; }
      modal.classList.add('active');
    }

    function closePreview() {
      document.getElementById('previewModal').classList.remove('active');
      const img = document.getElementById('previewImage');
      img.style.transform = 'scale(1)';
      img.style.cursor = 'zoom-in';
      document.getElementById('previewVideo').pause();
      document.getElementById('previewVideo').src = '';
      document.getElementById('previewAudio').pause();
      document.getElementById('previewAudio').src = '';
    }

    function showSessionEnded(status) {
      sessionEnded = true;
      document.getElementById('mainContent').style.display = 'none';
      const overlay = document.getElementById('sessionEndedOverlay');
      overlay.style.display = 'flex';
      document.getElementById('endedTitle').textContent = 'SESSION ' + status;
      document.getElementById('endedMessage').textContent =
        status === 'CLOSED'
          ? 'This transfer session has been closed by the sender.'
          : 'This transfer session has expired.';
    }

    /* ── Polling ── */
    const poll = setInterval(async () => {
      if (sessionEnded) return;
      try {
        const res = await fetch('/api/session/' + SESSION_ID);
        if (res.status === 404) {
          showSessionEnded('EXPIRED');
          clearInterval(poll);
          return;
        }
        const data = await res.json();

        if (data.status === 'CLOSED' || data.status === 'EXPIRED') {
          showSessionEnded(data.status);
          clearInterval(poll);
          return;
        }

        if (data.remaining_seconds !== undefined) {
          const m = Math.floor(data.remaining_seconds / 60);
          const s = Math.floor(data.remaining_seconds % 60).toString().padStart(2, '0');
          document.getElementById('countdown').textContent = '[' + m + ':' + s + ']';
        }

        if (data.files && data.files.length > 0) {
          document.getElementById('emptyState').style.display = 'none';
          const container = document.getElementById('filesContainer');
          data.files.forEach(f => {
            if (!knownFiles.has(f.name)) {
              knownFiles.add(f.name);
              const el = document.createElement('div');
              el.className = 'file-card animate-in';

              let actions = '';
              if (f.is_image) {
                actions += `<button class="btn btn-outline btn-sm" onclick="showPreview('image', '/api/preview/${SESSION_ID}/${encodeURIComponent(f.name)}')">PREVIEW</button>`;
              } else if (f.is_video) {
                actions += `<button class="btn btn-outline btn-sm" onclick="showPreview('video', '/api/preview/${SESSION_ID}/${encodeURIComponent(f.name)}')">PREVIEW</button>`;
              } else if (f.is_audio) {
                actions += `<button class="btn btn-outline btn-sm" onclick="showPreview('audio', '/api/preview/${SESSION_ID}/${encodeURIComponent(f.name)}')">PREVIEW</button>`;
              }
              actions += `<button class="btn btn-primary btn-sm" onclick="showDownloadModal('${encodeURIComponent(f.name)}', '${encodeURIComponent(f.original_name)}')">DOWNLOAD</button>`;

              el.innerHTML = `
                <div class="file-card-header">
                  <span class="material-icons-round file-card-icon">${f.icon}</span>
                  <div class="file-card-info">
                    <div class="file-card-name">${f.original_name}</div>
                    <div class="file-card-meta">
                      <span>${f.size_formatted}</span>
                      <span class="file-item-ext">${f.original_name.split('.').pop().toUpperCase()}</span>
                    </div>
                  </div>
                </div>
                <div class="file-card-actions">${actions}</div>
              `;
              container.appendChild(el);
            }
          });

          if (data.files.length > 1) {
            const dlAllBtn = document.getElementById('downloadAllBtn');
            dlAllBtn.style.display = 'inline-flex';
            dlAllBtn.onclick = function(e) {
              e.preventDefault();
              const a = document.createElement('a');
              a.style.display = 'none';
              a.href = '/api/download-all/' + SESSION_ID;
              document.body.appendChild(a);
              a.click();
              setTimeout(() => { document.body.removeChild(a); }, 100);
              showToast('Starting download...', 'info');
            };
          }
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
    if sid in sessions and sessions[sid].get("mode") == "receive":
        sessions[sid]["waiting"] = False
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
