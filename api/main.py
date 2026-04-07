"""
BSOD Analyzer v2 - FastAPI Backend
Windows Crash Dump Analysis API with AI Diagnostics

Features:
  - Chunked multipart upload (up to 2GB)
  - Rule-based dump analysis (64-bit/32-bit kernel, MDMP)
  - LLM-powered AI diagnostics
  - Customer email draft generation
  - PDF report generation
  - Full Swagger UI documentation
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, File, HTTPException, Request, UploadFile, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent))
from engine.dump_analyzer import DumpAnalyzer
from engine.bugcheck_db import BUGCHECK_CODES, get_bugcheck_info

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bsod_analyzer")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024   # 2 GB
# Vercel serverless hard limit: 4.5 MB per request body
# We use 4 MB chunks to stay safely under the limit
CHUNK_SIZE_LIMIT = 4 * 1024 * 1024        # 4 MB per chunk (Vercel safe limit)

# ---------------------------------------------------------------------------
# Vercel-compatible storage helpers
# ---------------------------------------------------------------------------
# Vercel serverless functions are EPHEMERAL and STATELESS:
#   1. Each invocation may run in a different container → in-memory dicts are lost
#   2. /tmp is the ONLY writable directory (max ~512 MB per invocation)
#   3. Files written to /tmp in one invocation ARE NOT visible in another
#
# Architecture decision:
#   - Session metadata is stored as a JSON file in /tmp/bsod_<upload_id>/session.json
#   - Each chunk is stored as /tmp/bsod_<upload_id>/part_NNNNN
#   - The assembled file is /tmp/bsod_<upload_id>/assembled.dmp
#   - UPLOAD_SESSIONS dict is only used as a fast in-process cache;
#     every read falls back to disk if the key is missing (cross-invocation safe)
#
# IMPORTANT: Because Vercel does NOT share /tmp across invocations, large
# multi-chunk uploads (>512 MB) will fail when chunks land on different
# containers. For production use of 2 GB uploads, use a persistent store
# (e.g., Vercel KV, Redis, or S3 presigned URLs).

UPLOAD_SESSIONS: Dict[str, Dict] = {}  # in-process cache only


def _get_session_dir(upload_id: str) -> Path:
    """Return the /tmp directory for this upload session."""
    d = Path(tempfile.gettempdir()) / f"bsod_{upload_id}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_session(session: dict) -> None:
    """Persist session metadata to disk so other invocations can read it."""
    session_dir = _get_session_dir(session["upload_id"])
    session_file = session_dir / "session.json"
    # Convert Path objects to strings for JSON serialisation
    serialisable = {k: str(v) if isinstance(v, Path) else v for k, v in session.items()}
    session_file.write_text(json.dumps(serialisable))


def _load_session(upload_id: str) -> Optional[Dict]:
    """Load session from in-process cache or fall back to disk."""
    if upload_id in UPLOAD_SESSIONS:
        return UPLOAD_SESSIONS[upload_id]
    session_file = Path(tempfile.gettempdir()) / f"bsod_{upload_id}" / "session.json"
    if session_file.exists():
        try:
            session = json.loads(session_file.read_text())
            UPLOAD_SESSIONS[upload_id] = session  # warm the cache
            return session
        except Exception:
            pass
    return None


TEMP_DIR = Path(tempfile.gettempdir())  # base /tmp — always exists on Vercel

# LLM is handled client-side via Puter.js (no API key required)
# Server-side LLM is optional; set FORGE_API_KEY to enable it
LLM_API_URL = os.environ.get("FORGE_API_URL", "")
LLM_API_KEY = os.environ.get("FORGE_API_KEY", "")

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class UploadInitRequest(BaseModel):
    filename: str = Field(..., description="Original filename of the dump file")
    file_size: int = Field(..., description="Total file size in bytes")
    sha256: Optional[str] = Field(None, description="SHA-256 hash of the file (optional, for integrity check)")
    mime_type: Optional[str] = Field("application/octet-stream", description="MIME type")

class UploadInitResponse(BaseModel):
    upload_id: str = Field(..., description="Unique upload session ID")
    chunk_size: int = Field(..., description="Recommended chunk size in bytes")
    total_chunks: int = Field(..., description="Total number of chunks expected")
    expires_at: float = Field(..., description="Unix timestamp when session expires")

class ChunkUploadResponse(BaseModel):
    upload_id: str
    part_number: int
    received: bool
    completed_parts: List[int]
    progress_percent: float

class CompleteUploadRequest(BaseModel):
    upload_id: str = Field(..., description="Upload session ID")
    parts: List[int] = Field(..., description="List of completed part numbers in order")

class CompleteUploadResponse(BaseModel):
    upload_id: str
    file_key: str
    filename: str
    file_size: int
    sha256: Optional[str]
    ready_for_analysis: bool

class AIDiagnoseRequest(BaseModel):
    analysis_result: Dict[str, Any] = Field(..., description="Raw analysis result from /api/analyze")
    language: str = Field("ko", description="Response language: 'ko' (Korean) or 'en' (English)")

class AIDiagnoseResponse(BaseModel):
    lay_summary: str = Field(..., description="Plain-language summary for non-technical users")
    technical_analysis: str = Field(..., description="In-depth technical analysis for engineers")
    root_cause: str = Field(..., description="Most likely root cause")
    confidence: int = Field(..., description="Confidence score 0-100")
    confidence_reason: str = Field(..., description="Reason for confidence score")
    prioritized_fixes: List[str] = Field(..., description="Recommended fixes in priority order")
    additional_checks: List[str] = Field(..., description="Additional checks to perform")
    severity: str = Field(..., description="critical | high | medium | low")
    estimated_impact: str = Field(..., description="Business/operational impact description")

class EmailGenerateRequest(BaseModel):
    analysis_result: Dict[str, Any] = Field(..., description="Raw analysis result from /api/analyze")
    ai_diagnosis: Optional[Dict[str, Any]] = Field(None, description="AI diagnosis result (optional)")
    customer_name: str = Field(..., description="Customer company name")
    contact_name: Optional[str] = Field("", description="Customer contact person name")
    language: str = Field("ko", description="Email language: 'ko' or 'en'")
    tone: str = Field("formal", description="Email tone: 'formal', 'friendly', 'technical'")

class EmailGenerateResponse(BaseModel):
    subject: str
    greeting: str
    overview: str
    key_summary: str
    issues_and_impact: str
    recommendations: str
    closing: str
    full_text: str = Field(..., description="Complete email text ready to copy")

class PDFReportRequest(BaseModel):
    analysis_result: Dict[str, Any] = Field(..., description="Raw analysis result from /api/analyze")
    ai_diagnosis: Optional[Dict[str, Any]] = Field(None, description="AI diagnosis result (optional)")
    language: str = Field("ko", description="PDF language: 'ko' or 'en'")
    include_modules: bool = Field(True, description="Include loaded modules section")
    include_watermark: bool = Field(False, description="Add CONFIDENTIAL watermark")

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------
app = FastAPI(
    title="BSOD Analyzer API",
    description="""
## Windows Crash Dump Analysis Service

Upload Windows memory dump files (`.dmp`, `.mdmp`, `.dump`) and receive instant diagnostic results — **no WinDbg required**.

### Features
- **Chunked Upload**: Upload files up to 2GB with resume support
- **Rule-based Analysis**: Instant Bug Check code identification (60+ known codes)
- **AI Diagnostics**: LLM-powered deep analysis with root cause identification
- **Email Generation**: Auto-generate customer-ready email drafts
- **PDF Reports**: Download structured PDF reports with charts

### Supported Dump Types
| Type | Signature | Description |
|------|-----------|-------------|
| 64-bit Kernel Dump | `PAGEDU64` | Windows 10/11 kernel minidump |
| 32-bit Kernel Dump | `PAGEDUMP` | Windows 7/8 kernel minidump |
| User-mode Minidump | `MDMP` | Application crash dump |

### Quick Start
1. `POST /api/upload/init` — Initialize upload session
2. `POST /api/upload/chunk/{upload_id}` — Upload file chunks
3. `POST /api/upload/complete` — Finalize upload
4. `POST /api/analyze` — Analyze the dump file
5. `POST /api/ai/diagnose` — Get AI-powered diagnosis
6. `POST /api/email/generate` — Generate customer email
7. `POST /api/pdf/generate` — Download PDF report
    """,
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    contact={
        "name": "BSOD Analyzer",
        "url": "https://github.com/your-org/bsod-analyzer",
    },
    license_info={
        "name": "MIT",
    },
    tags_metadata=[
        {"name": "health", "description": "Service health and status checks"},
        {"name": "upload", "description": "Chunked file upload with resume support (up to 2GB)"},
        {"name": "analysis", "description": "Core dump file analysis engine"},
        {"name": "bugchecks", "description": "Bug Check code reference database"},
        {"name": "ai", "description": "LLM-powered AI diagnostics"},
        {"name": "email", "description": "Customer email draft generation"},
        {"name": "pdf", "description": "PDF report generation and download"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static frontend
frontend_dir = Path(__file__).parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def validate_dump_file(file: UploadFile) -> None:
    allowed_extensions = {".dmp", ".mdmp", ".dump"}
    filename = file.filename or ""
    ext = Path(filename).suffix.lower()
    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{ext}'. Allowed: {', '.join(allowed_extensions)}"
        )

def format_analysis_response(raw: dict, filename: str) -> dict:
    """Convert raw DumpAnalyzer result to structured API response."""
    analysis_time = raw.get("analysis_time")
    if analysis_time is None:
        analysis_time = round(raw.get("analysis_time_ms", 0) / 1000, 3)
    return {
        "filename": filename,
        "dump_type": raw.get("dump_type", "Unknown"),
        "architecture": raw.get("architecture", "Unknown"),
        "file_size_bytes": raw.get("file_size", raw.get("file_size_bytes", 0)),
        "analysis_time_seconds": round(analysis_time or 0, 3),
        "analysis_mode": raw.get("analysis_mode", "unknown"),
        "crash_summary": {
            "bugcheck_code": raw.get("bugcheck_code", "N/A"),
            "bugcheck_name": raw.get("bugcheck_name", "UNKNOWN"),
            "bugcheck_description": raw.get("bugcheck_description", ""),
            "bugcheck_parameters": raw.get("bugcheck_parameters", []),
            "severity": raw.get("bugcheck_severity", "unknown"),
            "crash_address": raw.get("crash_address"),
            "caused_by_driver": raw.get("caused_by_driver"),
        },
        "system_info": raw.get("system_info", {}),
        "exception": raw.get("exception"),
        "loaded_modules": raw.get("loaded_modules", []),
        "threads": raw.get("threads", []),
        "stack_trace": raw.get("stack_trace", []),
        "diagnosis": {
            "known_causes": raw.get("known_causes", []),
            "suggested_fixes": raw.get("suggested_fixes", []),
        },
        "target_process": raw.get("target_process", "Unknown"),
        "faulting_process": raw.get("faulting_process", raw.get("target_process", "Unknown")),
        "debug_session_time": raw.get("debug_session_time", "N/A"),
        "system_uptime": raw.get("system_uptime", "N/A"),
        "process_uptime": raw.get("process_uptime", "N/A"),
        "log_type": raw.get("log_type", "Unknown"),
        "thread_count": raw.get("thread_count", 0),
        "module_count": raw.get("module_count", 0),
        "failure_bucket": raw.get("failure_bucket", "Unknown"),
        "faulting_thread": raw.get("faulting_thread", "FAULTING_THREAD: N/A"),
        "stack_core": raw.get("stack_core", "N/A"),
        "third_party_intervention": raw.get("third_party_intervention", "N/A"),
        "root_cause_analysis": raw.get("root_cause_analysis", []),
        "additional_analysis_recommendations": raw.get("additional_analysis_recommendations", []),
        "recommended_windbg_commands": raw.get("recommended_windbg_commands", []),
        "recommended_windbg_script": raw.get("recommended_windbg_script", ""),
        "windbg_output": raw.get("windbg_output", ""),
        "warnings": raw.get("warnings", []),
        "errors": raw.get("errors", []),
    }

def cleanup_temp_file(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except Exception:
        pass

def _get_chunk_size(file_size: int) -> int:
    # Vercel serverless enforces a 4.5 MB request body limit.
    # All chunks must be <= 4 MB regardless of file size.
    return 4 * 1024 * 1024  # 4 MB — safe for Vercel Pro (4.5 MB limit)

async def _call_llm(messages: list, response_format: Optional[dict] = None) -> str:
    """Call the LLM API (server-side, optional). Falls back to Puter.js client-side."""
    if not LLM_API_KEY or not LLM_API_URL:
        # No server-side key — signal client to use Puter.js
        raise HTTPException(
            status_code=503,
            detail="SERVER_LLM_NOT_CONFIGURED",
            headers={"X-Use-Puter": "true"},
        )

    payload: dict = {
        "model": "gpt-4o-mini",
        "messages": messages,
        "max_tokens": 2048,
    }
    if response_format:
        payload["response_format"] = response_format

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{LLM_API_URL}/chat/completions",
            headers={"Authorization": f"Bearer {LLM_API_KEY}", "Content-Type": "application/json"},
            json=payload,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"LLM API error: {resp.text[:200]}")
        data = resp.json()
        return data["choices"][0]["message"]["content"]

# ---------------------------------------------------------------------------
# Routes — Health
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def root():
    index_path = Path(__file__).parent.parent / "frontend" / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>BSOD Analyzer API v2</h1><p>Visit <a href='/api/docs'>/api/docs</a> for Swagger UI.</p>")

@app.get("/api/health", tags=["health"], summary="Health check")
async def health_check():
    """Returns service health status and version information."""
    return {
        "status": "healthy",
        "service": "BSOD Analyzer API",
        "version": "2.0.0",
        "timestamp": time.time(),
        "features": {
            "chunked_upload": True,
            "max_file_size_gb": 2,
            "ai_diagnostics": "puter_js_client_side",
            "ai_server_side": bool(LLM_API_KEY),
            "email_generation": "puter_js_client_side",
            "pdf_generation": True,
            "bugcheck_db_size": len(BUGCHECK_CODES),
        }
    }

# ---------------------------------------------------------------------------
# Routes — Chunked Upload
# ---------------------------------------------------------------------------

@app.post(
    "/api/upload/init",
    response_model=UploadInitResponse,
    tags=["upload"],
    summary="Initialize a chunked upload session",
    description="""
Initialize a new upload session for a large dump file.

Returns an `upload_id` that must be used in subsequent chunk upload requests.
Sessions expire after **24 hours** of inactivity.

**Chunk size recommendation:**
- Files ≤ 100MB → 5MB chunks
- Files 100MB–500MB → 10MB chunks  
- Files > 500MB → 20MB chunks
    """,
)
async def upload_init(req: UploadInitRequest):
    if req.file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({req.file_size / 1024**3:.2f} GB). Maximum: 2 GB"
        )
    if req.file_size == 0:
        raise HTTPException(status_code=400, detail="File size must be greater than 0")

    upload_id = uuid.uuid4().hex
    chunk_size = _get_chunk_size(req.file_size)
    import math
    total_chunks = math.ceil(req.file_size / chunk_size)

    # Create temp directory for this upload — /tmp is writable on Vercel
    try:
        session_dir = _get_session_dir(upload_id)
    except Exception as exc:
        logger.error(f"Failed to create session directory: {exc}")
        raise HTTPException(status_code=500, detail=f"Could not create upload session directory: {exc}")

    session = {
        "upload_id": upload_id,
        "filename": req.filename,
        "file_size": req.file_size,
        "sha256": req.sha256,
        "chunk_size": chunk_size,
        "total_chunks": total_chunks,
        "completed_parts": [],
        "session_dir": str(session_dir),
        "created_at": time.time(),
        "expires_at": time.time() + 86400,  # 24h
    }
    UPLOAD_SESSIONS[upload_id] = session
    # Persist to disk so other Vercel invocations can find this session
    try:
        _save_session(session)
    except Exception as exc:
        logger.warning(f"Could not persist session to disk: {exc}")

    logger.info(f"Upload session created: id={upload_id}, file={req.filename!r}, size={req.file_size:,}")
    return UploadInitResponse(
        upload_id=upload_id,
        chunk_size=chunk_size,
        total_chunks=total_chunks,
        expires_at=session["expires_at"],
    )

@app.post(
    "/api/upload/chunk/{upload_id}",
    response_model=ChunkUploadResponse,
    tags=["upload"],
    summary="Upload a single file chunk",
    description="""
Upload one chunk of a file. Must be called after `/api/upload/init`.

- `upload_id`: Session ID from init response
- `part_number`: 1-based index of this chunk (1, 2, 3, ...)
- Body: Raw binary chunk data (`Content-Type: application/octet-stream`)

Chunks can be retried safely — uploading the same part number again overwrites the previous attempt.
    """,
)
async def upload_chunk(upload_id: str, part_number: int, request: Request):
    session = _load_session(upload_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Upload session '{upload_id}' not found or expired. On Vercel, sessions may be lost between invocations. Please start a new upload.")
    if time.time() > session["expires_at"]:
        raise HTTPException(status_code=410, detail="Upload session has expired")
    if part_number < 1 or part_number > session["total_chunks"]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid part_number {part_number}. Must be 1–{session['total_chunks']}"
        )

    chunk_data = await request.body()
    if not chunk_data:
        raise HTTPException(
            status_code=400,
            detail=f"Empty chunk body received for part {part_number}. "
                   f"Vercel enforces a 4.5 MB request body limit. "
                   f"Ensure chunk size <= 4 MB."
        )
    if len(chunk_data) > CHUNK_SIZE_LIMIT:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Chunk {part_number} too large ({len(chunk_data) // 1024 // 1024} MB). "
                f"Maximum allowed: {CHUNK_SIZE_LIMIT // 1024 // 1024} MB. "
                f"Vercel serverless enforces a 4.5 MB request body limit. "
                f"Reduce chunk size to 4 MB or less."
            )
        )

    # Save chunk to disk — /tmp is writable on Vercel
    session_dir = Path(session["session_dir"])
    import asyncio
    
    def save_chunk():
        session_dir.mkdir(parents=True, exist_ok=True)
        chunk_path = session_dir / f"part_{part_number:05d}"
        chunk_path.write_bytes(chunk_data)

    try:
        await asyncio.to_thread(save_chunk)
    except Exception as exc:
        logger.error(f"Failed to write chunk {part_number}: {exc}")
        raise HTTPException(status_code=500, detail=f"Failed to save chunk {part_number}: {exc}")

    if part_number not in session["completed_parts"]:
        session["completed_parts"].append(part_number)
    session["completed_parts"].sort()

    # Persist updated session to disk
    UPLOAD_SESSIONS[upload_id] = session
    try:
        await asyncio.to_thread(_save_session, session)
    except Exception as exc:
        logger.warning(f"Could not persist session after chunk {part_number}: {exc}")

    progress = len(session["completed_parts"]) / session["total_chunks"] * 100
    logger.info(f"Chunk received: upload={upload_id}, part={part_number}, progress={progress:.1f}%")

    return ChunkUploadResponse(
        upload_id=upload_id,
        part_number=part_number,
        received=True,
        completed_parts=session["completed_parts"],
        progress_percent=round(progress, 1),
    )

@app.get(
    "/api/upload/status/{upload_id}",
    tags=["upload"],
    summary="Get upload session status",
    description="Returns the current status of an upload session, including completed parts. Use this to resume interrupted uploads.",
)
async def upload_status(upload_id: str):
    session = _load_session(upload_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Upload session '{upload_id}' not found")
    return {
        "upload_id": upload_id,
        "filename": session["filename"],
        "file_size": session["file_size"],
        "total_chunks": session["total_chunks"],
        "completed_parts": session["completed_parts"],
        "progress_percent": round(len(session["completed_parts"]) / session["total_chunks"] * 100, 1),
        "expires_at": session["expires_at"],
    }

@app.post(
    "/api/upload/complete",
    response_model=CompleteUploadResponse,
    tags=["upload"],
    summary="Finalize chunked upload",
    description="""
Assemble all uploaded chunks into a single file and verify integrity.

All chunks must be uploaded before calling this endpoint. The assembled file is stored temporarily and can be analyzed using `/api/analyze/by-upload-id`.
    """,
)
async def upload_complete(req: CompleteUploadRequest):
    session = _load_session(req.upload_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Upload session '{req.upload_id}' not found")

    session_dir = Path(session["session_dir"])

    # Check which parts actually exist on disk (cross-invocation safe)
    existing_parts = set()
    if session_dir.exists():
        for p in session_dir.iterdir():
            if p.name.startswith("part_"):
                try:
                    existing_parts.add(int(p.name.split("_")[1]))
                except ValueError:
                    pass

    # Merge disk state with session metadata (handles cross-invocation gaps)
    all_parts = existing_parts | set(session["completed_parts"])
    missing = set(range(1, session["total_chunks"] + 1)) - all_parts
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Missing chunks: {sorted(missing)[:10]}{'...' if len(missing) > 10 else ''}. "
                   f"On Vercel, /tmp is not shared across invocations — if chunks were uploaded to "
                   f"different containers they will be missing. Consider using a smaller file or a "
                   f"persistent storage backend."
        )

    # Assemble chunks inside the session directory
    output_path = session_dir / "assembled.dmp"
    import asyncio
    
    def assemble_and_hash():
        try:
            with open(output_path, "wb") as out:
                for i in range(1, session["total_chunks"] + 1):
                    chunk_path = session_dir / f"part_{i:05d}"
                    with open(chunk_path, "rb") as cp:
                        out.write(cp.read())
        except Exception as exc:
            output_path.unlink(missing_ok=True)
            raise RuntimeError(f"Failed to assemble chunks: {exc}")

        # Verify size
        actual_size = output_path.stat().st_size
        if actual_size != session["file_size"]:
            output_path.unlink(missing_ok=True)
            raise RuntimeError(f"Size mismatch: expected {session['file_size']}, got {actual_size}")

        # Compute SHA-256 (stream to avoid loading 2 GB into memory)
        h = hashlib.sha256()
        with open(output_path, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024 * 4), b""):
                h.update(block)
        return actual_size, h.hexdigest()

    try:
        actual_size, sha256 = await asyncio.to_thread(assemble_and_hash)
    except RuntimeError as exc:
        raise HTTPException(status_code=500 if "assemble" in str(exc) else 400, detail=str(exc))


    session["assembled_path"] = str(output_path)
    session["sha256_actual"] = sha256
    UPLOAD_SESSIONS[req.upload_id] = session
    try:
        _save_session(session)
    except Exception as exc:
        logger.warning(f"Could not persist assembled session: {exc}")

    logger.info(f"Upload complete: id={req.upload_id}, size={actual_size:,}, sha256={sha256[:16]}...")
    return CompleteUploadResponse(
        upload_id=req.upload_id,
        file_key=req.upload_id,
        filename=session["filename"],
        file_size=actual_size,
        sha256=sha256,
        ready_for_analysis=True,
    )

@app.delete(
    "/api/upload/abort/{upload_id}",
    tags=["upload"],
    summary="Abort and clean up an upload session",
)
async def upload_abort(upload_id: str):
    session = _load_session(upload_id)
    UPLOAD_SESSIONS.pop(upload_id, None)
    if session:
        import shutil
        shutil.rmtree(session["session_dir"], ignore_errors=True)
    return {"upload_id": upload_id, "aborted": True}

# ---------------------------------------------------------------------------
# Routes — Analysis
# ---------------------------------------------------------------------------

@app.post(
    "/api/analyze",
    tags=["analysis"],
    summary="Analyze a dump file (direct upload, max 4MB on Vercel)",
    description="""
Upload and analyze a Windows crash dump file directly.

**⚠️ Vercel Limitation:** Vercel serverless enforces a **4.5 MB request body limit**.
For files larger than 4 MB, use the chunked upload endpoints (`/api/upload/*`) instead.

**Supported formats:**
- `.dmp` — Windows kernel minidump (64-bit or 32-bit)
- `.mdmp` — User-mode minidump (application crash)
- `.dump` — Generic dump format

**Returns:** Structured JSON with Bug Check code, system info, loaded modules, and suggested fixes.
    """,
    responses={
        200: {"description": "Analysis successful"},
        400: {"description": "Invalid file type or empty file"},
        413: {"description": "File too large: use chunked upload for files > 4 MB on Vercel"},
        500: {"description": "Analysis engine error"},
    },
)
async def analyze_dump(file: UploadFile = File(..., description="Windows dump file (.dmp, .mdmp, .dump)")):
    validate_dump_file(file)
    content = await file.read()
    file_size = len(content)

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    # Vercel hard limit: 4.5 MB. Reject anything over 4 MB with a clear message.
    if file_size > 4 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail=(
                f"File ({file_size // 1024 // 1024} MB) exceeds Vercel's 4.5 MB request body limit. "
                f"Use the chunked upload flow: POST /api/upload/init → "
                f"POST /api/upload/chunk/{{id}} (4 MB chunks) → "
                f"POST /api/upload/complete → GET /api/analyze/by-upload-id/{{id}}"
            )
        )

    temp_path = TEMP_DIR / f"dump_{uuid.uuid4().hex}.dmp"
    try:
        temp_path.write_bytes(content)
        analyzer = DumpAnalyzer()
        raw_result = analyzer.analyze(str(temp_path))
        return JSONResponse(content=format_analysis_response(raw_result, file.filename or "unknown.dmp"))
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(f"Analysis failed for {file.filename!r}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(exc)}")
    finally:
        cleanup_temp_file(temp_path)

@app.post(
    "/api/analyze/by-upload-id/{upload_id}",
    tags=["analysis"],
    summary="Analyze a previously uploaded dump file",
    description="Analyze a dump file that was uploaded via the chunked upload endpoints. Call `/api/upload/complete` first.",
)
async def analyze_by_upload_id(upload_id: str):
    session = _load_session(upload_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Upload session '{upload_id}' not found")

    assembled_path = session.get("assembled_path")
    if not assembled_path or not Path(assembled_path).exists():
        raise HTTPException(status_code=400, detail="Upload not yet completed. Call /api/upload/complete first.")

    try:
        analyzer = DumpAnalyzer()
        raw_result = analyzer.analyze(assembled_path)
        return JSONResponse(content=format_analysis_response(raw_result, session["filename"]))
    except Exception as exc:
        logger.exception(f"Analysis failed for upload {upload_id}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(exc)}")

# ---------------------------------------------------------------------------
# Routes — Bug Check Database
# ---------------------------------------------------------------------------

@app.get(
    "/api/bugchecks",
    tags=["bugchecks"],
    summary="List all known Bug Check codes",
    description="Returns the complete Bug Check code reference database with descriptions, causes, and severity ratings.",
)
async def list_bugchecks(
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
):
    """
    Query parameters:
    - **limit**: Number of results to return (default: 50, max: 200)
    - **offset**: Pagination offset
    - **severity**: Filter by severity (`critical`, `high`, `medium`, `low`)
    """
    all_codes = list(BUGCHECK_CODES.items())
    if severity:
        all_codes = [(k, v) for k, v in all_codes if v.get("severity") == severity]

    codes = [
        {
            "code": f"0x{code:08X}",
            "name": info["name"],
            "description": info["description"],
            "severity": info["severity"],
        }
        for code, info in all_codes[offset:offset + min(limit, 200)]
    ]
    return {
        "total": len(all_codes),
        "limit": limit,
        "offset": offset,
        "bugchecks": codes,
    }

@app.get(
    "/api/bugcheck/{code}",
    tags=["bugchecks"],
    summary="Get details for a specific Bug Check code",
    description="""
Retrieve full information for a specific Bug Check code.

**Code format:** Accepts both hex (`0x0000000A`) and decimal (`10`) formats.
    """,
)
async def get_bugcheck(code: str):
    try:
        code_int = int(code, 16) if code.lower().startswith("0x") else int(code)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid bug check code: {code}")
    info = get_bugcheck_info(code_int)
    if not info:
        raise HTTPException(status_code=404, detail=f"Bug check code {code} not found in database")
    return {"code": f"0x{code_int:08X}", **info}

# ---------------------------------------------------------------------------
# Routes — AI Diagnostics
# ---------------------------------------------------------------------------

AI_SYSTEM_PROMPT = """You are a senior Windows kernel crash dump analysis expert with 15+ years of experience.
Analyze the provided crash dump data and return a structured JSON diagnosis.

Rules:
1. Base your analysis strictly on the provided data. If uncertain, say so explicitly.
2. Provide TWO versions of your analysis:
   - lay_summary: For non-technical users (no jargon, max 3 sentences)
   - technical_analysis: For engineers (specific, reference memory addresses and driver names)
3. Rate your confidence 0-100 and explain why.
4. List fixes in priority order (most impactful first).
5. Never recommend deleting system files or disabling security features.
6. If language is 'ko', respond in Korean. If 'en', respond in English."""

@app.post(
    "/api/ai/diagnose",
    response_model=AIDiagnoseResponse,
    tags=["ai"],
    summary="AI-powered crash diagnosis",
    description="""
Send a dump analysis result to the LLM for deep diagnostic analysis.

The AI provides:
- Plain-language explanation for end users
- Technical root cause analysis for engineers
- Confidence scoring with reasoning
- Prioritized fix recommendations

**Requires:** `FORGE_API_KEY` environment variable to be set.

**Note:** Response time is typically 10–30 seconds.
    """,
)
async def ai_diagnose(req: AIDiagnoseRequest):
    analysis = req.analysis_result
    crash = analysis.get("crash_summary", {})
    sys_info = analysis.get("system_info", {})
    modules = analysis.get("loaded_modules", [])[:15]
    diagnosis = analysis.get("diagnosis", {})

    module_list = "\n".join(
        f"  - {m.get('name', '?')} @ {m.get('base_address', '?')} (size: {m.get('size', 0):,})"
        for m in modules
    )

    user_prompt = f"""Analyze this Windows crash dump:

## Crash Information
- Bug Check Code: {crash.get('bugcheck_code', 'N/A')} ({crash.get('bugcheck_name', 'UNKNOWN')})
- Parameters: {crash.get('bugcheck_parameters', [])}
- Crash Address: {crash.get('crash_address', 'N/A')}
- Caused By Driver: {crash.get('caused_by_driver', 'Unknown')}
- Severity: {crash.get('severity', 'unknown')}
- Dump Type: {analysis.get('dump_type', 'Unknown')}

## System Environment
- OS: {sys_info.get('os_version', 'Unknown')} ({analysis.get('architecture', 'Unknown')})
- Build: {sys_info.get('build_number', 'Unknown')}
- Processors: {sys_info.get('processor_count', 'Unknown')}

## Loaded Modules (top {len(modules)})
{module_list if module_list else '  (none)'}

## Exception Info
{json.dumps(analysis.get('exception', {}), indent=2) if analysis.get('exception') else '  (none)'}

## Rule-based Analysis
- Known Causes: {diagnosis.get('known_causes', [])}
- Basic Fixes: {diagnosis.get('suggested_fixes', [])}

Language: {req.language}

Respond with this exact JSON schema:
{{
  "lay_summary": "string",
  "technical_analysis": "string",
  "root_cause": "string",
  "confidence": 0-100,
  "confidence_reason": "string",
  "prioritized_fixes": ["string"],
  "additional_checks": ["string"],
  "severity": "critical|high|medium|low",
  "estimated_impact": "string"
}}"""

    content = await _call_llm(
        messages=[
            {"role": "system", "content": AI_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "ai_diagnosis",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "lay_summary": {"type": "string"},
                        "technical_analysis": {"type": "string"},
                        "root_cause": {"type": "string"},
                        "confidence": {"type": "integer"},
                        "confidence_reason": {"type": "string"},
                        "prioritized_fixes": {"type": "array", "items": {"type": "string"}},
                        "additional_checks": {"type": "array", "items": {"type": "string"}},
                        "severity": {"type": "string"},
                        "estimated_impact": {"type": "string"},
                    },
                    "required": ["lay_summary", "technical_analysis", "root_cause", "confidence",
                                 "confidence_reason", "prioritized_fixes", "additional_checks",
                                 "severity", "estimated_impact"],
                    "additionalProperties": False,
                },
            },
        },
    )

    try:
        result = json.loads(content)
        return AIDiagnoseResponse(**result)
    except (json.JSONDecodeError, Exception) as e:
        raise HTTPException(status_code=502, detail=f"Failed to parse AI response: {e}")

# ---------------------------------------------------------------------------
# Routes — Email Generation
# ---------------------------------------------------------------------------

EMAIL_SYSTEM_PROMPT = """You are a senior technical writer at an IT consulting firm.
Write professional customer-facing emails about Windows system crash analysis results.

Rules:
1. Use clear, non-technical language accessible to business stakeholders.
2. When using technical terms, add a brief parenthetical explanation.
3. Be factual — do not exaggerate or minimize the severity.
4. Recommendations must be specific and actionable.
5. Maintain a professional, reassuring tone.
6. If language is 'ko', write entirely in Korean. If 'en', write in English.
7. Tone variants: 'formal' = 합쇼체/formal business, 'friendly' = 해요체/warm, 'technical' = detailed with specs."""

@app.post(
    "/api/email/generate",
    response_model=EmailGenerateResponse,
    tags=["email"],
    summary="Generate customer email draft",
    description="""
Automatically generate a professional customer-facing email draft from crash analysis results.

The email includes:
1. **Analysis Overview** — When, what, and how it was analyzed
2. **Key Summary** — Plain-language description of findings
3. **Issues & Impact** — What went wrong and business implications
4. **Recommendations** — Prioritized action items with next steps

**Requires:** `FORGE_API_KEY` environment variable to be set.
    """,
)
async def email_generate(req: EmailGenerateRequest):
    analysis = req.analysis_result
    crash = analysis.get("crash_summary", {})
    sys_info = analysis.get("system_info", {})
    ai = req.ai_diagnosis or {}

    tone_desc = {"formal": "formal business (합쇼체)", "friendly": "warm and approachable (해요체)", "technical": "technical and detailed"}.get(req.tone, "formal")

    user_prompt = f"""Generate a customer email for this crash analysis:

## Analysis Data
- File: {analysis.get('filename', 'unknown.dmp')}
- Bug Check: {crash.get('bugcheck_code', 'N/A')} ({crash.get('bugcheck_name', 'UNKNOWN')})
- Severity: {crash.get('severity', 'unknown')}
- OS: {sys_info.get('os_version', 'Unknown')}
- AI Root Cause: {ai.get('root_cause', crash.get('bugcheck_description', 'Unknown'))}
- AI Summary: {ai.get('lay_summary', '')}
- Recommended Fixes: {ai.get('prioritized_fixes', analysis.get('diagnosis', {}).get('suggested_fixes', []))}
- Business Impact: {ai.get('estimated_impact', 'System instability and potential data loss')}

## Email Settings
- Customer Company: {req.customer_name}
- Contact Name: {req.contact_name or '담당자'}
- Language: {req.language}
- Tone: {tone_desc}

Respond with this exact JSON schema:
{{
  "subject": "email subject line",
  "greeting": "opening salutation",
  "overview": "2-3 sentence analysis overview",
  "key_summary": "3-5 sentence plain-language summary of findings",
  "issues_and_impact": "3-5 sentences on specific issues and business impact",
  "recommendations": "numbered list of 3-5 specific action items",
  "closing": "professional closing paragraph"
}}"""

    content = await _call_llm(
        messages=[
            {"role": "system", "content": EMAIL_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )

    try:
        # Try JSON parse first
        if content.strip().startswith("{"):
            result = json.loads(content)
        else:
            # Extract JSON from markdown code block
            import re
            match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
            result = json.loads(match.group(1)) if match else {}

        # Build full text
        full_text = f"""제목: {result.get('subject', '')}

{result.get('greeting', '')}

{result.get('overview', '')}

■ 주요 결과 요약
{result.get('key_summary', '')}

■ 발견된 이슈 및 영향도
{result.get('issues_and_impact', '')}

■ 권장 사항 및 다음 단계
{result.get('recommendations', '')}

{result.get('closing', '')}"""

        result["full_text"] = full_text
        return EmailGenerateResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to parse email response: {e}")

# ---------------------------------------------------------------------------
# Routes — PDF Generation
# ---------------------------------------------------------------------------

def _build_pdf_html(analysis: dict, ai: Optional[dict], language: str, include_modules: bool, include_watermark: bool) -> str:
    """Build a styled HTML document for PDF rendering."""
    crash = analysis.get("crash_summary", {})
    sys_info = analysis.get("system_info", {})
    modules = analysis.get("loaded_modules", [])
    diagnosis = analysis.get("diagnosis", {})

    severity_color = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#16a34a",
    }.get(crash.get("severity", "unknown"), "#6b7280")

    modules_html = ""
    if include_modules and modules:
        rows = "".join(
            f"<tr><td>{m.get('name','?')}</td><td style='font-family:monospace'>{m.get('base_address','?')}</td><td>{m.get('size',0):,}</td></tr>"
            for m in modules[:30]
        )
        modules_html = f"""
        <div class="section">
          <h2>5. 로드된 모듈 ({len(modules)}개)</h2>
          <table>
            <thead><tr><th>모듈명</th><th>기준 주소</th><th>크기 (bytes)</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""

    ai_html = ""
    if ai:
        fixes_html = "".join(f"<li>{f}</li>" for f in ai.get("prioritized_fixes", []))
        checks_html = "".join(f"<li>{c}</li>" for c in ai.get("additional_checks", []))
        ai_html = f"""
        <div class="section">
          <h2>4. AI 진단 결과</h2>
          <div class="info-box">
            <div class="label">비전문가 요약</div>
            <p>{ai.get('lay_summary','')}</p>
          </div>
          <div class="info-box">
            <div class="label">기술 심층 분석</div>
            <p>{ai.get('technical_analysis','')}</p>
          </div>
          <div class="info-box">
            <div class="label">근본 원인</div>
            <p>{ai.get('root_cause','')}</p>
          </div>
          <div class="confidence-bar">
            <div class="label">AI 신뢰도: {ai.get('confidence',0)}%</div>
            <div class="bar-bg"><div class="bar-fill" style="width:{ai.get('confidence',0)}%"></div></div>
            <small>{ai.get('confidence_reason','')}</small>
          </div>
          <div class="info-box">
            <div class="label">권장 조치 (우선순위 순)</div>
            <ol>{fixes_html}</ol>
          </div>
          <div class="info-box">
            <div class="label">추가 확인 사항</div>
            <ul>{checks_html}</ul>
          </div>
        </div>"""

    params_html = "".join(f"<li><code>{p}</code></li>" for p in crash.get("bugcheck_parameters", []))
    causes_html = "".join(f"<li>{c}</li>" for c in diagnosis.get("known_causes", []))
    fixes_html = "".join(f"<li>{f}</li>" for f in diagnosis.get("suggested_fixes", []))

    watermark = '<div class="watermark">CONFIDENTIAL</div>' if include_watermark else ""

    return f"""<!DOCTYPE html>
<html lang="{language}">
<head>
<meta charset="UTF-8">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Noto Sans KR', sans-serif; font-size: 11pt; color: #1e293b; background: #fff; }}
  .watermark {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%,-50%) rotate(-45deg);
    font-size: 80pt; color: rgba(0,0,0,0.04); font-weight: 700; pointer-events: none; z-index: 0; }}
  .cover {{ background: #0f172a; color: white; padding: 60px 50px; min-height: 200px; }}
  .cover h1 {{ font-size: 28pt; font-weight: 700; color: #38bdf8; margin-bottom: 8px; }}
  .cover h2 {{ font-size: 16pt; font-weight: 400; color: #94a3b8; margin-bottom: 30px; }}
  .cover .meta {{ font-size: 10pt; color: #64748b; }}
  .severity-badge {{ display: inline-block; padding: 6px 16px; border-radius: 4px;
    background: {severity_color}; color: white; font-weight: 700; font-size: 12pt; margin-top: 16px; }}
  .section {{ padding: 24px 50px; border-bottom: 1px solid #e2e8f0; page-break-inside: avoid; }}
  .section h2 {{ font-size: 14pt; font-weight: 700; color: #0f172a; margin-bottom: 16px;
    padding-bottom: 8px; border-bottom: 2px solid #38bdf8; }}
  .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px; }}
  .info-item {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; }}
  .info-item .label {{ font-size: 8pt; color: #64748b; font-weight: 600; text-transform: uppercase; margin-bottom: 4px; }}
  .info-item .value {{ font-size: 11pt; font-weight: 600; color: #0f172a; }}
  .info-item .value.mono {{ font-family: 'JetBrains Mono', monospace; font-size: 10pt; color: #38bdf8; }}
  .info-box {{ background: #f8fafc; border-left: 3px solid #38bdf8; padding: 12px 16px; margin-bottom: 12px; border-radius: 0 6px 6px 0; }}
  .info-box .label {{ font-size: 9pt; color: #64748b; font-weight: 600; margin-bottom: 6px; }}
  .info-box p, .info-box li {{ font-size: 10pt; line-height: 1.6; color: #334155; }}
  .info-box ol, .info-box ul {{ padding-left: 20px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 9pt; }}
  th {{ background: #0f172a; color: white; padding: 8px 10px; text-align: left; font-weight: 600; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid #e2e8f0; font-family: 'JetBrains Mono', monospace; }}
  tr:nth-child(even) td {{ background: #f8fafc; }}
  .confidence-bar {{ margin: 12px 0; }}
  .confidence-bar .label {{ font-size: 9pt; color: #64748b; font-weight: 600; margin-bottom: 4px; }}
  .bar-bg {{ background: #e2e8f0; border-radius: 4px; height: 12px; }}
  .bar-fill {{ background: #38bdf8; border-radius: 4px; height: 12px; }}
  code {{ font-family: 'JetBrains Mono', monospace; background: #f1f5f9; padding: 1px 5px; border-radius: 3px; font-size: 9pt; }}
  .footer {{ padding: 16px 50px; font-size: 8pt; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; }}
</style>
</head>
<body>
{watermark}

<div class="cover">
  <h1>BSOD Analyzer</h1>
  <h2>Windows Crash Analysis Report</h2>
  <div class="meta">
    <div>파일명: {analysis.get('filename','unknown.dmp')}</div>
    <div>분석 일시: {time.strftime('%Y-%m-%d %H:%M UTC')}</div>
    <div>덤프 유형: {analysis.get('dump_type','Unknown')} | 아키텍처: {analysis.get('architecture','Unknown')}</div>
  </div>
  <div class="severity-badge">⚠ {crash.get('severity','unknown').upper()}</div>
</div>

<div class="section">
  <h2>1. 분석 요약 (Executive Summary)</h2>
  <div class="info-grid">
    <div class="info-item">
      <div class="label">Bug Check Code</div>
      <div class="value mono">{crash.get('bugcheck_code','N/A')}</div>
    </div>
    <div class="info-item">
      <div class="label">Bug Check Name</div>
      <div class="value">{crash.get('bugcheck_name','UNKNOWN')}</div>
    </div>
    <div class="info-item">
      <div class="label">심각도</div>
      <div class="value" style="color:{severity_color}">{crash.get('severity','unknown').upper()}</div>
    </div>
    <div class="info-item">
      <div class="label">크래시 주소</div>
      <div class="value mono">{crash.get('crash_address','N/A')}</div>
    </div>
  </div>
  <div class="info-box">
    <div class="label">설명</div>
    <p>{crash.get('bugcheck_description','')}</p>
  </div>
</div>

<div class="section">
  <h2>2. 시스템 정보</h2>
  <div class="info-grid">
    <div class="info-item">
      <div class="label">운영체제</div>
      <div class="value">{sys_info.get('os_version','Unknown')}</div>
    </div>
    <div class="info-item">
      <div class="label">아키텍처</div>
      <div class="value">{analysis.get('architecture','Unknown')}</div>
    </div>
    <div class="info-item">
      <div class="label">빌드 번호</div>
      <div class="value mono">{sys_info.get('build_number','Unknown')}</div>
    </div>
    <div class="info-item">
      <div class="label">프로세서 수</div>
      <div class="value">{sys_info.get('processor_count','Unknown')}</div>
    </div>
  </div>
</div>

<div class="section">
  <h2>3. 크래시 상세 분석</h2>
  <div class="info-box">
    <div class="label">Bug Check 파라미터</div>
    <ul>{params_html}</ul>
  </div>
  <div class="info-box">
    <div class="label">알려진 원인</div>
    <ul>{causes_html}</ul>
  </div>
  <div class="info-box">
    <div class="label">기본 수정 방법</div>
    <ul>{fixes_html}</ul>
  </div>
</div>

{ai_html}

{modules_html}

<div class="section">
  <h2>{'6' if ai_html and modules_html else '5' if ai_html or modules_html else '4'}. 분석 메타데이터</h2>
  <div class="info-grid">
    <div class="info-item">
      <div class="label">파일 크기</div>
      <div class="value">{analysis.get('file_size_bytes',0):,} bytes</div>
    </div>
    <div class="info-item">
      <div class="label">분석 소요 시간</div>
      <div class="value">{analysis.get('analysis_time_seconds',0):.3f}초</div>
    </div>
  </div>
</div>

<div class="footer">
  Generated by BSOD Analyzer v2.0 · {time.strftime('%Y-%m-%d')} · This report is for diagnostic purposes only.
</div>
</body>
</html>"""

@app.post(
    "/api/pdf/generate",
    tags=["pdf"],
    summary="Generate PDF analysis report",
    description="""
Generate a structured PDF report from crash analysis results.

The PDF includes:
- Cover page with severity indicator
- Executive summary with key metrics
- System information table
- Crash analysis details with parameters
- AI diagnosis results (if provided)
- Loaded modules table (optional)
- Analysis metadata

**Returns:** PDF file as binary download (`application/pdf`).

**Note:** PDF generation takes approximately 3–8 seconds.
    """,
    response_class=Response,
    responses={
        200: {
            "description": "PDF file",
            "content": {"application/pdf": {}},
        },
        503: {"description": "PDF generation unavailable (Puppeteer not installed)"},
    },
)
async def pdf_generate(req: PDFReportRequest):
    html_content = _build_pdf_html(
        analysis=req.analysis_result,
        ai=req.ai_diagnosis,
        language=req.language,
        include_modules=req.include_modules,
        include_watermark=req.include_watermark,
    )

    # Try Puppeteer (pyppeteer) first, fall back to weasyprint
    pdf_bytes: Optional[bytes] = None

    try:
        import asyncio
        from pyppeteer import launch  # type: ignore
        browser = await launch(args=["--no-sandbox", "--disable-setuid-sandbox"])
        page = await browser.newPage()
        await page.setContent(html_content, {"waitUntil": "networkidle0"})
        pdf_bytes = await page.pdf({
            "format": "A4",
            "printBackground": True,
            "margin": {"top": "0", "bottom": "15mm", "left": "0", "right": "0"},
        })
        await browser.close()
    except ImportError:
        pass

    if pdf_bytes is None:
        try:
            from weasyprint import HTML  # type: ignore
            pdf_bytes = HTML(string=html_content).write_pdf()
        except ImportError:
            pass

    if pdf_bytes is None:
        # Return HTML as fallback with instructions
        raise HTTPException(
            status_code=503,
            detail="PDF generation requires 'pyppeteer' or 'weasyprint'. Install with: pip install pyppeteer weasyprint"
        )

    crash = req.analysis_result.get("crash_summary", {})
    filename = f"BSOD_Report_{time.strftime('%Y%m%d')}_{crash.get('bugcheck_code','UNKNOWN').replace('0x','')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.get(
    "/api/pdf/preview/{upload_id}",
    tags=["pdf"],
    summary="Preview PDF report as HTML",
    description="Returns the PDF report as HTML for browser preview. Useful for testing without PDF generation.",
    response_class=HTMLResponse,
)
async def pdf_preview_html(upload_id: str):
    """Returns the HTML that would be rendered as PDF — useful for debugging layout."""
    session = _load_session(upload_id)
    if not session or not session.get("assembled_path"):
        raise HTTPException(status_code=404, detail="Upload session not found or incomplete")

    analyzer = DumpAnalyzer()
    raw = analyzer.analyze(session["assembled_path"])
    analysis = format_analysis_response(raw, session["filename"])
    html = _build_pdf_html(analysis, None, "ko", True, False)
    return HTMLResponse(content=html)

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(status_code=404, content={"error": "Not found", "path": str(request.url.path)})

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
