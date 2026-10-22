from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File, Form, Query, status
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import (create_engine, String, Integer, DateTime, ForeignKey, Text, Boolean,
                        select, or_, and_, desc, func)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
load_dotenv(ROOT_DIR / ".env")
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", str(ROOT_DIR / "private_uploads"))).resolve()
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT_DIR / 'trustvault.db'}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"): ]

# Production must use an external PostgreSQL database. SQLite remains suitable
# for local development and isolated tests, but must not be used accidentally in
# a deployed production service where its local filesystem may be ephemeral.
if (
    os.getenv("ENVIRONMENT", "development").lower() == "production"
    and DATABASE_URL.startswith("sqlite")
):
    raise RuntimeError(
        "Production requires PostgreSQL through DATABASE_URL. "
        "SQLite is allowed only for local development and testing."
    )

AUDIT_KEY = os.getenv("AUDIT_HMAC_KEY", "development-only-change-this-secret-please")
if os.getenv("ENVIRONMENT", "development") == "production":
    if len(AUDIT_KEY) < 32 or "development-only" in AUDIT_KEY:
        raise RuntimeError("Set AUDIT_HMAC_KEY to a random secret of at least 32 characters in production")
    if len(os.getenv("SESSION_SECRET", "")) < 32 or "dev-session" in os.getenv("SESSION_SECRET", ""):
        raise RuntimeError("Set SESSION_SECRET to a random secret of at least 32 characters in production")
    if os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "ChangeMe-Admin-2026!") == "ChangeMe-Admin-2026!":
        raise RuntimeError("Set a unique BOOTSTRAP_ADMIN_PASSWORD in production")
    if os.getenv("SESSION_COOKIE_SECURE", "false").lower() != "true":
        raise RuntimeError("SESSION_COOKIE_SECURE must be true in production")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(20), index=True)  # admin, owner, viewer
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: utcnow())

class Document(Base):
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200), index=True)
    category: Mapped[str] = mapped_column(String(80), index=True)
    description: Mapped[str] = mapped_column(String(1000), default="")
    original_filename: Mapped[str] = mapped_column(String(255))
    stored_filename: Mapped[str] = mapped_column(String(80), unique=True)
    content_type: Mapped[str] = mapped_column(String(120))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: utcnow(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: utcnow())
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    owner: Mapped[User] = relationship()

class Grant(Base):
    __tablename__ = "document_grants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    permission: Mapped[str] = mapped_column(String(10))  # read or edit
    granted_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: utcnow())

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: utcnow(), index=True)
    actor_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    actor_email: Mapped[str] = mapped_column(String(320), default="anonymous")
    action: Mapped[str] = mapped_column(String(80), index=True)
    document_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    target_user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    outcome: Mapped[str] = mapped_column(String(20))
    detail: Mapped[str] = mapped_column(String(1000), default="")
    previous_hash: Mapped[str] = mapped_column(String(64), default="0" * 64)
    event_hash: Mapped[str] = mapped_column(String(64), index=True)

class PasswordHash:
    """PBKDF2-HMAC-SHA256 password hashing using Python's standard library.

    Argon2id is preferable where available; PBKDF2 is used here to keep the
    starter runnable without a native crypto dependency. Tune iterations to deployment hardware.
    """
    iterations = 600_000
    @classmethod
    def hash(cls, password: str) -> str:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), cls.iterations).hex()
        return f"pbkdf2_sha256${cls.iterations}${salt}${digest}"
    @classmethod
    def verify(cls, password: str, encoded: str) -> bool:
        try:
            scheme, iterations, salt, expected = encoded.split("$", 3)
            if scheme != "pbkdf2_sha256": return False
            actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations)).hex()
            return hmac.compare_digest(actual, expected)
        except (ValueError, TypeError):
            return False

password_hash = PasswordHash


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



def audit_payload(
    *,
    at,
    actor_id,
    actor_email,
    action,
    document_id,
    target_user_id,
    outcome,
    detail,
    previous_hash,
):
    # Normalize timestamps to naive UTC so the HMAC payload is
    # consistent whether the database returns a naive or aware datetime.
    if at.tzinfo is not None:
        at = at.astimezone(timezone.utc).replace(tzinfo=None)

    return json.dumps(
        {
            "at": at.isoformat(),
            "actor_id": actor_id,
            "actor_email": actor_email,
            "action": action,
            "document_id": document_id,
            "target_user_id": target_user_id,
            "outcome": outcome,
            "detail": detail,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def record_audit(db: Session, *, actor: Optional[User], action: str, document_id: Optional[int] = None,
                 target_user_id: Optional[int] = None, outcome: str = "success", detail: str = ""):
    # Serialize PostgreSQL chain appends so concurrent requests cannot fork the chain.
    if engine.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(74281931)"))
    # HMAC chain detects edits/deletions/reordering if AUDIT_HMAC_KEY is kept outside the DB.
    last = db.scalar(select(AuditEvent).order_by(desc(AuditEvent.id)).limit(1))
    at = utcnow()
    prev = last.event_hash if last else "0" * 64
    actor_id = actor.id if actor else None
    actor_email = actor.email if actor else "anonymous"
    safe_detail = detail[:1000]
    payload = audit_payload(at=at, actor_id=actor_id, actor_email=actor_email, action=action,
                            document_id=document_id, target_user_id=target_user_id, outcome=outcome,
                            detail=safe_detail, previous_hash=prev)
    digest = hmac.new(AUDIT_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    db.add(AuditEvent(at=at, actor_id=actor_id, actor_email=actor_email, action=action,
                      document_id=document_id, target_user_id=target_user_id, outcome=outcome,
                      detail=safe_detail, previous_hash=prev, event_hash=digest))
    db.commit()


def verify_audit_chain(db: Session) -> bool:
    previous = "0" * 64
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
    for event in events:
        if not hmac.compare_digest(event.previous_hash, previous):
            return False
        payload = audit_payload(at=event.at, actor_id=event.actor_id, actor_email=event.actor_email,
                                action=event.action, document_id=event.document_id,
                                target_user_id=event.target_user_id, outcome=event.outcome,
                                detail=event.detail, previous_hash=event.previous_hash)
        expected = hmac.new(AUDIT_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(event.event_hash, expected):
            return False
        previous = event.event_hash
    return True



def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.session.get("session_token")

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    session = db.scalar(
        select(LoginSession).where(LoginSession.token_hash == token_hash)
    )

    if not session or session.revoked_at:
        request.session.clear()
        raise HTTPException(
            status_code=401,
            detail="Session expired or revoked",
        )

    # Normalize the expiry timestamp to naive UTC, matching utcnow().
    expires_at = session.expires_at

    if expires_at.tzinfo is not None:
        expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)

    if expires_at <= utcnow():
        request.session.clear()
        raise HTTPException(
            status_code=401,
            detail="Session expired or revoked",
        )

    user = db.get(User, session.user_id)

    if not user or not user.active:
        request.session.clear()
        raise HTTPException(
            status_code=401,
            detail="Account inactive",
        )

    return user


class LoginSession(Base):
    __tablename__ = "login_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: utcnow())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


def require_role(*roles: str):
    def dependency(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return dependency


def get_document(db: Session, document_id: int) -> Document:
    doc = db.get(Document, document_id)
    if not doc or doc.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc


def can_read(db: Session, user: User, doc: Document) -> bool:
    if user.role == "admin" or doc.owner_id == user.id:
        return True
    grant = db.scalar(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == user.id))
    return grant is not None and grant.permission in ("read", "edit")


def can_edit(db: Session, user: User, doc: Document) -> bool:
    if user.role == "admin" or doc.owner_id == user.id:
        return True
    grant = db.scalar(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == user.id))
    return grant is not None and grant.permission == "edit"


def require_read(db: Session, user: User, doc: Document):
    if not can_read(db, user, doc):
        record_audit(db, actor=user, action="document.read", document_id=doc.id, outcome="denied", detail="Permission check failed")
        raise HTTPException(status_code=403, detail="Document access denied")


def require_edit(db: Session, user: User, doc: Document):
    if not can_edit(db, user, doc):
        record_audit(db, actor=user, action="document.edit", document_id=doc.id, outcome="denied", detail="Permission check failed")
        raise HTTPException(status_code=403, detail="Document edit denied")


app = FastAPI(title="TrustVault API", version="1.0.0", description="Secure document sharing with HMAC-chained audit trail")

@app.middleware("http")
async def enforce_same_origin_mutations(request: Request, call_next):
    # SameSite=Strict is the primary CSRF barrier; reject cross-origin unsafe requests as defense in depth.
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.headers.get("origin"):
        origin = urlsplit(request.headers["origin"])
        if origin.netloc.lower() != request.headers.get("host", "").lower():
            return JSONResponse(status_code=403, content={"detail": "Cross-origin mutation rejected"})
    return await call_next(request)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "dev-session-secret-change-me"),
                   session_cookie="trustvault_session", same_site="strict", https_only=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true", max_age=12*3600)
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    # Defense in depth: ordinary SQL cannot update/delete audit rows. A DB superuser can still
    # alter schema, so production should also export signed checkpoints to separate immutable storage.
    with engine.begin() as conn:
        if engine.dialect.name == "sqlite":
            conn.exec_driver_sql("CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END")
            conn.exec_driver_sql("CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END")
        elif engine.dialect.name == "postgresql":
            conn.exec_driver_sql("CREATE OR REPLACE FUNCTION trustvault_reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are append-only'; END; $$")
            conn.exec_driver_sql("DROP TRIGGER IF EXISTS audit_no_update_delete ON audit_events")
            conn.exec_driver_sql("CREATE TRIGGER audit_no_update_delete BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION trustvault_reject_audit_mutation()")
    with SessionLocal() as db:
        admin_email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com").lower()
        if not db.scalar(select(User).where(User.email == admin_email)):
            admin = User(email=admin_email, display_name="TrustVault Admin",
                         password_hash=password_hash.hash(os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "ChangeMe-Admin-2026!")), role="admin")
            db.add(admin)
            db.commit()

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home(request: Request):
    return templates.TemplateResponse(
    request=request,
    name="index.html",
    context={"max_upload_mb": MAX_UPLOAD_MB},
)

@app.get("/health")
def health():
    return {"status": "ok"}

class LoginBody(BaseModel):
    email: str
    password: str

class UserCreate(BaseModel):
    email: str
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=128)
    role: str

class GrantBody(BaseModel):
    user_id: int
    permission: str

class DocumentUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=1000)

@app.post("/api/auth/login")
def login(body: LoginBody, request: Request, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    if not user or not user.active or not password_hash.verify(body.password, user.password_hash):
        record_audit(db, actor=user, action="auth.login", outcome="denied", detail="Invalid credentials")
        raise HTTPException(status_code=401, detail="Invalid email or password")
    # Rotate session identifier and store only its hash in the database.
    raw = secrets.token_urlsafe(32)
    ttl = int(os.getenv("SESSION_TTL_HOURS", "12"))
    db.add(LoginSession(user_id=user.id, token_hash=hashlib.sha256(raw.encode()).hexdigest(), expires_at=utcnow()+timedelta(hours=ttl)))
    record_audit(db, actor=user, action="auth.login", detail="Login succeeded")
    request.session.clear()
    request.session["session_token"] = raw
    return {"id": user.id, "email": user.email, "display_name": user.display_name, "role": user.role}

@app.post("/api/auth/logout")
def logout(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    raw = request.session.get("session_token", "")
    s = db.scalar(select(LoginSession).where(LoginSession.token_hash == hashlib.sha256(raw.encode()).hexdigest()))
    if s:
        s.revoked_at = utcnow()
    record_audit(db, actor=user, action="auth.logout", detail="Session revoked")
    request.session.clear()
    return {"ok": True}

@app.get("/api/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "display_name": user.display_name, "role": user.role}

@app.post("/api/admin/users", status_code=201)
def create_user(body: UserCreate, db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    email = body.email.strip().lower()
    if body.role not in ("owner", "viewer", "admin"):
        raise HTTPException(status_code=422, detail="Role must be admin, owner, or viewer")
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email already exists")
    user = User(email=email, display_name=body.display_name.strip(), password_hash=password_hash.hash(body.password), role=body.role)
    db.add(user); db.flush(); db.refresh(user)
    record_audit(db, actor=admin, action="user.create", target_user_id=user.id, detail=f"Created role={user.role}")
    return {"id": user.id, "email": user.email, "display_name": user.display_name, "role": user.role}

@app.get("/api/users")
def list_users(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # Names/emails are exposed to authenticated users to allow named grants; no password fields are returned.
    return [{"id": u.id, "email": u.email, "display_name": u.display_name, "role": u.role}
            for u in db.scalars(select(User).where(User.active.is_(True)).order_by(User.display_name)).all()]

@app.post("/api/documents", status_code=201)
async def upload_document(title: str = Form(...), category: str = Form(...), description: str = Form(""),
                          file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(require_role("owner", "admin"))):
    title = title.strip(); category = category.strip()
    if not title or len(title) > 200 or not category or len(category) > 80 or len(description) > 1000:
        raise HTTPException(status_code=422, detail="Invalid title, category, or description")
    # Allow a conservative set of document types; never trust client-provided content type alone.
    allowed = {".pdf": {"application/pdf"}, ".txt": {"text/plain"}, ".csv": {"text/csv", "application/vnd.ms-excel"},
               ".png": {"image/png"}, ".jpg": {"image/jpeg"}, ".jpeg": {"image/jpeg"}}
    original = Path(file.filename or "upload").name[:255]
    ext = Path(original).suffix.lower()
    if ext not in allowed:
        raise HTTPException(status_code=415, detail="Allowed file types: PDF, TXT, CSV, PNG, JPG")
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if not data:
        raise HTTPException(status_code=422, detail="Empty files are not allowed")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds {MAX_UPLOAD_MB} MB limit")
    # Basic magic-byte validation for formats with signatures; TXT/CSV are decoded strictly.
    signatures = {".pdf": data.startswith(b"%PDF-"), ".png": data.startswith(b"\x89PNG\r\n\x1a\n"),
                  ".jpg": data.startswith(b"\xff\xd8\xff"), ".jpeg": data.startswith(b"\xff\xd8\xff")}
    if ext in signatures and not signatures[ext]:
        raise HTTPException(status_code=415, detail="File content does not match its extension")
    if ext in (".txt", ".csv"):
        try: data.decode("utf-8")
        except UnicodeDecodeError: raise HTTPException(status_code=415, detail="Text files must be UTF-8")
    stored = f"{uuid.uuid4().hex}{ext}"
    target = STORAGE_DIR / stored
    # Filesystem path is generated by the server and is never derived from user input.
    target.write_bytes(data)
    doc = Document(title=title, category=category, description=description.strip(), original_filename=original,
                   stored_filename=stored, content_type=(file.content_type or mimetypes.guess_type(original)[0] or "application/octet-stream"),
                   size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), owner_id=user.id)
    db.add(doc); db.flush(); db.refresh(doc)
    record_audit(db, actor=user, action="document.upload", document_id=doc.id, detail=f"sha256={doc.sha256};size={len(data)}")
    return document_json(doc, user)


def document_json(doc: Document, user: User):
    return {"id": doc.id, "title": doc.title, "category": doc.category, "description": doc.description,
            "original_filename": doc.original_filename, "content_type": doc.content_type, "size_bytes": doc.size_bytes,
            "sha256": doc.sha256, "owner_id": doc.owner_id, "owner_email": doc.owner.email,
            "created_at": doc.created_at.isoformat(), "updated_at": doc.updated_at.isoformat()}

@app.get("/api/documents")
def search_documents(q: Optional[str] = None, owner: Optional[str] = None, category: Optional[str] = None,
                     date_from: Optional[str] = None, date_to: Optional[str] = None,
                     db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # Query only documents this user may read. Admin sees all non-deleted documents.
    stmt = select(Document).where(Document.deleted_at.is_(None))
    if user.role != "admin":
        grants = select(Grant.document_id).where(Grant.user_id == user.id)
        stmt = stmt.where(or_(Document.owner_id == user.id, Document.id.in_(grants)))
    if q: stmt = stmt.where(or_(Document.title.ilike(f"%{q}%"), Document.original_filename.ilike(f"%{q}%"), Document.description.ilike(f"%{q}%")))
    if category: stmt = stmt.where(Document.category.ilike(f"%{category}%"))
    if owner: stmt = stmt.join(User, Document.owner_id == User.id).where(User.email.ilike(f"%{owner}%"))
    if date_from: stmt = stmt.where(Document.created_at >= datetime.fromisoformat(date_from))
    if date_to: stmt = stmt.where(Document.created_at < datetime.fromisoformat(date_to) + timedelta(days=1))
    docs = db.scalars(stmt.order_by(desc(Document.created_at)).limit(200)).unique().all()
    visible = [d for d in docs if can_read(db, user, d)]
    record_audit(db, actor=user, action="document.search", outcome="success", detail=f"results={len(visible)}")
    return [document_json(d, user) for d in visible]

@app.get("/api/documents/{document_id}")
def get_document_detail(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document(db, document_id); require_read(db, user, doc)
    record_audit(db, actor=user, action="document.view", document_id=doc.id)
    return document_json(doc, user)

@app.get("/api/documents/{document_id}/download")
def download_document(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document(db, document_id); require_read(db, user, doc)
    path = STORAGE_DIR / doc.stored_filename
    if not path.is_file():
        record_audit(db, actor=user, action="document.download", document_id=doc.id, outcome="error", detail="Stored file missing")
        raise HTTPException(status_code=404, detail="Stored file not found")
    # Re-check hash before serving to detect accidental/tampered file contents.
    content = path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), doc.sha256):
        record_audit(db, actor=user, action="document.download", document_id=doc.id, outcome="error", detail="Integrity check failed")
        raise HTTPException(status_code=500, detail="File integrity check failed")
    record_audit(db, actor=user, action="document.download", document_id=doc.id, detail=f"sha256={doc.sha256}")
    return FileResponse(path, media_type="application/octet-stream", filename=doc.original_filename, headers={"X-Content-Type-Options":"nosniff", "Cache-Control":"no-store"})

@app.patch("/api/documents/{document_id}")
def update_document(document_id: int, body: DocumentUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document(db, document_id); require_edit(db, user, doc)
    doc.title = body.title.strip(); doc.category = body.category.strip(); doc.description = body.description.strip(); doc.updated_at = utcnow()
    record_audit(db, actor=user, action="document.update", document_id=doc.id, detail="Document metadata fields updated")
    return document_json(doc, user)

@app.delete("/api/documents/{document_id}")
def delete_document(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    doc = get_document(db, document_id)

    # Editing metadata does not grant permission to delete the document.
    # Only its owner or an administrator may delete it.
    if user.role != "admin" and doc.owner_id != user.id:
        record_audit(
            db,
            actor=user,
            action="document.delete",
            document_id=doc.id,
            outcome="denied",
            detail="Only owner/admin can delete",
        )
        raise HTTPException(
            status_code=403,
            detail="Only the owner or administrator can delete this document",
        )

    # Soft-delete preserves audit references and removes active access.
    doc.deleted_at = utcnow()
    record_audit(
        db,
        actor=user,
        action="document.delete",
        document_id=doc.id,
        detail="Soft deleted",
    )
    return {"ok": True}

@app.put("/api/documents/{document_id}/grants")
def grant_access(document_id: int, body: GrantBody, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document(db, document_id)
    if user.role != "admin" and doc.owner_id != user.id:
        record_audit(db, actor=user, action="permission.grant", document_id=doc.id, target_user_id=body.user_id, outcome="denied", detail="Only owner/admin can grant")
        raise HTTPException(status_code=403, detail="Only the owner or administrator can grant access")
    if body.permission not in ("read", "edit"):
        raise HTTPException(status_code=422, detail="Permission must be read or edit")
    target = db.get(User, body.user_id)
    if not target or not target.active: raise HTTPException(status_code=404, detail="Target user not found")
    if target.id == doc.owner_id: raise HTTPException(status_code=422, detail="Owner already has access")
    grant = db.scalar(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == target.id))
    if grant:
        grant.permission = body.permission; grant.granted_by_id = user.id; grant.created_at = utcnow()
    else:
        grant = Grant(document_id=doc.id, user_id=target.id, permission=body.permission, granted_by_id=user.id)
        db.add(grant)
    record_audit(db, actor=user, action="permission.grant", document_id=doc.id, target_user_id=target.id, detail=f"permission={body.permission}")
    return {"document_id": doc.id, "user_id": target.id, "permission": body.permission}

@app.delete("/api/documents/{document_id}/grants/{target_user_id}")
def revoke_access(document_id: int, target_user_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document(db, document_id)
    if user.role != "admin" and doc.owner_id != user.id:
        record_audit(db, actor=user, action="permission.revoke", document_id=doc.id, target_user_id=target_user_id, outcome="denied", detail="Only owner/admin can revoke")
        raise HTTPException(status_code=403, detail="Only the owner or administrator can revoke access")
    grant = db.scalar(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == target_user_id))
    if not grant: raise HTTPException(status_code=404, detail="Grant not found")
    db.delete(grant)
    record_audit(db, actor=user, action="permission.revoke", document_id=doc.id, target_user_id=target_user_id, detail="Grant deleted; subsequent requests denied")
    return {"ok": True}

@app.get("/api/documents/{document_id}/grants")
def list_grants(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document(db, document_id)
    if user.role != "admin" and doc.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Only owner/admin can view grants")
    rows = db.execute(select(Grant, User).join(User, Grant.user_id == User.id).where(Grant.document_id == doc.id)).all()
    return [{"user_id": u.id, "email": u.email, "display_name": u.display_name, "permission": g.permission, "granted_at": g.created_at.isoformat()} for g,u in rows]

@app.get("/api/admin/audit")
def admin_audit(limit: int = Query(default=200, ge=1, le=1000), outcome: Optional[str] = None,
                db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    stmt = select(AuditEvent)
    if outcome in ("success", "denied", "error"): stmt = stmt.where(AuditEvent.outcome == outcome)
    events = db.scalars(stmt.order_by(desc(AuditEvent.id)).limit(limit)).all()
    return [{"id": e.id, "at": e.at.isoformat(), "actor_id": e.actor_id, "actor_email": e.actor_email,
             "action": e.action, "document_id": e.document_id, "target_user_id": e.target_user_id,
             "outcome": e.outcome, "detail": e.detail, "event_hash": e.event_hash} for e in events]

@app.get("/api/admin/audit/verify")
def audit_verify(db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    ok = verify_audit_chain(db)
    record_audit(db, actor=user, action="audit.verify", outcome="success" if ok else "error", detail="Audit chain verification")
    return {"valid": ok, "message": "Audit chain is intact" if ok else "Audit chain integrity failure"}

@app.get("/api/admin/summary")
def admin_summary(db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    return {"users": db.scalar(select(func.count(User.id))) or 0,
            "active_documents": db.scalar(select(func.count(Document.id)).where(Document.deleted_at.is_(None))) or 0,
            "denied_events": db.scalar(select(func.count(AuditEvent.id)).where(AuditEvent.outcome == "denied")) or 0,
            "permission_changes": db.scalar(select(func.count(AuditEvent.id)).where(AuditEvent.action.in_(["permission.grant", "permission.revoke"]))) or 0,
            "audit_chain_valid": verify_audit_chain(db)}
