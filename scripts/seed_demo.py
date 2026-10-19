"""Create challenge demo Owner/Viewer accounts and a sample document.

Set DEMO_OWNER_EMAIL, DEMO_OWNER_PASSWORD, DEMO_VIEWER_EMAIL, DEMO_VIEWER_PASSWORD
in your environment before running. Never commit the passwords.
"""
import hashlib
import os
import uuid
from pathlib import Path
from sqlalchemy import select
from app.main import (Base, engine, SessionLocal, User, Document, Grant, password_hash,
                      record_audit, STORAGE_DIR, utcnow)

required = ["DEMO_OWNER_EMAIL", "DEMO_OWNER_PASSWORD", "DEMO_VIEWER_EMAIL", "DEMO_VIEWER_PASSWORD"]
missing = [name for name in required if not os.getenv(name)]
if missing:
    raise SystemExit("Missing required environment variables: " + ", ".join(missing))
if len(os.environ["DEMO_OWNER_PASSWORD"]) < 12 or len(os.environ["DEMO_VIEWER_PASSWORD"]) < 12:
    raise SystemExit("Demo passwords must be at least 12 characters")
Base.metadata.create_all(bind=engine)
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
with SessionLocal() as db:
    admin = db.scalar(select(User).where(User.role == "admin").order_by(User.id).limit(1))
    if not admin:
        raise SystemExit("Start the app once first so the bootstrap administrator exists")
    def get_or_create(email_env, password_env, display_name, role):
        email = os.environ[email_env].strip().lower()
        user = db.scalar(select(User).where(User.email == email))
        if user:
            print(f"Account already exists: {email} (password unchanged)")
            return user
        user = User(email=email, display_name=display_name, password_hash=password_hash.hash(os.environ[password_env]), role=role)
        db.add(user); db.flush()
        record_audit(db, actor=admin, action="user.create", target_user_id=user.id, detail=f"Demo seed created role={role}")
        print(f"Created {role}: {email}")
        return user
    owner = get_or_create("DEMO_OWNER_EMAIL", "DEMO_OWNER_PASSWORD", "Demo Document Owner", "owner")
    viewer = get_or_create("DEMO_VIEWER_EMAIL", "DEMO_VIEWER_PASSWORD", "Demo Viewer", "viewer")
    doc = db.scalar(select(Document).where(Document.title == "TrustVault Demo Contract", Document.owner_id == owner.id, Document.deleted_at.is_(None)))
    if not doc:
        content = b"TRUSTVAULT DEMO DOCUMENT\nThis is harmless sample content for demonstrating document permissions.\nDo not put real confidential information in demo data.\n"
        stored = f"{uuid.uuid4().hex}.txt"
        (STORAGE_DIR / stored).write_bytes(content)
        doc = Document(title="TrustVault Demo Contract", category="Legal", description="Harmless sample document for the challenge demo.",
                       original_filename="demo-contract.txt", stored_filename=stored, content_type="text/plain",
                       size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest(), owner_id=owner.id)
        db.add(doc); db.flush()
        record_audit(db, actor=owner, action="document.upload", document_id=doc.id, detail=f"demo seed sha256={doc.sha256};size={len(content)}")
        grant = Grant(document_id=doc.id, user_id=viewer.id, permission="read", granted_by_id=owner.id)
        db.add(grant)
        record_audit(db, actor=owner, action="permission.grant", document_id=doc.id, target_user_id=viewer.id, detail="demo seed permission=read")
        print(f"Created sample document id={doc.id}; viewer has read-only access")
    else:
        print(f"Sample document already exists id={doc.id}")
print("Demo seed complete. Store the credentials securely; only publish them if the challenge expects public demo credentials.")
