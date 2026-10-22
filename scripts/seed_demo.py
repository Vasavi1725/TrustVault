
"""Create challenge demo Owner/Viewer accounts and a sample document.

Set DEMO_OWNER_EMAIL, DEMO_OWNER_PASSWORD, DEMO_VIEWER_EMAIL, and
DEMO_VIEWER_PASSWORD before running. Never commit demo passwords.
"""
import hashlib
import os
import uuid

from sqlalchemy import select

from app.main import (
    Base,
    Document,
    Grant,
    SessionLocal,
    STORAGE_BACKEND,
    STORAGE_DIR,
    SUPABASE_BUCKET,
    User,
    engine,
    password_hash,
    record_audit,
    supabase_client,
)

REQUIRED = (
    "DEMO_OWNER_EMAIL",
    "DEMO_OWNER_PASSWORD",
    "DEMO_VIEWER_EMAIL",
    "DEMO_VIEWER_PASSWORD",
)

missing = [key for key in REQUIRED if not os.getenv(key)]
if missing:
    raise SystemExit("Missing required environment variables: " + ", ".join(missing))

if len(os.environ["DEMO_OWNER_PASSWORD"]) < 12 or len(os.environ["DEMO_VIEWER_PASSWORD"]) < 12:
    raise SystemExit("Demo passwords must be at least 12 characters")

owner_email = os.environ["DEMO_OWNER_EMAIL"].strip().lower()
viewer_email = os.environ["DEMO_VIEWER_EMAIL"].strip().lower()

if not owner_email or not viewer_email or owner_email == viewer_email:
    raise SystemExit("Owner and Viewer must have different, non-empty email addresses")

Base.metadata.create_all(bind=engine)
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

content = (
    b"TRUSTVAULT DEMO DOCUMENT\n"
    b"This is harmless sample content for demonstrating document permissions.\n"
    b"Do not put real confidential information in demo data.\n"
)
content_hash = hashlib.sha256(content).hexdigest()
document_title = "TrustVault Demo Contract"
uploaded_key = None

with SessionLocal() as db:
    try:
        admin = db.scalar(
            select(User).where(User.role == "admin").order_by(User.id).limit(1)
        )
        if not admin:
            raise SystemExit(
                "Start the app once first so the bootstrap administrator exists"
            )

        def get_or_create(email, password, display_name, expected_role):
            user = db.scalar(select(User).where(User.email == email))

            if user:
                if user.role != expected_role:
                    raise SystemExit(
                        f"{email} already exists with role {user.role!r}; "
                        f"expected {expected_role!r}. No password was changed."
                    )
                print(f"Account already exists: {email} (password unchanged)")
                return user

            user = User(
                email=email,
                display_name=display_name,
                password_hash=password_hash.hash(password),
                role=expected_role,
            )
            db.add(user)
            db.flush()

            record_audit(
                db,
                actor=admin,
                action="user.create",
                target_user_id=user.id,
                detail=f"Demo seed created role={expected_role}",
            )
            print(f"Created {expected_role}: {email}")
            return user

        owner = get_or_create(
            owner_email,
            os.environ["DEMO_OWNER_PASSWORD"],
            "Demo Document Owner",
            "owner",
        )
        viewer = get_or_create(
            viewer_email,
            os.environ["DEMO_VIEWER_PASSWORD"],
            "Demo Viewer",
            "viewer",
        )

        doc = db.scalar(
            select(Document).where(
                Document.title == document_title,
                Document.owner_id == owner.id,
                Document.deleted_at.is_(None),
            )
        )

        if doc:
            print(f"Sample document already exists id={doc.id}")
        else:
            stored = f"{uuid.uuid4().hex}.txt"

            if STORAGE_BACKEND == "supabase":
                supabase_client.storage.from_(SUPABASE_BUCKET).upload(
                    stored,
                    content,
                    file_options={
                        "content-type": "text/plain",
                        "upsert": "false",
                    },
                )
            else:
                (STORAGE_DIR / stored).write_bytes(content)

            uploaded_key = stored

            doc = Document(
                title=document_title,
                category="Legal",
                description="Harmless sample document for the challenge demo.",
                original_filename="demo-contract.txt",
                stored_filename=stored,
                content_type="text/plain",
                size_bytes=len(content),
                sha256=content_hash,
                owner_id=owner.id,
            )
            db.add(doc)
            db.flush()

            record_audit(
                db,
                actor=owner,
                action="document.upload",
                document_id=doc.id,
                detail=f"demo seed sha256={content_hash};size={len(content)}",
            )
            print(f"Created sample document id={doc.id}")

        grant = db.scalar(
            select(Grant).where(
                Grant.document_id == doc.id,
                Grant.user_id == viewer.id,
            )
        )

        if grant:
            print(
                f"Viewer already has {grant.permission!r} permission "
                f"for document id={doc.id}"
            )
        else:
            grant = Grant(
                document_id=doc.id,
                user_id=viewer.id,
                permission="read",
                granted_by_id=owner.id,
            )
            db.add(grant)
            db.flush()

            record_audit(
                db,
                actor=owner,
                action="permission.grant",
                document_id=doc.id,
                target_user_id=viewer.id,
                detail="demo seed permission=read",
            )
            print("Granted Viewer read-only access to the sample document")

        db.commit()
        uploaded_key = None
        print("Demo seed complete. Database changes committed.")
        print("Store demo credentials securely; never commit passwords.")

    except BaseException:
        db.rollback()

        if uploaded_key:
            try:
                if STORAGE_BACKEND == "supabase":
                    supabase_client.storage.from_(SUPABASE_BUCKET).remove(
                        [uploaded_key]
                    )
                else:
                    (STORAGE_DIR / uploaded_key).unlink(missing_ok=True)
            except Exception:
                print(
                    "WARNING: Could not clean up the newly uploaded demo file; "
                    "check storage for an orphaned object."
                )
        raise
