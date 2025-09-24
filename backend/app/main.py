# backend/app/main.py
from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic_settings import BaseSettings
from pydantic import BaseModel, field_validator
from sqlalchemy import create_engine, text
from minio import Minio
from web3 import Web3
from eth_account import Account
from eth_account.signers.local import LocalAccount

from typing import Optional
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import smtplib, ssl
import io
import uuid
import secrets
import hashlib
import time
import hmac
import random
import jwt

# ---------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------
class Settings(BaseSettings):
    BACKEND_PORT: int = 8000
    DATABASE_URL: str
    S3_ENDPOINT_URL: str
    S3_ACCESS_KEY: str
    S3_SECRET_KEY: str
    S3_BUCKET: str
    RPC_HTTP_URL: str
    ETH_PRIVATE_KEY: str
    COMPLAINT_REGISTRY_ADDRESS: str
    CHAIN_ID: int = 20250923

    # SMTP (Mailpit: host=mailpit, port=1025, TLS=false)
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""
    SMTP_TLS: bool = True
    FROM_EMAIL: str | None = None
    FROM_NAME: str = "Defence Cyber Portal"

    # JWT
    JWT_SECRET: str = "CHANGE_ME_RANDOM_HEX"
    JWT_ISSUER: str = "dc-portal"
    JWT_AUDIENCE: str = "dc-frontend"
    JWT_EXPIRES_MIN: int = 60


settings = Settings()
app = FastAPI(title="Defence Cyber Incident & Safety Portal - API (v1)")

# CORS for Vite
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # dev: allow everything
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)

# ---------------------------------------------------------------------
# Infra clients
# ---------------------------------------------------------------------
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)

s3_client = Minio(
    endpoint=settings.S3_ENDPOINT_URL.replace("http://", "").replace("https://", ""),
    access_key=settings.S3_ACCESS_KEY,
    secret_key=settings.S3_SECRET_KEY,
    secure=settings.S3_ENDPOINT_URL.startswith("https://"),
)
if not s3_client.bucket_exists(settings.S3_BUCKET):
    s3_client.make_bucket(settings.S3_BUCKET)

w3 = Web3(Web3.HTTPProvider(settings.RPC_HTTP_URL))
deployer: LocalAccount = Account.from_key(settings.ETH_PRIVATE_KEY)

COMPLAINT_REGISTRY_ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "_intake", "type": "address"},
            {"internalType": "address", "name": "_analysis", "type": "address"},
        ],
        "stateMutability": "nonpayable",
        "type": "constructor",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "complaintId", "type": "uint256"},
            {"internalType": "bytes32", "name": "bundleHash", "type": "bytes32"},
            {"internalType": "uint8", "name": "severityCode", "type": "uint8"},
        ],
        "name": "registerComplaint",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "complaintId", "type": "uint256"},
            {"internalType": "bytes32", "name": "evidenceHash", "type": "bytes32"},
        ],
        "name": "appendEvidence",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "complaintId", "type": "uint256"},
            {"internalType": "uint16", "name": "labelCode", "type": "uint16"},
            {"internalType": "uint8", "name": "severityCode", "type": "uint8"},
            {"internalType": "bytes32", "name": "analysisHash", "type": "bytes32"},
        ],
        "name": "recordAnalysis",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]
registry = w3.eth.contract(
    address=Web3.to_checksum_address(settings.COMPLAINT_REGISTRY_ADDRESS),
    abi=COMPLAINT_REGISTRY_ABI,
)

def _send_tx(tx_fn):
    nonce = w3.eth.get_transaction_count(deployer.address)
    tx = tx_fn.build_transaction(
        {"from": deployer.address, "nonce": nonce, "gas": 500_000, "gasPrice": 0, "chainId": settings.CHAIN_ID}
    )
    signed = deployer.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    return tx_hash.hex(), receipt.blockNumber

# ---------------------------------------------------------------------
# Auth helpers (OTP + JWT)
# ---------------------------------------------------------------------
def _hash_code(code: str) -> str:
    return hashlib.sha256(("otp-salt-v1" + code).encode()).hexdigest()

def _send_email(to_email: str, subject: str, body: str):
    from_email = settings.FROM_EMAIL or settings.SMTP_USER or "no-reply@dc-portal.local"
    msg = EmailMessage()
    msg["From"] = f"{settings.FROM_NAME} <{from_email}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    host = settings.SMTP_HOST
    port = int(settings.SMTP_PORT)
    user = (settings.SMTP_USER or "").strip()
    pwd  = (settings.SMTP_PASS or "").strip()

    try:
        if settings.SMTP_TLS and port == 587:
            with smtplib.SMTP(host, port, timeout=20) as s:
                s.ehlo(); s.starttls(context=ssl.create_default_context())
                if user and pwd: s.login(user, pwd)
                s.send_message(msg)
        elif not settings.SMTP_TLS and port == 465:
            with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=20) as s:
                if user and pwd: s.login(user, pwd)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as s:
                if user and pwd: s.login(user, pwd)
                s.send_message(msg)
    except Exception as e:
        print(f"EMAIL WARNING: {e}")
        print(f"EMAIL DEV: to={to_email} subject={subject} body={body[:120]!r}")

def _jwt_for_user(user_id: int, email: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": now,
        "exp": now + settings.JWT_EXPIRES_MIN * 60,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")

def _decode_jwt(token: str) -> dict:
    return jwt.decode(
        token, settings.JWT_SECRET, algorithms=["HS256"],
        audience=settings.JWT_AUDIENCE, issuer=settings.JWT_ISSUER,
    )

bearer = HTTPBearer(auto_error=False)

def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    if not creds:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        data = _decode_jwt(creds.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id, email, role FROM users WHERE id=:id"),
            {"id": int(data["sub"])},
        ).mappings().first()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(row)

# ---------------------------------------------------------------------
# Schema & human ID generator
# ---------------------------------------------------------------------
def init_schema():
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS otp_codes (
              id BIGSERIAL PRIMARY KEY,
              email TEXT NOT NULL UNIQUE,
              code_hash TEXT NOT NULL,
              attempts INT NOT NULL DEFAULT 0,
              max_attempts INT NOT NULL DEFAULT 5,
              expires_at TIMESTAMPTZ NOT NULL,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
              id BIGSERIAL PRIMARY KEY,
              email TEXT UNIQUE NOT NULL,
              role  TEXT NOT NULL DEFAULT 'citizen',
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS complaints (
              id BIGINT PRIMARY KEY,
              human_id TEXT UNIQUE,
              title TEXT NOT NULL,
              story TEXT NOT NULL,
              user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              status TEXT NOT NULL DEFAULT 'submitted',
              severity_initial INT,
              intake_txhash TEXT,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """))
        # make sure column exists on old dbs
        conn.execute(text("ALTER TABLE complaints ADD COLUMN IF NOT EXISTS human_id TEXT UNIQUE;"))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS evidence (
              id BIGSERIAL PRIMARY KEY,
              complaint_id BIGINT NOT NULL REFERENCES complaints(id) ON DELETE CASCADE,
              sha256 TEXT NOT NULL,
              object_name TEXT NOT NULL,
              txhash TEXT,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS analysis (
              id BIGSERIAL PRIMARY KEY,
              complaint_id BIGINT NOT NULL REFERENCES complaints(id) ON DELETE CASCADE,
              label_code SMALLINT,
              severity_code SMALLINT,
              sha256 TEXT NOT NULL,
              object_name TEXT NOT NULL,
              txhash TEXT,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS messages (
              id BIGSERIAL PRIMARY KEY,
              complaint_id BIGINT NOT NULL REFERENCES complaints(id) ON DELETE CASCADE,
              sender_role TEXT NOT NULL,
              body TEXT NOT NULL,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS notes (
              id BIGSERIAL PRIMARY KEY,
              complaint_id BIGINT NOT NULL REFERENCES complaints(id) ON DELETE CASCADE,
              author_cert_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              body TEXT NOT NULL,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """))
        # single-row state for human ID generator
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS complaint_hid_state (
              id BOOLEAN PRIMARY KEY,
              prefix CHAR(1) NOT NULL,
              seq INT NOT NULL
            );
        """))
        conn.execute(text("""
            INSERT INTO complaint_hid_state (id, prefix, seq)
            VALUES (TRUE, 'A', 0)
            ON CONFLICT (id) DO NOTHING;
        """))

@app.on_event("startup")
def on_startup():
    init_schema()

def _next_human_id(conn) -> str:
    """
    Generate next short ID like A0001..A9999, B0001.., ..., Z9999.
    Must be called inside a transaction. Uses row-level lock.
    """
    row = conn.execute(
        text("SELECT prefix, seq FROM complaint_hid_state WHERE id=TRUE FOR UPDATE")
    ).mappings().first()
    if not row:
        conn.execute(text("""
            INSERT INTO complaint_hid_state (id, prefix, seq)
            VALUES (TRUE, 'A', 0)
            ON CONFLICT (id) DO NOTHING
        """))
        row = conn.execute(
            text("SELECT prefix, seq FROM complaint_hid_state WHERE id=TRUE FOR UPDATE")
        ).mappings().first()

    prefix = row["prefix"]
    seq = int(row["seq"])

    if seq < 9999:
        seq += 1
    else:
        if prefix < 'Z':
            prefix = chr(ord(prefix) + 1)
            seq = 1
        else:
            # all Z9999 used — extremely unlikely in dev
            raise HTTPException(500, "Human ID space exhausted")

    human_id = f"{prefix}{seq:04d}"
    conn.execute(
        text("UPDATE complaint_hid_state SET prefix=:p, seq=:s WHERE id=TRUE"),
        {"p": prefix, "s": seq},
    )
    return human_id

# ---------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------
@app.get("/health")
def health():
    status = {"db": "unknown", "minio": "unknown", "rpc": "unknown", "contract": "unknown"}
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        status["db"] = "ok"
    except Exception as e:
        status["db"] = f"error: {e}"
    try:
        s3_client.list_buckets()
        status["minio"] = "ok"
    except Exception as e:
        status["minio"] = f"error: {e}"
    try:
        bn = w3.eth.block_number
        _ = registry.address
        status["rpc"] = f"ok (block {bn})"
        status["contract"] = "ok"
    except Exception as e:
        status["rpc"] = f"error: {e}"
    return {"service": "api", "status": status}

# ---------------------------------------------------------------------
# Auth (OTP + JWT)
# ---------------------------------------------------------------------
class ReqOtpBody(BaseModel):
    email: str
    role: Optional[str] = "citizen"

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if "@" not in v or not v.split("@", 1)[1]:
            raise ValueError("enter a valid email-like address")
        return v

class VerifyOtpBody(BaseModel):
    email: str
    code: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return (v or "").strip().lower()

@app.post("/auth/request-otp")
def auth_request_otp(body: ReqOtpBody):
    email = body.email.lower().strip()
    role = (body.role or "citizen").lower()

    if role == "cert":
        with engine.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM users WHERE email=:e AND role='cert'"),
                {"e": email},
            ).first()
        if not exists:
            raise HTTPException(403, "CERT account not found")

    code = f"{random.randint(0, 999999):06d}"
    code_hash = _hash_code(code)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO otp_codes (email, code_hash, expires_at, max_attempts)
            VALUES (:e, :h, :exp, 5)
            ON CONFLICT (email) DO UPDATE
            SET code_hash=EXCLUDED.code_hash,
                expires_at=EXCLUDED.expires_at,
                attempts=0,
                max_attempts=EXCLUDED.max_attempts
        """), {"e": email, "h": code_hash, "exp": expires_at})

    _send_email(
        to_email=email,
        subject="Your login code",
        body=f"Your Defence Cyber Portal login code is: {code}\nIt expires in 10 minutes.",
    )
    return {"ok": True}

@app.post("/auth/verify-otp")
def auth_verify_otp(body: VerifyOtpBody):
    email = body.email.lower().strip()
    code = body.code.strip()
    if not code.isdigit() or len(code) != 6:
        raise HTTPException(400, "Invalid code format")

    with engine.begin() as conn:
        otp = conn.execute(text("""
            SELECT id, code_hash, expires_at, attempts, max_attempts
            FROM otp_codes WHERE email=:e
        """), {"e": email}).mappings().first()

        if not otp:
            raise HTTPException(400, "No code requested")
        if otp["attempts"] >= otp["max_attempts"]:
            raise HTTPException(400, "Too many attempts")
        if datetime.now(timezone.utc) > otp["expires_at"]:
            conn.execute(text("DELETE FROM otp_codes WHERE id=:id"), {"id": otp["id"]})
            raise HTTPException(400, "Code expired")

        ok = hmac.compare_digest(_hash_code(code), otp["code_hash"])
        conn.execute(text("UPDATE otp_codes SET attempts = attempts + 1 WHERE id=:id"),
                     {"id": otp["id"]})
        if not ok:
            raise HTTPException(400, "Incorrect code")

        row = conn.execute(
            text("SELECT id, role FROM users WHERE email=:e"), {"e": email}
        ).mappings().first()
        if not row:
            conn.execute(
                text("INSERT INTO users(email, role) VALUES (:e, 'citizen')"),
                {"e": email},
            )
            row = conn.execute(
                text("SELECT id, role FROM users WHERE email=:e"), {"e": email}
            ).mappings().first()

        conn.execute(text("DELETE FROM otp_codes WHERE id=:id"), {"id": otp["id"]})

    token = _jwt_for_user(row["id"], email, row["role"])
    return {"ok": True, "token": token, "user": {"id": row["id"], "email": email, "role": row["role"]}}

# ---------------------------------------------------------------------
# WHOAMI
# ---------------------------------------------------------------------
@app.get("/whoami")
def whoami(user=Depends(get_current_user)):
    return {"id": user["id"], "email": user["email"], "role": user["role"]}

# ---------------------------------------------------------------------
# Citizen dashboard
# ---------------------------------------------------------------------
@app.get("/complaints/mine")
def complaints_mine(user=Depends(get_current_user)):
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT status, COUNT(*)::int AS n
            FROM complaints
            WHERE user_id=:uid
            GROUP BY status
        """), {"uid": int(user["id"])}).mappings().fetchall()
        counts = {r["status"]: r["n"] for r in rows}

        items = conn.execute(text("""
            SELECT id::text AS id_str, human_id, title, status,
                   severity_initial AS severity, created_at
            FROM complaints
            WHERE user_id=:uid
            ORDER BY created_at DESC
            LIMIT 100
        """), {"uid": int(user["id"])}).mappings().fetchall()

    return {
        "counts": {
            "submitted": counts.get("submitted", 0),
            "in_progress": counts.get("in_progress", 0),
            "resolved": counts.get("resolved", 0),
        },
        "items": [dict(r) for r in items],
    }

# ---------------------------------------------------------------------
# CERT dashboard
# ---------------------------------------------------------------------
@app.get("/cert/complaints")
def cert_complaints(user=Depends(get_current_user)):
    if user.get("role") != "cert":
        raise HTTPException(403, "Forbidden")
    with engine.connect() as conn:
        rows = conn.execute(text("""
            WITH latest_analysis AS (
              SELECT DISTINCT ON (complaint_id)
                complaint_id, label_code, severity_code, created_at
              FROM analysis
              ORDER BY complaint_id, created_at DESC
            )
            SELECT c.id::text AS id_str, c.human_id, c.title, c.status, c.created_at,
                   COALESCE(la.label_code, NULL) AS label_code,
                   COALESCE(la.severity_code, NULL) AS severity_code,
                   u.email AS reporter_email
            FROM complaints c
            JOIN users u ON u.id = c.user_id
            LEFT JOIN latest_analysis la ON la.complaint_id = c.id
            ORDER BY c.created_at DESC
            LIMIT 200
        """)).mappings().fetchall()
    return {"items": [dict(r) for r in rows]}

# ---------------------------------------------------------------------
# Complaint detail
# ---------------------------------------------------------------------
def _assert_can_view_complaint(cid: int, user: dict):
    if user.get("role") == "cert":
        return
    with engine.connect() as conn:
        r = conn.execute(
            text("SELECT 1 FROM complaints WHERE id=:cid AND user_id=:uid"),
            {"cid": cid, "uid": int(user["id"])},
        ).first()
    if not r:
        raise HTTPException(status_code=403, detail="Forbidden")

@app.get("/complaints/{cid}")
def complaint_detail(cid: int, user=Depends(get_current_user)):
    _assert_can_view_complaint(cid, user)
    with engine.connect() as conn:
        c = conn.execute(text("""
            SELECT id, id::text AS id_str, human_id, title, story, status,
                   severity_initial AS severity, intake_txhash, created_at, user_id
            FROM complaints WHERE id=:cid
        """), {"cid": cid}).mappings().first()
        if not c:
            raise HTTPException(404, "Not found")

        ev = conn.execute(text("""
            SELECT id, sha256, object_name, txhash, created_at
            FROM evidence WHERE complaint_id=:cid ORDER BY created_at
        """), {"cid": cid}).mappings().fetchall()

        an = conn.execute(text("""
            SELECT id, label_code, severity_code, sha256, object_name, txhash, created_at
            FROM analysis WHERE complaint_id=:cid ORDER BY created_at DESC
        """), {"cid": cid}).mappings().fetchall()

    return {"complaint": dict(c), "evidence": [dict(r) for r in ev], "analysis": [dict(r) for r in an]}

# ---------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------
class SendMessageBody(BaseModel):
    complaint_id: int
    body: str

@app.get("/messages/thread")
def messages_thread(complaint_id: int, user=Depends(get_current_user)):
    _assert_can_view_complaint(complaint_id, user)
    with engine.connect() as conn:
        msgs = conn.execute(text("""
            SELECT id, sender_role, body, created_at
            FROM messages WHERE complaint_id=:cid
            ORDER BY created_at
        """), {"cid": complaint_id}).mappings().fetchall()
    return {"items": [dict(m) for m in msgs]}

@app.post("/messages/send")
def messages_send(body: SendMessageBody, user=Depends(get_current_user)):
    _assert_can_view_complaint(body.complaint_id, user)
    sender = "cert" if user.get("role") == "cert" else "citizen"
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO messages (complaint_id, sender_role, body)
            VALUES (:cid, :role, :b)
        """), {"cid": body.complaint_id, "role": sender, "b": body.body})
    return {"ok": True}

# ---------------------------------------------------------------------
# CERT notes
# ---------------------------------------------------------------------
class AddNoteBody(BaseModel):
    complaint_id: int
    body: str

@app.post("/notes/add")
def notes_add(body: AddNoteBody, user=Depends(get_current_user)):
    if user.get("role") != "cert":
        raise HTTPException(403, "Forbidden")
    _assert_can_view_complaint(body.complaint_id, user)
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO notes (complaint_id, author_cert_id, body)
            VALUES (:cid, :uid, :b)
        """), {"cid": body.complaint_id, "uid": int(user["id"]), "b": body.body})
    return {"ok": True}

# ---------------------------------------------------------------------
# Core endpoints
# ---------------------------------------------------------------------
@app.post("/complaints/create")
async def complaints_create(
    request: Request,
    user=Depends(get_current_user),
    file: UploadFile = File(...),
    severity_code: int = Form(...),
    meta: str = Form(""),
    title: str = Form(""),
    story: str = Form(""),
):
    complaint_id = secrets.randbits(64)

    data = await file.read()
    sha = hashlib.sha256(data).hexdigest()
    evidence_bytes32 = Web3.to_bytes(hexstr=sha)

    ev_uuid = str(uuid.uuid4())
    object_name = f"complaints/{complaint_id}/evidence/{ev_uuid}/{file.filename or 'evidence.bin'}"
    s3_client.put_object(
        settings.S3_BUCKET, object_name,
        data=io.BytesIO(data), length=len(data),
        content_type=file.content_type or "application/octet-stream",
    )

    txh, blk = _send_tx(
        registry.functions.registerComplaint(complaint_id, evidence_bytes32, int(severity_code))
    )

    story = story or meta
    title = title or (file.filename or "Complaint")

    with engine.begin() as conn:
        human_id = _next_human_id(conn)  # <-- A0001..Z9999
        conn.execute(text("""
            INSERT INTO complaints (id, human_id, title, story, user_id, status, severity_initial, intake_txhash)
            VALUES (:id, :hid, :title, :story, :uid, 'submitted', :sev, :tx)
        """), dict(id=complaint_id, hid=human_id, title=title, story=story,
                   uid=int(user["id"]), sev=int(severity_code), tx=txh))
        conn.execute(text("""
            INSERT INTO evidence (complaint_id, sha256, object_name, txhash)
            VALUES (:cid, :sha, :obj, :tx)
        """), dict(cid=complaint_id, sha=sha, obj=object_name, tx=txh))

    return {
        "complaint_id": complaint_id,
        "id_str": str(complaint_id),
        "human_id": human_id,
        "sha256": sha,
        "object_name": object_name,
        "txHash": txh,
        "blockNumber": blk,
    }

@app.post("/evidence/upload")
async def evidence_upload(
    complaint_id: int = Form(...),
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    data = await file.read()
    sha = hashlib.sha256(data).hexdigest()
    evidence_bytes32 = Web3.to_bytes(hexstr=sha)
    ev_uuid = str(uuid.uuid4())
    object_name = f"complaints/{complaint_id}/evidence/{ev_uuid}/{file.filename or 'evidence.bin'}"
    s3_client.put_object(
        settings.S3_BUCKET, object_name,
        data=io.BytesIO(data), length=len(data),
        content_type=file.content_type or "application/octet-stream",
    )
    txh, blk = _send_tx(registry.functions.appendEvidence(complaint_id, evidence_bytes32))

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO evidence (complaint_id, sha256, object_name, txhash)
            VALUES (:cid, :sha, :obj, :tx)
        """), dict(cid=complaint_id, sha=sha, obj=object_name, tx=txh))

    return {
        "complaint_id": complaint_id,
        "id_str": str(complaint_id),
        "sha256": sha,
        "object_name": object_name,
        "txHash": txh,
        "blockNumber": blk,
    }

@app.post("/analysis/record")
async def analysis_record(
    complaint_id: int = Form(...),
    label_code: int = Form(...),
    severity_code: int = Form(...),
    analysis_json: UploadFile = File(...),
    user=Depends(get_current_user),
):
    if user.get("role") != "cert":
        raise HTTPException(status_code=403, detail="Forbidden")

    data = await analysis_json.read()
    sha = hashlib.sha256(data).hexdigest()
    analysis_bytes32 = Web3.to_bytes(hexstr=sha)
    an_uuid = str(uuid.uuid4())
    object_name = f"complaints/{complaint_id}/analysis/{an_uuid}/{analysis_json.filename or 'analysis.json'}"
    s3_client.put_object(
        settings.S3_BUCKET, object_name,
        data=io.BytesIO(data), length=len(data),
        content_type=analysis_json.content_type or "application/json",
    )
    txh, blk = _send_tx(
        registry.functions.recordAnalysis(complaint_id, int(label_code), int(severity_code), analysis_bytes32)
    )

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO analysis (complaint_id, label_code, severity_code, sha256, object_name, txhash)
            VALUES (:cid, :lc, :sc, :sha, :obj, :tx)
        """), dict(cid=complaint_id, lc=int(label_code), sc=int(severity_code),
                   sha=sha, obj=object_name, tx=txh))
        conn.execute(text(
            "UPDATE complaints SET status='in_progress' WHERE id=:cid AND status='submitted'"
        ), {"cid": complaint_id})

    return {
        "complaint_id": complaint_id,
        "id_str": str(complaint_id),
        "analysis_sha256": sha,
        "analysis_object": object_name,
        "txHash": txh,
        "blockNumber": blk,
    }
