"""
CloudGPU Backend — FastAPI + SQLite
Çalıştırmak için: python -m uvicorn main:app --reload
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import sqlite3, hashlib, secrets

app = FastAPI(title="CloudGPU API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()
DB_PATH = "cloudgpu.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        credit REAL DEFAULT 25.0,
        created_at TEXT DEFAULT (datetime('now'))
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS pods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        gpu TEXT NOT NULL,
        region TEXT NOT NULL,
        image TEXT NOT NULL,
        status TEXT DEFAULT 'running',
        price REAL NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )""")
    conn.commit()
    conn.close()
    print("✓ Veritabanı hazır:", DB_PATH)

init_db()

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def create_token(user_id: int) -> str:
    token = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(days=7)).isoformat()
    conn = get_db()
    conn.execute("INSERT INTO tokens (token, user_id, expires_at) VALUES (?, ?, ?)", (token, user_id, expires))
    conn.commit()
    conn.close()
    return token

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    conn = get_db()
    row = conn.execute(
        "SELECT t.user_id, t.expires_at, u.name, u.email, u.credit "
        "FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ?", (token,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "Geçersiz oturum.")
    if datetime.fromisoformat(row["expires_at"]) < datetime.now():
        raise HTTPException(401, "Oturum süresi doldu.")
    return {"id": row["user_id"], "name": row["name"], "email": row["email"], "credit": row["credit"]}

# ── Modeller ──────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    user_name: str
    user_email: str
    user_password: str

class LoginRequest(BaseModel):
    user_email: str
    user_password: str

class PodCreateRequest(BaseModel):
    pod_name: str
    pod_gpu: str
    pod_region: str
    pod_image: str
    pod_price: float

class UpdateSettingsRequest(BaseModel):
    new_name: Optional[str] = None
    new_email: Optional[str] = None

# ── Auth ──────────────────────────────────────────────────────
@app.post("/auth/register")
def register(req: RegisterRequest):
    if len(req.user_password) < 8:
        raise HTTPException(400, "Şifre en az 8 karakter olmalıdır.")
    conn = get_db()
    if conn.execute("SELECT id FROM users WHERE email = ?", (req.user_email,)).fetchone():
        conn.close()
        raise HTTPException(400, "Bu e-posta zaten kayıtlı.")
    cursor = conn.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                          (req.user_name, req.user_email, hash_password(req.user_password)))
    user_id = cursor.lastrowid
    conn.execute("INSERT INTO transactions (user_id, description, amount) VALUES (?, ?, ?)",
                 (user_id, "Başlangıç kredisi 🎁", 25.0))
    conn.commit()
    conn.close()
    return {"message": "Hesap oluşturuldu!", "token": create_token(user_id), "user_name": req.user_name, "credit": 25.0}

@app.post("/auth/login")
def login(req: LoginRequest):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ? AND password = ?",
                        (req.user_email, hash_password(req.user_password))).fetchone()
    conn.close()
    if not user:
        raise HTTPException(401, "E-posta veya şifre hatalı.")
    return {"token": create_token(user["id"]), "user_name": user["name"], "email": user["email"], "credit": user["credit"]}

@app.post("/auth/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    conn = get_db()
    conn.execute("DELETE FROM tokens WHERE token = ?", (credentials.credentials,))
    conn.commit()
    conn.close()
    return {"message": "Çıkış yapıldı."}

@app.get("/me")
def get_me(user=Depends(get_current_user)):
    return user

@app.put("/me")
def update_me(req: UpdateSettingsRequest, user=Depends(get_current_user)):
    conn = get_db()
    if req.new_name:
        conn.execute("UPDATE users SET name = ? WHERE id = ?", (req.new_name, user["id"]))
    if req.new_email:
        if conn.execute("SELECT id FROM users WHERE email = ? AND id != ?", (req.new_email, user["id"])).fetchone():
            conn.close()
            raise HTTPException(400, "Bu e-posta başka hesapta kullanılıyor.")
        conn.execute("UPDATE users SET email = ? WHERE id = ?", (req.new_email, user["id"]))
    conn.commit()
    conn.close()
    return {"message": "Profil güncellendi."}

# ── GPU ───────────────────────────────────────────────────────
@app.get("/gpus")
def list_gpus():
    return [
        {"name": "RTX 4090",     "type": "Consumer",     "vram": "24 GB", "tflops": 82.6,  "price": 0.44, "availability": "available"},
        {"name": "RTX 3090",     "type": "Consumer",     "vram": "24 GB", "tflops": 35.6,  "price": 0.22, "availability": "available"},
        {"name": "A100 SXM",     "type": "Data Center",  "vram": "80 GB", "tflops": 312.0, "price": 1.89, "availability": "limited"},
        {"name": "H100 SXM",     "type": "Data Center",  "vram": "80 GB", "tflops": 989.0, "price": 2.49, "availability": "available"},
        {"name": "L40S",         "type": "Professional", "vram": "48 GB", "tflops": 91.6,  "price": 1.14, "availability": "available"},
        {"name": "RTX 6000 Ada", "type": "Professional", "vram": "48 GB", "tflops": 91.1,  "price": 0.88, "availability": "limited"},
        {"name": "A40",          "type": "Data Center",  "vram": "48 GB", "tflops": 37.4,  "price": 0.76, "availability": "available"},
        {"name": "RTX 4000 Ada", "type": "Professional", "vram": "20 GB", "tflops": 26.7,  "price": 0.38, "availability": "unavailable"},
    ]

# ── Pods ──────────────────────────────────────────────────────
@app.get("/pods")
def list_pods(user=Depends(get_current_user)):
    conn = get_db()
    pods = conn.execute("SELECT * FROM pods WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
    conn.close()
    return [dict(p) for p in pods]

@app.post("/pods", status_code=201)
def create_pod(req: PodCreateRequest, user=Depends(get_current_user)):
    conn = get_db()
    current = conn.execute("SELECT credit FROM users WHERE id = ?", (user["id"],)).fetchone()
    if current["credit"] < req.pod_price:
        conn.close()
        raise HTTPException(400, f"Yetersiz kredi. Mevcut: ${current['credit']:.2f}")
    cursor = conn.execute(
        "INSERT INTO pods (user_id, name, gpu, region, image, price) VALUES (?, ?, ?, ?, ?, ?)",
        (user["id"], req.pod_name, req.pod_gpu, req.pod_region, req.pod_image, req.pod_price)
    )
    pod_id = cursor.lastrowid
    new_credit = current["credit"] - req.pod_price
    conn.execute("UPDATE users SET credit = ? WHERE id = ?", (new_credit, user["id"]))
    conn.execute("INSERT INTO transactions (user_id, description, amount) VALUES (?, ?, ?)",
                 (user["id"], f"Pod: {req.pod_name} ({req.pod_gpu})", -req.pod_price))
    conn.commit()
    conn.close()
    return {"id": pod_id, "name": req.pod_name, "status": "running", "remaining_credit": new_credit}

@app.delete("/pods/{pod_id}")
def delete_pod(pod_id: int, user=Depends(get_current_user)):
    conn = get_db()
    pod = conn.execute("SELECT * FROM pods WHERE id = ? AND user_id = ?", (pod_id, user["id"])).fetchone()
    if not pod:
        conn.close()
        raise HTTPException(404, "Pod bulunamadı.")
    conn.execute("DELETE FROM pods WHERE id = ?", (pod_id,))
    conn.commit()
    conn.close()
    return {"message": "Pod silindi."}

# ── Fatura ────────────────────────────────────────────────────
@app.get("/transactions")
def get_transactions(user=Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ── Sağlık ────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now().isoformat()}
