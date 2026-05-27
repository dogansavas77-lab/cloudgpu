"""
CloudGPU Backend — FastAPI + PostgreSQL
Çalıştırmak için: python -m uvicorn main:app --reload
"""

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, Dict
from datetime import datetime, timedelta
import hashlib, secrets, json, asyncio, os
import psycopg2
import psycopg2.extras

app = FastAPI(title="CloudGPU API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
security = HTTPBearer()
connected_agents: Dict[str, WebSocket] = {}

DATABASE_URL = os.environ.get("DATABASE_URL", "")

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

def fetchone(cur):
    row = cur.fetchone()
    if row is None: return None
    cols = [desc[0] for desc in cur.description]
    return dict(zip(cols, row))

def fetchall(cur):
    rows = cur.fetchall()
    if not rows: return []
    cols = [desc[0] for desc in cur.description]
    return [dict(zip(cols, row)) for row in rows]

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        credit REAL DEFAULT 25.0,
        role TEXT DEFAULT 'user',
        created_at TEXT DEFAULT (NOW()::TEXT)
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS gpu_listings (
        id SERIAL PRIMARY KEY,
        provider_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        vram TEXT NOT NULL,
        tflops REAL NOT NULL,
        price_per_hour REAL NOT NULL,
        provider_share REAL DEFAULT 0.70,
        status TEXT DEFAULT 'offline',
        agent_key TEXT UNIQUE NOT NULL,
        location TEXT DEFAULT 'Bilinmiyor',
        created_at TEXT DEFAULT (NOW()::TEXT)
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS rentals (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        gpu_id INTEGER NOT NULL,
        status TEXT DEFAULT 'starting',
        ssh_host TEXT,
        ssh_port INTEGER,
        ssh_password TEXT,
        started_at TEXT DEFAULT (NOW()::TEXT),
        ended_at TEXT,
        total_cost REAL DEFAULT 0
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS pods (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        gpu TEXT NOT NULL,
        region TEXT NOT NULL,
        image TEXT NOT NULL,
        status TEXT DEFAULT 'running',
        price REAL NOT NULL,
        rental_id INTEGER,
        created_at TEXT DEFAULT (NOW()::TEXT)
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT DEFAULT (NOW()::TEXT)
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS provider_earnings (
        id SERIAL PRIMARY KEY,
        provider_id INTEGER NOT NULL,
        gpu_id INTEGER NOT NULL,
        rental_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT DEFAULT (NOW()::TEXT)
    )""")
    conn.commit()
    conn.close()
    print("✓ PostgreSQL veritabanı hazır!")

try:
    init_db()
except Exception as e:
    print(f"⚠️ DB init hatası: {e}")

def hash_password(pw): return hashlib.sha256(pw.encode()).hexdigest()

def create_token(user_id):
    token = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(days=7)).isoformat()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO tokens (token, user_id, expires_at) VALUES (%s, %s, %s)", (token, user_id, expires))
    conn.commit(); conn.close()
    return token

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT t.user_id, t.expires_at, u.name, u.email, u.credit, u.role FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = %s", (token,))
    row = fetchone(cur); conn.close()
    if not row: raise HTTPException(401, "Geçersiz oturum.")
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(): raise HTTPException(401, "Oturum süresi doldu.")
    return {"id": row["user_id"], "name": row["name"], "email": row["email"], "credit": row["credit"], "role": row["role"]}

class RegisterRequest(BaseModel):
    user_name: str; user_email: str; user_password: str; user_role: Optional[str] = "user"

class LoginRequest(BaseModel):
    user_email: str; user_password: str

class GpuListingRequest(BaseModel):
    gpu_name: str; gpu_vram: str; gpu_tflops: float; gpu_price: float; gpu_location: Optional[str] = "Türkiye"

class PodCreateRequest(BaseModel):
    pod_name: str; pod_gpu: str; pod_region: str; pod_image: str; pod_price: float; gpu_listing_id: Optional[int] = None

class UpdateSettingsRequest(BaseModel):
    new_name: Optional[str] = None; new_email: Optional[str] = None

class AdminLoginRequest(BaseModel):
    admin_email: str; admin_password: str

class AddCreditRequest(BaseModel):
    user_id: int; amount: float

ADMIN_EMAIL = "admin@cloudgpu.com"
ADMIN_PASSWORD = "admin1234"

@app.post("/auth/register")
def register(req: RegisterRequest):
    if len(req.user_password) < 8: raise HTTPException(400, "Şifre en az 8 karakter olmalıdır.")
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (req.user_email,))
    if fetchone(cur): conn.close(); raise HTTPException(400, "Bu e-posta zaten kayıtlı.")
    role = req.user_role if req.user_role in ["user","provider"] else "user"
    cur.execute("INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s) RETURNING id",
                (req.user_name, req.user_email, hash_password(req.user_password), role))
    user_id = cur.fetchone()[0]
    cur.execute("INSERT INTO transactions (user_id, description, amount) VALUES (%s, %s, %s)", (user_id, "Başlangıç kredisi 🎁", 25.0))
    conn.commit(); conn.close()
    return {"message": "Hesap oluşturuldu!", "token": create_token(user_id), "user_name": req.user_name, "credit": 25.0, "role": role}

@app.post("/auth/login")
def login(req: LoginRequest):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s AND password = %s", (req.user_email, hash_password(req.user_password)))
    user = fetchone(cur); conn.close()
    if not user: raise HTTPException(401, "E-posta veya şifre hatalı.")
    return {"token": create_token(user["id"]), "user_name": user["name"], "email": user["email"], "credit": user["credit"], "role": user["role"]}

@app.post("/auth/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM tokens WHERE token = %s", (credentials.credentials,))
    conn.commit(); conn.close()
    return {"message": "Çıkış yapıldı."}

@app.get("/me")
def get_me(user=Depends(get_current_user)): return user

@app.put("/me")
def update_me(req: UpdateSettingsRequest, user=Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    if req.new_name: cur.execute("UPDATE users SET name = %s WHERE id = %s", (req.new_name, user["id"]))
    if req.new_email:
        cur.execute("SELECT id FROM users WHERE email = %s AND id != %s", (req.new_email, user["id"]))
        if fetchone(cur): conn.close(); raise HTTPException(400, "Bu e-posta başka hesapta kullanılıyor.")
        cur.execute("UPDATE users SET email = %s WHERE id = %s", (req.new_email, user["id"]))
    conn.commit(); conn.close()
    return {"message": "Profil güncellendi."}

@app.post("/provider/gpus")
def add_gpu(req: GpuListingRequest, user=Depends(get_current_user)):
    agent_key = secrets.token_hex(24)
    conn = get_db(); cur = conn.cursor()
    cur.execute("INSERT INTO gpu_listings (provider_id, name, vram, tflops, price_per_hour, agent_key, location) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (user["id"], req.gpu_name, req.gpu_vram, req.gpu_tflops, req.gpu_price, agent_key, req.gpu_location))
    gpu_id = cur.fetchone()[0]
    conn.commit(); conn.close()
    return {"id": gpu_id, "agent_key": agent_key, "install_command": f"python agent.py --key {agent_key}"}

@app.get("/provider/gpus")
def get_provider_gpus(user=Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM gpu_listings WHERE provider_id = %s ORDER BY created_at DESC", (user["id"],))
    gpus = fetchall(cur); conn.close()
    return gpus

@app.get("/provider/earnings")
def get_earnings(user=Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT pe.*, gl.name as gpu_name FROM provider_earnings pe JOIN gpu_listings gl ON pe.gpu_id = gl.id WHERE pe.provider_id = %s ORDER BY pe.created_at DESC", (user["id"],))
    earnings = fetchall(cur)
    cur.execute("SELECT COALESCE(SUM(amount),0) as total FROM provider_earnings WHERE provider_id = %s", (user["id"],))
    total = cur.fetchone()[0]
    conn.close()
    return {"total_earnings": total, "history": earnings}

@app.delete("/provider/gpus/{gpu_id}")
def remove_gpu(gpu_id: int, user=Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM gpu_listings WHERE id = %s AND provider_id = %s", (gpu_id, user["id"]))
    if not fetchone(cur): conn.close(); raise HTTPException(404, "GPU bulunamadı.")
    cur.execute("DELETE FROM gpu_listings WHERE id = %s", (gpu_id,))
    conn.commit(); conn.close()
    return {"message": "GPU kaldırıldı."}

@app.websocket("/agent/connect/{agent_key}")
async def agent_connect(websocket: WebSocket, agent_key: str):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM gpu_listings WHERE agent_key = %s", (agent_key,))
    gpu = fetchone(cur)
    if not gpu: await websocket.close(code=4001); conn.close(); return
    gpu_id = gpu["id"]
    await websocket.accept()
    cur.execute("UPDATE gpu_listings SET status = 'available' WHERE id = %s", (gpu_id,))
    conn.commit(); conn.close()
    connected_agents[agent_key] = websocket
    print(f"✓ Agent bağlandı: GPU #{gpu_id}")
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "heartbeat":
                await websocket.send_text(json.dumps({"type": "pong"}))
            elif msg.get("type") == "pod_started":
                rental_id = msg.get("rental_id")
                db = get_db(); c = db.cursor()
                c.execute("UPDATE rentals SET status='running', ssh_host=%s, ssh_port=%s, ssh_password=%s WHERE id=%s",
                          (msg.get("ssh_host"), msg.get("ssh_port"), msg.get("ssh_password"), rental_id))
                db.commit(); db.close()
    except WebSocketDisconnect:
        connected_agents.pop(agent_key, None)
        db = get_db(); c = db.cursor()
        c.execute("UPDATE gpu_listings SET status = 'offline' WHERE id = %s", (gpu_id,))
        db.commit(); db.close()
        print(f"✗ Agent ayrıldı: GPU #{gpu_id}")

@app.get("/gpus")
def list_gpus(all: bool = False):
    conn = get_db(); cur = conn.cursor()
    if all:
        cur.execute("SELECT gl.*, u.name as provider_name FROM gpu_listings gl JOIN users u ON gl.provider_id = u.id ORDER BY gl.created_at DESC")
    else:
        cur.execute("SELECT gl.*, u.name as provider_name FROM gpu_listings gl JOIN users u ON gl.provider_id = u.id WHERE gl.status = 'available' ORDER BY gl.price_per_hour ASC")
    result = fetchall(cur); conn.close()
    if not result and not all:
        result = [
            {"id": None, "name": "RTX 4090", "vram": "24 GB", "tflops": 82.6, "price_per_hour": 0.44, "status": "available", "location": "Demo"},
            {"id": None, "name": "RTX 3090", "vram": "24 GB", "tflops": 35.6, "price_per_hour": 0.22, "status": "available", "location": "Demo"},
            {"id": None, "name": "A100 SXM", "vram": "80 GB", "tflops": 312.0, "price_per_hour": 1.89, "status": "limited", "location": "Demo"},
            {"id": None, "name": "H100 SXM", "vram": "80 GB", "tflops": 989.0, "price_per_hour": 2.49, "status": "available", "location": "Demo"},
            {"id": None, "name": "L40S", "vram": "48 GB", "tflops": 91.6, "price_per_hour": 1.14, "status": "available", "location": "Demo"},
        ]
    return result

@app.get("/pods")
def list_pods(user=Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM pods WHERE user_id = %s ORDER BY created_at DESC", (user["id"],))
    pods = fetchall(cur); conn.close()
    return pods

@app.post("/pods", status_code=201)
def create_pod(req: PodCreateRequest, user=Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT credit FROM users WHERE id = %s", (user["id"],))
    current = cur.fetchone()
    if current[0] < req.pod_price: conn.close(); raise HTTPException(400, f"Yetersiz kredi.")
    rental_id = None
    gpu_agent_key = None

    # Gerçek GPU listing varsa kiralama başlat
    if req.gpu_listing_id:
        cur.execute("SELECT * FROM gpu_listings WHERE id = %s AND status = 'available'", (req.gpu_listing_id,))
        gpu = fetchone(cur)
        if gpu:
            cur.execute("INSERT INTO rentals (user_id, gpu_id) VALUES (%s, %s) RETURNING id", (user["id"], req.gpu_listing_id))
            rental_id = cur.fetchone()[0]
            gpu_agent_key = gpu["agent_key"]
            cur.execute("UPDATE gpu_listings SET status = 'busy' WHERE id = %s", (req.gpu_listing_id,))

    cur.execute("INSERT INTO pods (user_id, name, gpu, region, image, price, rental_id) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (user["id"], req.pod_name, req.pod_gpu, req.pod_region, req.pod_image, req.pod_price, rental_id))
    pod_id = cur.fetchone()[0]
    new_credit = current[0] - req.pod_price
    cur.execute("UPDATE users SET credit = %s WHERE id = %s", (new_credit, user["id"]))
    cur.execute("INSERT INTO transactions (user_id, description, amount) VALUES (%s,%s,%s)",
                (user["id"], f"Pod: {req.pod_name}", -req.pod_price))
    conn.commit(); conn.close()

    # Agent kuyruğuna komut ekle
    if gpu_agent_key and rental_id:
        agent_commands[gpu_agent_key].append({
            "type": "start_pod",
            "rental_id": rental_id,
            "image": req.pod_image
        })

    return {"id": pod_id, "name": req.pod_name, "status": "starting", "remaining_credit": new_credit, "rental_id": rental_id}

@app.delete("/pods/{pod_id}")
def delete_pod(pod_id: int, user=Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM pods WHERE id = %s AND user_id = %s", (pod_id, user["id"]))
    if not fetchone(cur): conn.close(); raise HTTPException(404, "Pod bulunamadı.")
    cur.execute("DELETE FROM pods WHERE id = %s", (pod_id,))
    conn.commit(); conn.close()
    return {"message": "Pod silindi."}

@app.get("/transactions")
def get_transactions(user=Depends(get_current_user)):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM transactions WHERE user_id = %s ORDER BY created_at DESC", (user["id"],))
    rows = fetchall(cur); conn.close()
    return rows

@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    if req.admin_email != ADMIN_EMAIL or req.admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Hatalı admin bilgileri.")
    return {"token": "admin_" + secrets.token_hex(16), "message": "Admin girişi başarılı."}

@app.get("/admin/users")
def admin_get_users(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials.credentials.startswith("admin_"): raise HTTPException(403, "Admin yetkisi gerekli.")
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id, name, email, role, credit, created_at FROM users ORDER BY created_at DESC")
    users = fetchall(cur); conn.close()
    return users

@app.get("/admin/stats")
def admin_get_stats(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials.credentials.startswith("admin_"): raise HTTPException(403, "Admin yetkisi gerekli.")
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users"); user_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM gpu_listings"); gpu_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM gpu_listings WHERE status='available'"); online = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM rentals WHERE status='running'"); active = cur.fetchone()[0]
    cur.execute("SELECT COALESCE(SUM(amount),0) FROM provider_earnings"); rev = cur.fetchone()[0]
    conn.close()
    return {"user_count": user_count, "gpu_count": gpu_count, "online_gpus": online, "active_rentals": active, "total_revenue": round(float(rev)*0.3, 2)}

@app.post("/admin/add-credit")
def admin_add_credit(req: AddCreditRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials.credentials.startswith("admin_"): raise HTTPException(403, "Admin yetkisi gerekli.")
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT credit FROM users WHERE id = %s", (req.user_id,))
    user = cur.fetchone()
    if not user: conn.close(); raise HTTPException(404, "Kullanıcı bulunamadı.")
    new_credit = user[0] + req.amount
    cur.execute("UPDATE users SET credit = %s WHERE id = %s", (new_credit, req.user_id))
    cur.execute("INSERT INTO transactions (user_id, description, amount) VALUES (%s,%s,%s)",
                (req.user_id, "Admin tarafından kredi eklendi", req.amount))
    conn.commit(); conn.close()
    return {"message": f"${req.amount} kredi eklendi.", "new_credit": new_credit}

@app.get("/admin/rentals")
def admin_get_rentals(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials.credentials.startswith("admin_"): raise HTTPException(403, "Admin yetkisi gerekli.")
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT r.*, u.name as user_name FROM rentals r JOIN users u ON r.user_id = u.id ORDER BY r.started_at DESC")
    rows = fetchall(cur); conn.close()
    return rows

@app.get("/admin/transactions")
def admin_get_transactions(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials.credentials.startswith("admin_"): raise HTTPException(403, "Admin yetkisi gerekli.")
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT t.*, u.name as user_name FROM transactions t JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC")
    rows = fetchall(cur); conn.close()
    return rows

@app.get("/health")
def health():
    return {"status": "ok", "db": "postgresql", "time": datetime.now().isoformat()}

# ── Agent HTTP Polling Endpoint'leri ─────────────────────────
from collections import defaultdict
agent_commands = defaultdict(list)  # agent_key -> komut listesi
agent_status = {}  # agent_key -> son heartbeat zamanı

class AgentHeartbeat(BaseModel):
    agent_key: str
    status: str
    docker: Optional[bool] = False

class AgentPodStarted(BaseModel):
    agent_key: str
    rental_id: int
    ssh_host: str
    ssh_port: int
    ssh_password: str

@app.post("/agent/heartbeat")
def agent_heartbeat(req: AgentHeartbeat):
    """Agent heartbeat — GPU durumunu güncelle ve komut varsa döndür"""
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM gpu_listings WHERE agent_key = %s", (req.agent_key,))
    gpu = fetchone(cur)

    if not gpu:
        conn.close()
        raise HTTPException(404, "Agent key geçersiz.")

    # GPU durumunu güncelle
    status = "available" if req.status == "online" else "offline"
    cur.execute("UPDATE gpu_listings SET status = %s WHERE agent_key = %s", (status, req.agent_key))
    conn.commit()

    # Bekleyen komut var mı?
    command = None
    if agent_commands[req.agent_key]:
        command = agent_commands[req.agent_key].pop(0)

    agent_status[req.agent_key] = datetime.now().isoformat()
    conn.close()
    return {"status": "ok", "command": command}

@app.post("/agent/pod-started")
def agent_pod_started(req: AgentPodStarted):
    """Agent pod'u başlattığında SSH bilgilerini kaydet"""
    conn = get_db(); cur = conn.cursor()
    cur.execute(
        "UPDATE rentals SET status='running', ssh_host=%s, ssh_port=%s, ssh_password=%s WHERE id=%s",
        (req.ssh_host, req.ssh_port, req.ssh_password, req.rental_id)
    )
    conn.commit(); conn.close()
    return {"status": "ok"}

# Pod oluşturulduğunda agent'a komut kuyruğa ekle
# main.py'deki create_pod fonksiyonunu güncelle
