"""
CloudGPU Backend — FastAPI + SQLite
Çalıştırmak için: python -m uvicorn main:app --reload
"""

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime, timedelta
import sqlite3, hashlib, secrets, json, asyncio

app = FastAPI(title="CloudGPU API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()
DB_PATH = "cloudgpu.db"

# Bağlı agent'ları bellekte tut
connected_agents: Dict[str, WebSocket] = {}

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
        role TEXT DEFAULT 'user',
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL
    )""")

    # GPU sağlayıcıların eklediği GPU'lar
    c.execute("""CREATE TABLE IF NOT EXISTS gpu_listings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        vram TEXT NOT NULL,
        tflops REAL NOT NULL,
        price_per_hour REAL NOT NULL,
        provider_share REAL DEFAULT 0.70,
        status TEXT DEFAULT 'offline',
        agent_key TEXT UNIQUE NOT NULL,
        machine_id TEXT,
        location TEXT DEFAULT 'Bilinmiyor',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (provider_id) REFERENCES users(id)
    )""")

    # Kiralama işlemleri
    c.execute("""CREATE TABLE IF NOT EXISTS rentals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        gpu_id INTEGER NOT NULL,
        status TEXT DEFAULT 'starting',
        ssh_host TEXT,
        ssh_port INTEGER,
        ssh_user TEXT DEFAULT 'root',
        ssh_password TEXT,
        started_at TEXT DEFAULT (datetime('now')),
        ended_at TEXT,
        total_cost REAL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (gpu_id) REFERENCES gpu_listings(id)
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
        rental_id INTEGER,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # Sağlayıcı kazanç tablosu
    c.execute("""CREATE TABLE IF NOT EXISTS provider_earnings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider_id INTEGER NOT NULL,
        gpu_id INTEGER NOT NULL,
        rental_id INTEGER NOT NULL,
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
        "SELECT t.user_id, t.expires_at, u.name, u.email, u.credit, u.role "
        "FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ?", (token,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "Geçersiz oturum.")
    if datetime.fromisoformat(row["expires_at"]) < datetime.now():
        raise HTTPException(401, "Oturum süresi doldu.")
    return {"id": row["user_id"], "name": row["name"], "email": row["email"],
            "credit": row["credit"], "role": row["role"]}

# ── Modeller ──────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    user_name: str
    user_email: str
    user_password: str
    user_role: Optional[str] = "user"  # "user" veya "provider"

class LoginRequest(BaseModel):
    user_email: str
    user_password: str

class GpuListingRequest(BaseModel):
    gpu_name: str
    gpu_vram: str
    gpu_tflops: float
    gpu_price: float
    gpu_location: Optional[str] = "Türkiye"

class PodCreateRequest(BaseModel):
    pod_name: str
    pod_gpu: str
    pod_region: str
    pod_image: str
    pod_price: float
    gpu_listing_id: Optional[int] = None

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
    role = req.user_role if req.user_role in ["user", "provider"] else "user"
    cursor = conn.execute(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
        (req.user_name, req.user_email, hash_password(req.user_password), role)
    )
    user_id = cursor.lastrowid
    conn.execute("INSERT INTO transactions (user_id, description, amount) VALUES (?, ?, ?)",
                 (user_id, "Başlangıç kredisi 🎁", 25.0))
    conn.commit()
    conn.close()
    return {"message": "Hesap oluşturuldu!", "token": create_token(user_id),
            "user_name": req.user_name, "credit": 25.0, "role": role}

@app.post("/auth/login")
def login(req: LoginRequest):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ? AND password = ?",
                        (req.user_email, hash_password(req.user_password))).fetchone()
    conn.close()
    if not user:
        raise HTTPException(401, "E-posta veya şifre hatalı.")
    return {"token": create_token(user["id"]), "user_name": user["name"],
            "email": user["email"], "credit": user["credit"], "role": user["role"]}

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
        if conn.execute("SELECT id FROM users WHERE email = ? AND id != ?",
                        (req.new_email, user["id"])).fetchone():
            conn.close()
            raise HTTPException(400, "Bu e-posta başka hesapta kullanılıyor.")
        conn.execute("UPDATE users SET email = ? WHERE id = ?", (req.new_email, user["id"]))
    conn.commit()
    conn.close()
    return {"message": "Profil güncellendi."}

# ── GPU Sağlayıcı Endpoint'leri ───────────────────────────────
@app.post("/provider/gpus")
def add_gpu(req: GpuListingRequest, user=Depends(get_current_user)):
    """GPU sağlayıcı yeni GPU ekler"""
    agent_key = secrets.token_hex(24)  # Agent'ın bağlanmak için kullanacağı key
    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO gpu_listings (provider_id, name, vram, tflops, price_per_hour, agent_key, location) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user["id"], req.gpu_name, req.gpu_vram, req.gpu_tflops,
         req.gpu_price, agent_key, req.gpu_location)
    )
    gpu_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {
        "id": gpu_id,
        "message": "GPU eklendi! Agent kurulum talimatları aşağıda.",
        "agent_key": agent_key,
        "install_command": f"pip install cloudgpu-agent && cloudgpu-agent start --key {agent_key}"
    }

@app.get("/provider/gpus")
def get_provider_gpus(user=Depends(get_current_user)):
    """Sağlayıcının kendi GPU'larını listele"""
    conn = get_db()
    gpus = conn.execute(
        "SELECT * FROM gpu_listings WHERE provider_id = ? ORDER BY created_at DESC",
        (user["id"],)
    ).fetchall()
    conn.close()
    return [dict(g) for g in gpus]

@app.get("/provider/earnings")
def get_earnings(user=Depends(get_current_user)):
    """Sağlayıcının kazançlarını göster"""
    conn = get_db()
    earnings = conn.execute(
        "SELECT pe.*, gl.name as gpu_name FROM provider_earnings pe "
        "JOIN gpu_listings gl ON pe.gpu_id = gl.id "
        "WHERE pe.provider_id = ? ORDER BY pe.created_at DESC",
        (user["id"],)
    ).fetchall()
    total = conn.execute(
        "SELECT COALESCE(SUM(amount), 0) as total FROM provider_earnings WHERE provider_id = ?",
        (user["id"],)
    ).fetchone()["total"]
    conn.close()
    return {"total_earnings": total, "history": [dict(e) for e in earnings]}

@app.delete("/provider/gpus/{gpu_id}")
def remove_gpu(gpu_id: int, user=Depends(get_current_user)):
    """GPU'yu listeden kaldır"""
    conn = get_db()
    gpu = conn.execute(
        "SELECT * FROM gpu_listings WHERE id = ? AND provider_id = ?",
        (gpu_id, user["id"])
    ).fetchone()
    if not gpu:
        conn.close()
        raise HTTPException(404, "GPU bulunamadı.")
    conn.execute("DELETE FROM gpu_listings WHERE id = ?", (gpu_id,))
    conn.commit()
    conn.close()
    return {"message": "GPU kaldırıldı."}

# ── Agent WebSocket Bağlantısı ────────────────────────────────
@app.websocket("/agent/connect/{agent_key}")
async def agent_connect(websocket: WebSocket, agent_key: str):
    """GPU sahibinin bilgisayarındaki agent bu endpoint'e bağlanır"""
    conn = get_db()
    gpu = conn.execute(
        "SELECT * FROM gpu_listings WHERE agent_key = ?", (agent_key,)
    ).fetchone()

    if not gpu:
        await websocket.close(code=4001)
        conn.close()
        return

    gpu_id = gpu["id"]
    await websocket.accept()

    # GPU'yu online yap
    conn.execute("UPDATE gpu_listings SET status = 'available' WHERE id = ?", (gpu_id,))
    conn.commit()
    conn.close()

    connected_agents[agent_key] = websocket
    print(f"✓ Agent bağlandı: GPU #{gpu_id}")

    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)

            if msg.get("type") == "heartbeat":
                await websocket.send_text(json.dumps({"type": "pong"}))

            elif msg.get("type") == "pod_started":
                # Agent pod'u başlattı, SSH bilgilerini kaydet
                rental_id = msg.get("rental_id")
                db = get_db()
                db.execute(
                    "UPDATE rentals SET status='running', ssh_host=?, ssh_port=?, ssh_password=? WHERE id=?",
                    (msg.get("ssh_host"), msg.get("ssh_port"), msg.get("ssh_password"), rental_id)
                )
                db.commit()
                db.close()

    except WebSocketDisconnect:
        connected_agents.pop(agent_key, None)
        db = get_db()
        db.execute("UPDATE gpu_listings SET status = 'offline' WHERE id = ?", (gpu_id,))
        db.commit()
        db.close()
        print(f"✗ Agent ayrıldı: GPU #{gpu_id}")

# ── Genel GPU Listesi (Kiracılar için) ────────────────────────
@app.get("/gpus")
def list_gpus(all: bool = False, credentials: Optional[str] = None):
    """Müsait GPU'ları listele — admin için hepsini, kullanıcı için sadece available"""
    conn = get_db()

    if all:
        # Admin — tüm GPU'ları göster
        real_gpus = conn.execute(
            "SELECT gl.*, u.name as provider_name FROM gpu_listings gl "
            "JOIN users u ON gl.provider_id = u.id "
            "ORDER BY gl.created_at DESC"
        ).fetchall()
    else:
        real_gpus = conn.execute(
            "SELECT gl.*, u.name as provider_name FROM gpu_listings gl "
            "JOIN users u ON gl.provider_id = u.id "
            "WHERE gl.status = 'available' ORDER BY gl.price_per_hour ASC"
        ).fetchall()

    conn.close()
    result = [dict(g) for g in real_gpus]

    # Kullanıcı için gerçek GPU yoksa demo göster
    if not result and not all:
        result = [
            {"id": None, "name": "RTX 4090",     "vram": "24 GB", "tflops": 82.6,  "price_per_hour": 0.44, "status": "available", "location": "Demo"},
            {"id": None, "name": "RTX 3090",     "vram": "24 GB", "tflops": 35.6,  "price_per_hour": 0.22, "status": "available", "location": "Demo"},
            {"id": None, "name": "A100 SXM",     "vram": "80 GB", "tflops": 312.0, "price_per_hour": 1.89, "status": "limited",   "location": "Demo"},
            {"id": None, "name": "H100 SXM",     "vram": "80 GB", "tflops": 989.0, "price_per_hour": 2.49, "status": "available", "location": "Demo"},
            {"id": None, "name": "L40S",         "vram": "48 GB", "tflops": 91.6,  "price_per_hour": 1.14, "status": "available", "location": "Demo"},
        ]
    return result

# ── Pod / Kiralama ────────────────────────────────────────────
@app.get("/pods")
def list_pods(user=Depends(get_current_user)):
    conn = get_db()
    pods = conn.execute(
        "SELECT * FROM pods WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)
    ).fetchall()
    conn.close()
    return [dict(p) for p in pods]

@app.post("/pods", status_code=201)
def create_pod(req: PodCreateRequest, user=Depends(get_current_user)):
    conn = get_db()
    current = conn.execute("SELECT credit FROM users WHERE id = ?", (user["id"],)).fetchone()

    if current["credit"] < req.pod_price:
        conn.close()
        raise HTTPException(400, f"Yetersiz kredi. Mevcut: ${current['credit']:.2f}")

    rental_id = None

    # Gerçek GPU listing varsa kiralama başlat
    if req.gpu_listing_id:
        gpu = conn.execute(
            "SELECT * FROM gpu_listings WHERE id = ? AND status = 'available'",
            (req.gpu_listing_id,)
        ).fetchone()
        if not gpu:
            conn.close()
            raise HTTPException(400, "Bu GPU şu an müsait değil.")

        # Kiralama kaydı oluştur
        rental_cursor = conn.execute(
            "INSERT INTO rentals (user_id, gpu_id) VALUES (?, ?)",
            (user["id"], req.gpu_listing_id)
        )
        rental_id = rental_cursor.lastrowid

        # GPU'yu meşgul yap
        conn.execute("UPDATE gpu_listings SET status = 'busy' WHERE id = ?", (req.gpu_listing_id,))

        # Agent'a pod başlat komutu gönder
        agent_key = gpu["agent_key"]
        if agent_key in connected_agents:
            import asyncio
            asyncio.create_task(connected_agents[agent_key].send_text(json.dumps({
                "type": "start_pod",
                "rental_id": rental_id,
                "image": req.pod_image
            })))

    # Pod kaydı
    cursor = conn.execute(
        "INSERT INTO pods (user_id, name, gpu, region, image, price, rental_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user["id"], req.pod_name, req.pod_gpu, req.pod_region, req.pod_image, req.pod_price, rental_id)
    )
    pod_id = cursor.lastrowid

    new_credit = current["credit"] - req.pod_price
    conn.execute("UPDATE users SET credit = ? WHERE id = ?", (new_credit, user["id"]))
    conn.execute("INSERT INTO transactions (user_id, description, amount) VALUES (?, ?, ?)",
                 (user["id"], f"Pod: {req.pod_name} ({req.pod_gpu})", -req.pod_price))
    conn.commit()
    conn.close()

    return {"id": pod_id, "name": req.pod_name, "status": "starting",
            "rental_id": rental_id, "remaining_credit": new_credit}

@app.delete("/pods/{pod_id}")
def delete_pod(pod_id: int, user=Depends(get_current_user)):
    conn = get_db()
    pod = conn.execute(
        "SELECT * FROM pods WHERE id = ? AND user_id = ?", (pod_id, user["id"])
    ).fetchone()
    if not pod:
        conn.close()
        raise HTTPException(404, "Pod bulunamadı.")

    # Kiralama varsa sonlandır
    if pod["rental_id"]:
        rental = conn.execute("SELECT * FROM rentals WHERE id = ?", (pod["rental_id"],)).fetchone()
        if rental:
            gpu = conn.execute("SELECT * FROM gpu_listings WHERE id = ?", (rental["gpu_id"],)).fetchone()
            if gpu:
                conn.execute("UPDATE gpu_listings SET status = 'available' WHERE id = ?", (rental["gpu_id"],))
                # Sağlayıcı kazancını hesapla
                started = datetime.fromisoformat(rental["started_at"])
                hours = max(0.1, (datetime.now() - started).total_seconds() / 3600)
                earnings = hours * gpu["price_per_hour"] * gpu["provider_share"]
                conn.execute(
                    "INSERT INTO provider_earnings (provider_id, gpu_id, rental_id, amount) VALUES (?, ?, ?, ?)",
                    (gpu["provider_id"], gpu["id"], rental["id"], round(earnings, 4))
                )
                # Agent'a durdur komutu gönder
                if gpu["agent_key"] in connected_agents:
                    import asyncio
                    asyncio.create_task(connected_agents[gpu["agent_key"]].send_text(json.dumps({
                        "type": "stop_pod",
                        "rental_id": rental["id"]
                    })))
            conn.execute("UPDATE rentals SET status='ended', ended_at=? WHERE id=?",
                         (datetime.now().isoformat(), rental["id"]))

    conn.execute("DELETE FROM pods WHERE id = ?", (pod_id,))
    conn.commit()
    conn.close()
    return {"message": "Pod silindi."}

@app.get("/rentals/{rental_id}")
def get_rental(rental_id: int, user=Depends(get_current_user)):
    """SSH bağlantı bilgilerini al"""
    conn = get_db()
    rental = conn.execute(
        "SELECT * FROM rentals WHERE id = ? AND user_id = ?", (rental_id, user["id"])
    ).fetchone()
    conn.close()
    if not rental:
        raise HTTPException(404, "Kiralama bulunamadı.")
    return dict(rental)

# ── Fatura ────────────────────────────────────────────────────
@app.get("/transactions")
def get_transactions(user=Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ── Sağlık ────────────────────────────────────────────────────
@app.get("/health")
def health():
    conn = get_db()
    gpu_count = conn.execute("SELECT COUNT(*) as c FROM gpu_listings WHERE status='available'").fetchone()["c"]
    conn.close()
    return {"status": "ok", "available_gpus": gpu_count, "time": datetime.now().isoformat()}

# ── Admin Endpoint'leri ───────────────────────────────────────
ADMIN_EMAIL = "admin@cloudgpu.com"
ADMIN_PASSWORD = "admin1234"

class AdminLoginRequest(BaseModel):
    admin_email: str
    admin_password: str

class AddCreditRequest(BaseModel):
    user_id: int
    amount: float

@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    if req.admin_email != ADMIN_EMAIL or req.admin_password != ADMIN_PASSWORD:
        raise HTTPException(401, "Hatalı admin bilgileri.")
    token = "admin_" + secrets.token_hex(16)
    return {"token": token, "message": "Admin girişi başarılı."}

@app.get("/admin/users")
def admin_get_users(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials.credentials.startswith("admin_"):
        raise HTTPException(403, "Admin yetkisi gerekli.")
    conn = get_db()
    users = conn.execute("SELECT id, name, email, role, credit, created_at FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(u) for u in users]

@app.get("/admin/stats")
def admin_get_stats(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials.credentials.startswith("admin_"):
        raise HTTPException(403, "Admin yetkisi gerekli.")
    conn = get_db()
    user_count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    gpu_count = conn.execute("SELECT COUNT(*) as c FROM gpu_listings").fetchone()["c"]
    online_gpus = conn.execute("SELECT COUNT(*) as c FROM gpu_listings WHERE status='available'").fetchone()["c"]
    active_rentals = conn.execute("SELECT COUNT(*) as c FROM rentals WHERE status='running'").fetchone()["c"]
    total_revenue = conn.execute("SELECT COALESCE(SUM(amount),0) as t FROM provider_earnings").fetchone()["t"]
    conn.close()
    return {
        "user_count": user_count,
        "gpu_count": gpu_count,
        "online_gpus": online_gpus,
        "active_rentals": active_rentals,
        "total_revenue": round(total_revenue * 0.3, 2)
    }

@app.post("/admin/add-credit")
def admin_add_credit(req: AddCreditRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials.credentials.startswith("admin_"):
        raise HTTPException(403, "Admin yetkisi gerekli.")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (req.user_id,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, "Kullanıcı bulunamadı.")
    new_credit = user["credit"] + req.amount
    conn.execute("UPDATE users SET credit = ? WHERE id = ?", (new_credit, req.user_id))
    conn.execute("INSERT INTO transactions (user_id, description, amount) VALUES (?, ?, ?)",
                 (req.user_id, f"Admin tarafından kredi eklendi", req.amount))
    conn.commit()
    conn.close()
    return {"message": f"${req.amount} kredi eklendi.", "new_credit": new_credit}

@app.get("/admin/rentals")
def admin_get_rentals(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials.credentials.startswith("admin_"):
        raise HTTPException(403, "Admin yetkisi gerekli.")
    conn = get_db()
    rentals = conn.execute(
        "SELECT r.*, u.name as user_name, gl.name as gpu_name "
        "FROM rentals r JOIN users u ON r.user_id = u.id "
        "JOIN gpu_listings gl ON r.gpu_id = gl.id "
        "ORDER BY r.started_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rentals]

@app.get("/admin/transactions")
def admin_get_transactions(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials.credentials.startswith("admin_"):
        raise HTTPException(403, "Admin yetkisi gerekli.")
    conn = get_db()
    rows = conn.execute(
        "SELECT t.*, u.name as user_name FROM transactions t "
        "JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
