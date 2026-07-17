import base64
import hashlib
import json
import math
import os
import secrets

import asyncpg
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

app = FastAPI()

# --- AYARLAR ---
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "degistir_bunu")
PASSWORD_SALT = os.environ.get("PASSWORD_SALT", "lilytaxi_varsayilan_tuz_degistir")

# Aktif (bağlı) sürücülerin anlık konumları burada tutulur (RAM, kalıcı değil)
DRIVERS = {}
# Şu an açık olan admin panel bağlantıları (bildirim yayınlamak için)
ADMIN_SOCKETS = []

DB_POOL = None
security = HTTPBasic()


def sifre_hashle(sifre: str) -> str:
    return hashlib.sha256((sifre + PASSWORD_SALT).encode()).hexdigest()


def calculate_distance(lat1, lon1, lat2, lon2):
    """İki koordinat arasındaki mesafeyi (KM) Haversine formülü ile hesaplar."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(
        math.radians(lat2)
    ) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


async def adminlere_yayinla(mesaj: str):
    kopmus_soketler = []
    for soket in ADMIN_SOCKETS:
        try:
            await soket.send_text(json.dumps({"bilgi": mesaj}))
        except Exception:
            kopmus_soketler.append(soket)
    for soket in kopmus_soketler:
        if soket in ADMIN_SOCKETS:
            ADMIN_SOCKETS.remove(soket)


def admin_auth(credentials: HTTPBasicCredentials = Depends(security)):
    dogru_kullanici = secrets.compare_digest(credentials.username, ADMIN_USER)
    dogru_sifre = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (dogru_kullanici and dogru_sifre):
        raise HTTPException(
            status_code=401,
            detail="Yetkisiz",
            headers={"WWW-Authenticate": "Basic"},
        )
    return True


def ws_admin_auth(auth_header: str) -> bool:
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:]).decode()
        kullanici, _, sifre = decoded.partition(":")
        return secrets.compare_digest(kullanici, ADMIN_USER) and secrets.compare_digest(
            sifre, ADMIN_PASSWORD
        )
    except Exception:
        return False


@app.on_event("startup")
async def startup():
    global DB_POOL
    db_url = os.environ.get("DATABASE_URL", "")
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    if not db_url:
        raise RuntimeError("DATABASE_URL ortam değişkeni bulunamadı!")
    DB_POOL = await asyncpg.create_pool(db_url)
    async with DB_POOL.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS drivers (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT now()
            )
            """
        )
        await conn.execute(
            "ALTER TABLE drivers ADD COLUMN IF NOT EXISTS sifre_metin TEXT"
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id SERIAL PRIMARY KEY,
                driver_username TEXT NOT NULL,
                nereden TEXT NOT NULL,
                nereye TEXT NOT NULL,
                fiyat TEXT NOT NULL,
                numara TEXT NOT NULL,
                durum TEXT NOT NULL DEFAULT 'bekliyor',
                created_at TIMESTAMP DEFAULT now()
            )
            """
        )
        await conn.execute(
            "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS tamamlanma_zamani TIMESTAMP"
        )


@app.on_event("shutdown")
async def shutdown():
    if DB_POOL:
        await DB_POOL.close()


# --- ŞOFÖR WEBSOCKET BAĞLANTISI (kullanıcı adı/şifre ile giriş) ---
@app.websocket("/ws/surucu")
async def surucu_websocket(websocket: WebSocket):
    await websocket.accept()
    surucu_id = None
    try:
        ilk_mesaj = await websocket.receive_text()
        giris = json.loads(ilk_mesaj)
        kullanici_adi = giris.get("kullanici_adi", "")
        sifre = giris.get("sifre", "")

        async with DB_POOL.acquire() as conn:
            kayit = await conn.fetchrow(
                "SELECT username, display_name, password_hash FROM drivers WHERE username=$1",
                kullanici_adi,
            )

        if not kayit or kayit["password_hash"] != sifre_hashle(sifre):
            await websocket.send_text(
                json.dumps(
                    {
                        "tip": "giris_sonucu",
                        "basarili": False,
                        "mesaj": "Kullanıcı adı veya şifre hatalı",
                    }
                )
            )
            await websocket.close()
            return

        await websocket.send_text(
            json.dumps(
                {"tip": "giris_sonucu", "basarili": True, "isim": kayit["display_name"]}
            )
        )

        surucu_id = kullanici_adi
        DRIVERS[surucu_id] = {
            "lat": 0.0,
            "lng": 0.0,
            "status": "Musait",
            "websocket": websocket,
            "isim": kayit["display_name"],
        }
        print(f" Sürücü giriş yaptı: {surucu_id}")

        # Bu sürücüye ait, henüz bitmemiş işleri (bekleyen/kabul edilmiş) gönder
        async with DB_POOL.acquire() as conn:
            bekleyen_isler = await conn.fetch(
                "SELECT id, nereden, nereye, fiyat, numara, durum FROM jobs "
                "WHERE driver_username=$1 AND durum IN ('bekliyor', 'kabul_edildi') "
                "ORDER BY created_at ASC",
                surucu_id,
            )
        for is_ in bekleyen_isler:
            await websocket.send_text(
                json.dumps(
                    {
                        "is_tipi": "YENI_CAGRI",
                        "id": is_["id"],
                        "nereden": is_["nereden"],
                        "nereye": is_["nereye"],
                        "fiyat": is_["fiyat"],
                        "numara": is_["numara"],
                        "kabul_edildi": is_["durum"] == "kabul_edildi",
                    }
                )
            )
            if is_["durum"] == "kabul_edildi":
                DRIVERS[surucu_id]["status"] = "Mesgul"

        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)

            if payload.get("tip") == "bildirim":
                mesaj = payload.get("mesaj", "")
                isim = DRIVERS.get(surucu_id, {}).get("isim", surucu_id)
                await adminlere_yayinla(f"[{isim}] {mesaj}")
                continue

            if payload.get("tip") == "is_durum":
                is_id = payload.get("id")
                yeni_durum = payload.get("durum")
                isim = DRIVERS.get(surucu_id, {}).get("isim", surucu_id)

                async with DB_POOL.acquire() as conn:
                    is_kaydi = await conn.fetchrow(
                        "SELECT nereden, nereye FROM jobs WHERE id=$1 AND driver_username=$2",
                        is_id, surucu_id,
                    )
                    if not is_kaydi:
                        continue

                    if yeni_durum == "kabul_edildi":
                        await conn.execute(
                            "UPDATE jobs SET durum='kabul_edildi' WHERE id=$1", is_id
                        )
                        await adminlere_yayinla(
                            f"[{isim}] ALDI: {is_kaydi['nereden']} → {is_kaydi['nereye']}"
                        )
                    elif yeni_durum == "iptal":
                        await conn.execute(
                            "UPDATE jobs SET durum='iptal' WHERE id=$1", is_id
                        )
                        await adminlere_yayinla(
                            f"[{isim}] İPTAL ETTİ: {is_kaydi['nereden']} → {is_kaydi['nereye']}"
                        )
                    elif yeni_durum == "tamamlandi":
                        await conn.execute(
                            "UPDATE jobs SET durum='tamamlandi', tamamlanma_zamani=now() WHERE id=$1",
                            is_id,
                        )
                        await adminlere_yayinla(f"[{isim}] {is_kaydi['nereden']} boş")
                continue

            if payload.get("tip") == "gecmis_getir":
                gun = payload.get("gun", "")
                async with DB_POOL.acquire() as conn:
                    kayitlar = await conn.fetch(
                        "SELECT nereden, nereye, fiyat, tamamlanma_zamani FROM jobs "
                        "WHERE driver_username=$1 AND durum='tamamlandi' "
                        "AND tamamlanma_zamani::date = $2::date "
                        "ORDER BY tamamlanma_zamani DESC",
                        surucu_id, gun,
                    )
                await websocket.send_text(
                    json.dumps(
                        {
                            "tip": "gecmis_sonuc",
                            "gun": gun,
                            "yolculuklar": [
                                {
                                    "nereden": k["nereden"],
                                    "nereye": k["nereye"],
                                    "fiyat": k["fiyat"],
                                    "saat": k["tamamlanma_zamani"].strftime("%H:%M"),
                                }
                                for k in kayitlar
                            ],
                        }
                    )
                )
                continue

            if payload.get("tip") == "kazanc_getir":
                async with DB_POOL.acquire() as conn:
                    kayitlar = await conn.fetch(
                        "SELECT tamamlanma_zamani::date AS gun, "
                        "SUM(NULLIF(regexp_replace(fiyat, '[^0-9]', '', 'g'), '')::numeric) AS toplam, "
                        "COUNT(*) AS adet "
                        "FROM jobs WHERE driver_username=$1 AND durum='tamamlandi' "
                        "GROUP BY gun ORDER BY gun DESC LIMIT 60",
                        surucu_id,
                    )
                await websocket.send_text(
                    json.dumps(
                        {
                            "tip": "kazanc_sonuc",
                            "gunler": [
                                {
                                    "gun": k["gun"].isoformat(),
                                    "toplam": float(k["toplam"] or 0),
                                    "adet": k["adet"],
                                }
                                for k in kayitlar
                            ],
                        }
                    )
                )
                continue

            if surucu_id in DRIVERS:
                DRIVERS[surucu_id]["lat"] = payload.get("lat", 0.0)
                DRIVERS[surucu_id]["lng"] = payload.get("lng", 0.0)
                DRIVERS[surucu_id]["status"] = payload.get("status", "Musait")
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f" Şoför websocket hatası: {e}")
    finally:
        if surucu_id and surucu_id in DRIVERS:
            del DRIVERS[surucu_id]
            print(f" Sürücü koptu: {surucu_id}")


# --- YÖNETİCİ PANELİ WEBSOCKET (şifre korumalı) ---
@app.websocket("/admin/ws")
async def admin_websocket(websocket: WebSocket):
    if not ws_admin_auth(websocket.headers.get("authorization")):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    ADMIN_SOCKETS.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
            hedef_surucu = payload.get("hedef_surucu")
            nereden = payload.get("nereden", "").strip()
            nereye = payload.get("nereye", "").strip()
            fiyat = payload.get("fiyat", "").strip()
            numara = payload.get("numara", "").strip()

            if not hedef_surucu:
                await websocket.send_text(
                    json.dumps({"bilgi": "Önce bir sürücü seçmelisin."})
                )
                continue

            if not (nereden and nereye and fiyat and numara):
                await websocket.send_text(
                    json.dumps({"bilgi": "Tüm alanları doldurmalısın (Nereden, Nereye, Fiyat, Numara)."})
                )
                continue

            info = DRIVERS.get(hedef_surucu)
            if not info or not info.get("websocket"):
                await websocket.send_text(
                    json.dumps({"bilgi": f"{hedef_surucu} adlı sürücü şu an bağlı değil."})
                )
                continue

            async with DB_POOL.acquire() as conn:
                yeni_id = await conn.fetchval(
                    "INSERT INTO jobs (driver_username, nereden, nereye, fiyat, numara, durum) "
                    "VALUES ($1, $2, $3, $4, $5, 'bekliyor') RETURNING id",
                    hedef_surucu, nereden, nereye, fiyat, numara,
                )

            is_emri = {
                "is_tipi": "YENI_CAGRI",
                "id": yeni_id,
                "nereden": nereden,
                "nereye": nereye,
                "fiyat": fiyat,
                "numara": numara,
                "kabul_edildi": False,
            }
            await info["websocket"].send_text(json.dumps(is_emri))
            await websocket.send_text(
                json.dumps({"bilgi": f"İş {hedef_surucu} sürücüsüne gönderildi!"})
            )
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in ADMIN_SOCKETS:
            ADMIN_SOCKETS.remove(websocket)


# --- SÜRÜCÜ HESABI EKLE / LİSTELE / SİL (admin şifreli) ---
class YeniSurucu(BaseModel):
    kullanici_adi: str
    sifre: str
    isim: str


@app.post("/admin/api/drivers")
async def surucu_ekle(surucu: YeniSurucu, yetki: bool = Depends(admin_auth)):
    async with DB_POOL.acquire() as conn:
        try:
            await conn.execute(
                "INSERT INTO drivers (username, password_hash, display_name, sifre_metin) VALUES ($1, $2, $3, $4)",
                surucu.kullanici_adi,
                sifre_hashle(surucu.sifre),
                surucu.isim,
                surucu.sifre,
            )
        except asyncpg.UniqueViolationError:
            raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten kayıtlı")
    return {"basarili": True}


@app.get("/admin/api/drivers")
async def surucu_listele(yetki: bool = Depends(admin_auth)):
    async with DB_POOL.acquire() as conn:
        kayitlar = await conn.fetch(
            "SELECT id, username, display_name, sifre_metin, created_at FROM drivers ORDER BY id DESC"
        )
    return [
        {
            "id": k["id"],
            "kullanici_adi": k["username"],
            "isim": k["display_name"],
            "sifre": k["sifre_metin"] or "—",
            "olusturma": k["created_at"].isoformat(),
        }
        for k in kayitlar
    ]


@app.delete("/admin/api/drivers/{driver_id}")
async def surucu_sil(driver_id: int, yetki: bool = Depends(admin_auth)):
    async with DB_POOL.acquire() as conn:
        await conn.execute("DELETE FROM drivers WHERE id=$1", driver_id)
    return {"basarili": True}


@app.get("/admin/api/suruculer")
async def aktif_suruculer(yetki: bool = Depends(admin_auth)):
    return {
        s_id: {"lat": info["lat"], "lng": info["lng"], "status": info["status"], "isim": info["isim"]}
        for s_id, info in DRIVERS.items()
    }


# --- HARİTALI WEB ARAYÜZÜ (şifre korumalı) ---
@app.get("/admin", response_class=HTMLResponse)
async def get_admin_panel(yetki: bool = Depends(admin_auth)):
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Taksi Yönetim Paneli</title>
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <style>
            * { box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                margin: 0;
                background: #0f172a;
                color: #e2e8f0;
            }
            #ustBaslik {
                padding: 16px 20px;
                background: #1e293b;
                border-bottom: 1px solid #334155;
            }
            #ustBaslik h3 { margin: 0; font-weight: 600; color: #f1f5f9; }
            #ustBaslik p { margin: 4px 0 0; font-size: 13px; color: #94a3b8; }
            #anaBolum {
                display: flex;
                height: 68vh;
                gap: 12px;
                padding: 12px;
            }
            #map {
                flex: 1;
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 4px 16px rgba(0,0,0,0.4);
            }
            #logPanel {
                flex: 1;
                background: #1e293b;
                border-radius: 12px;
                padding: 16px;
                overflow-y: auto;
                box-shadow: 0 4px 16px rgba(0,0,0,0.4);
                display: flex;
                flex-direction: column;
                gap: 8px;
            }
            #logPanel h4 { margin: 0 0 4px; color: #f1f5f9; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; }
            .logSatiri {
                background: #0f172a;
                border-left: 3px solid #22c55e;
                padding: 10px 12px;
                border-radius: 6px;
                font-size: 13.5px;
                color: #cbd5e1;
                animation: girisAnim 0.25s ease-out;
            }
            @keyframes girisAnim {
                from { opacity: 0; transform: translateY(-6px); }
                to { opacity: 1; transform: translateY(0); }
            }
            #altBolum {
                padding: 16px 20px 32px;
                display: flex;
                gap: 16px;
                align-items: flex-start;
            }
            #panel {
                background: #1e293b;
                border-radius: 12px;
                padding: 18px;
                box-shadow: 0 4px 16px rgba(0,0,0,0.4);
                width: 220px;
                height: 220px;
                flex-shrink: 0;
                display: flex;
                flex-direction: column;
            }
            #panel h4 { margin: 0 0 12px; color: #f1f5f9; font-size: 14px; }
            #panel .satir { display: flex; flex-direction: column; gap: 8px; flex: 1; }
            #panel input {
                padding: 8px 10px;
                border-radius: 8px;
                border: 1px solid #334155;
                background: #0f172a;
                color: #e2e8f0;
                font-size: 13px;
                width: 100%;
            }
            #panel button, #isFormuKutu button {
                padding: 9px 14px;
                border-radius: 8px;
                border: none;
                background: #22c55e;
                color: white;
                font-weight: 600;
                cursor: pointer;
                font-size: 13px;
            }
            #ekleSonuc { font-size: 12px; color: #94a3b8; margin-top: 4px; }
            #surucuListesiPaneli {
                flex: 1;
                background: #1e293b;
                border-radius: 12px;
                padding: 18px;
                box-shadow: 0 4px 16px rgba(0,0,0,0.4);
                height: 320px;
                display: flex;
                flex-direction: column;
            }
            #surucuListesiPaneli h4 { margin: 0 0 10px; color: #f1f5f9; font-size: 14px; }
            #surucuArama {
                padding: 9px 12px;
                border-radius: 8px;
                border: 1px solid #334155;
                background: #0f172a;
                color: #e2e8f0;
                font-size: 13px;
                margin-bottom: 10px;
            }
            #surucuSatirlari {
                overflow-y: auto;
                flex: 1;
                display: flex;
                flex-direction: column;
                gap: 8px;
            }
            .surucuSatir {
                background: #0f172a;
                border-radius: 8px;
                padding: 10px 12px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 10px;
            }
            .surucuSatir .bilgi { font-size: 13px; color: #cbd5e1; line-height: 1.5; }
            .surucuSatir .bilgi b { color: #f1f5f9; font-size: 14px; }
            .surucuSatir button {
                padding: 7px 12px;
                border-radius: 6px;
                border: none;
                background: #dc2626;
                color: white;
                cursor: pointer;
                font-size: 12px;
                font-weight: 600;
                flex-shrink: 0;
            }
            #isFormuOrtusu {
                display: none;
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: rgba(0,0,0,0.6);
                align-items: center; justify-content: center;
                z-index: 1000;
            }
            #isFormuKutu {
                background: #1e293b; padding: 24px; border-radius: 12px;
                width: 320px; max-width: 90%;
                box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            }
            #isFormuKutu h4 { margin-top: 0; color: #f1f5f9; }
            #isFormuKutu label { display: block; margin-top: 12px; font-size: 13px; font-weight: 600; color: #94a3b8; }
            #isFormuKutu input {
                width: 100%; padding: 10px; margin-top: 4px; box-sizing: border-box;
                border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0;
            }
            #isFormuKutu .butonlar { margin-top: 18px; display: flex; gap: 8px; justify-content: flex-end; }
            #isFormuKutu .butonlar button:first-child { background: #475569; }
        </style>
    </head>
    <body>
        <div id="ustBaslik">
            <h3>Canlı Takip Paneli</h3>
            <p>İş vermek için haritadaki bir sürücüye tıkla</p>
        </div>

        <div id="anaBolum">
            <div id="map"></div>
            <div id="logPanel">
                <h4>Canlı Akış</h4>
                <div id="logIcerik"></div>
            </div>
        </div>

        <div id="isFormuOrtusu">
            <div id="isFormuKutu">
                <h4 id="isFormuBaslik">İş Ver</h4>
                <label>Nereden:</label>
                <input id="formNereden" placeholder="örn. Kadıköy İskele" />
                <label>Nereye:</label>
                <input id="formNereye" placeholder="örn. Taksim Meydanı" />
                <label>Fiyat:</label>
                <input id="formFiyat" placeholder="örn. 450 TL" />
                <label>Numara:</label>
                <input id="formNumara" placeholder="örn. 0532 000 00 00" />
                <div class="butonlar">
                    <button onclick="isFormuKapat()">İptal</button>
                    <button onclick="isFormuGonder()">Gönder</button>
                </div>
            </div>
        </div>

        <div id="altBolum">
            <div id="panel">
                <h4>Yeni Sürücü Ekle</h4>
                <div class="satir">
                    <input id="yeniKullaniciAdi" placeholder="Kullanıcı adı" />
                    <input id="yeniSifre" placeholder="Şifre" />
                    <input id="yeniIsim" placeholder="Görünen isim / tabela" />
                    <button onclick="surucuEkle()">Ekle</button>
                </div>
                <div id="ekleSonuc"></div>
            </div>
            <div id="surucuListesiPaneli">
                <h4>Kayıtlı Sürücüler</h4>
                <input id="surucuArama" placeholder="Sürücü ara (isim veya kullanıcı adı)..." oninput="surucuListesiniFiltreleVeGoster()" />
                <div id="surucuSatirlari"></div>
            </div>
        </div>

        <script>
            var map = L.map('map', {zoomControl: true}).setView([41.0082, 28.9784], 11);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
            var surucuMarkerlari = {};
            var secilenSurucuId = null;
            var logIcerik = document.getElementById('logIcerik');
            var ws = new WebSocket("wss://" + window.location.host + "/admin/ws");

            function arabaIkonu(renk) {
                var svg = '<svg width="34" height="34" viewBox="0 0 24 24" style="filter: drop-shadow(0 2px 3px rgba(0,0,0,0.5));">' +
                    '<path fill="' + renk + '" d="M18.92 6.01C18.72 5.42 18.16 5 17.5 5h-11c-.66 0-1.21.42-1.42 1.01L3 12v8c0 .55.45 1 1 1h1c.55 0 1-.45 1-1v-1h12v1c0 .55.45 1 1 1h1c.55 0 1-.45 1-1v-8l-2.08-5.99zM6.5 16c-.83 0-1.5-.67-1.5-1.5S5.67 13 6.5 13s1.5.67 1.5 1.5S7.33 16 6.5 16zm11 0c-.83 0-1.5-.67-1.5-1.5s.67-1.5 1.5-1.5 1.5.67 1.5 1.5-.67 1.5-1.5 1.5zM5 11l1.5-4.5h11L19 11H5z"/>' +
                    '</svg>';
                return L.divIcon({
                    html: svg,
                    className: '',
                    iconSize: [34, 34],
                    iconAnchor: [17, 17],
                    popupAnchor: [0, -17]
                });
            }
            var maviIkon = arabaIkonu('#3b82f6');
            var kirmiziIkon = arabaIkonu('#ef4444');

            function logaYaz(mesaj) {
                var satir = document.createElement('div');
                satir.className = 'logSatiri';
                var simdi = new Date().toLocaleTimeString('tr-TR');
                satir.innerHTML = '<b>' + simdi + '</b> — ' + mesaj;
                logIcerik.insertBefore(satir, logIcerik.firstChild);
            }

            ws.onmessage = function(event) {
                var data = JSON.parse(event.data);
                if (data.bilgi) { logaYaz(data.bilgi); }
            };

            logaYaz('Sistem hazır. Şoförlerin bağlanması bekleniyor...');

            function isVerFormAc(surucuId, surucuIsim) {
                secilenSurucuId = surucuId;
                document.getElementById('isFormuBaslik').innerText = 'İş Ver: ' + surucuIsim;
                document.getElementById('formNereden').value = '';
                document.getElementById('formNereye').value = '';
                document.getElementById('formFiyat').value = '';
                document.getElementById('formNumara').value = '';
                document.getElementById('isFormuOrtusu').style.display = 'flex';
            }

            function isFormuKapat() {
                document.getElementById('isFormuOrtusu').style.display = 'none';
                secilenSurucuId = null;
            }

            function isFormuGonder() {
                var nereden = document.getElementById('formNereden').value.trim();
                var nereye = document.getElementById('formNereye').value.trim();
                var fiyat = document.getElementById('formFiyat').value.trim();
                var numara = document.getElementById('formNumara').value.trim();

                if (!nereden || !nereye || !fiyat || !numara) {
                    alert('Lütfen tüm alanları doldur: Nereden, Nereye, Fiyat, Numara.');
                    return;
                }

                ws.send(JSON.stringify({
                    hedef_surucu: secilenSurucuId,
                    nereden: nereden,
                    nereye: nereye,
                    fiyat: fiyat,
                    numara: numara
                }));

                isFormuKapat();
            }

            function suruculeriGuncelle() {
                fetch('/admin/api/suruculer').then(res => res.json()).then(suruculer => {
                    for (var id in suruculer) {
                        var s = suruculer[id];
                        if (s.lat === 0) continue;
                        var isim = s.isim || id;
                        var ikon = (s.status === 'Musait') ? maviIkon : kirmiziIkon;
                        var popupHtml = '<b>' + isim + '</b><br>' +
                            'Durum: ' + s.status + '<br>' +
                            '<button onclick="isVerFormAc(&quot;' + id + '&quot;, &quot;' + isim + '&quot;)">İş Ver</button>';
                        if (surucuMarkerlari[id]) {
                            surucuMarkerlari[id].setLatLng([s.lat, s.lng]);
                            surucuMarkerlari[id].setPopupContent(popupHtml);
                            surucuMarkerlari[id].setIcon(ikon);
                        } else {
                            surucuMarkerlari[id] = L.marker([s.lat, s.lng], {icon: ikon}).addTo(map).bindPopup(popupHtml);
                        }
                    }
                    // Artık bağlı olmayan sürücülerin ikonlarını kaldır
                    for (var id in surucuMarkerlari) {
                        if (!suruculer[id]) {
                            map.removeLayer(surucuMarkerlari[id]);
                            delete surucuMarkerlari[id];
                        }
                    }
                });
            }
            setInterval(suruculeriGuncelle, 3000);
            suruculeriGuncelle();

            var tumSuruculerListesi = [];

            function surucuListesiniYukle() {
                fetch('/admin/api/drivers').then(res => res.json()).then(liste => {
                    tumSuruculerListesi = liste;
                    surucuListesiniFiltreleVeGoster();
                });
            }

            function surucuListesiniFiltreleVeGoster() {
                var arama = document.getElementById('surucuArama').value.trim().toLowerCase();
                var filtreli = tumSuruculerListesi.filter(function(s) {
                    return s.isim.toLowerCase().indexOf(arama) !== -1 ||
                           s.kullanici_adi.toLowerCase().indexOf(arama) !== -1;
                });
                var kapsayici = document.getElementById('surucuSatirlari');
                kapsayici.innerHTML = '';
                if (filtreli.length === 0) {
                    kapsayici.innerHTML = '<div style="color:#64748b; font-size:13px;">Sonuç bulunamadı.</div>';
                    return;
                }
                filtreli.forEach(function(s) {
                    var satir = document.createElement('div');
                    satir.className = 'surucuSatir';
                    satir.innerHTML =
                        '<div class="bilgi"><b>' + s.isim + '</b><br>' +
                        s.kullanici_adi + ' &middot; ' + s.sifre + '</div>' +
                        '<button onclick="surucuSil(' + s.id + ')">Sil</button>';
                    kapsayici.appendChild(satir);
                });
            }

            function surucuEkle() {
                var kullaniciAdi = document.getElementById('yeniKullaniciAdi').value.trim();
                var sifre = document.getElementById('yeniSifre').value;
                var isim = document.getElementById('yeniIsim').value.trim();
                if (!kullaniciAdi || !sifre || !isim) {
                    document.getElementById('ekleSonuc').innerText = ' Tüm alanları doldur.';
                    return;
                }
                fetch('/admin/api/drivers', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({kullanici_adi: kullaniciAdi, sifre: sifre, isim: isim})
                }).then(res => res.json().then(data => ({status: res.status, data: data})))
                  .then(({status, data}) => {
                    if (status === 200) {
                        document.getElementById('ekleSonuc').innerText = ' Eklendi!';
                        document.getElementById('yeniKullaniciAdi').value = '';
                        document.getElementById('yeniSifre').value = '';
                        document.getElementById('yeniIsim').value = '';
                        surucuListesiniYukle();
                    } else {
                        document.getElementById('ekleSonuc').innerText = ' Hata: ' + (data.detail || 'bilinmeyen hata');
                    }
                  });
            }

            function surucuSil(id) {
                if (!confirm('Bu sürücüyü silmek istediğine emin misin?')) return;
                fetch('/admin/api/drivers/' + id, {method: 'DELETE'}).then(function() {
                    surucuListesiniYukle();
                });
            }

            surucuListesiniYukle();
        </script>
    </body>
    </html>
    """


@app.get("/")
async def kok():
    return RedirectResponse(url="/admin")


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
