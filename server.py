import base64
import hashlib
import json
import math
import os
import re
import secrets
from datetime import datetime, timedelta

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


def surum_tuple(surum_adi: str):
    """'1.2.3' -> (1, 2, 3) şeklinde karşılaştırılabilir bir değere çevirir."""
    parcalar = re.findall(r"\d+", surum_adi)
    return tuple(int(p) for p in parcalar) if parcalar else (0,)


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


async def adminlere_sohbet_yayinla(
    kullanici_adi: str, isim: str, gonderen: str, mesaj: str, mesaj_id: int, tip: str
):
    veri = json.dumps(
        {
            "tip": "sohbet_bildirim",
            "kullanici_adi": kullanici_adi,
            "isim": isim,
            "gonderen": gonderen,
            "mesaj": mesaj,
            "id": mesaj_id,
            "mesaj_tipi": tip,
        }
    )
    kopmus_soketler = []
    for soket in ADMIN_SOCKETS:
        try:
            await soket.send_text(veri)
        except Exception:
            kopmus_soketler.append(soket)
    for soket in kopmus_soketler:
        if soket in ADMIN_SOCKETS:
            ADMIN_SOCKETS.remove(soket)


async def adminlere_mesaj_silindi_yayinla(kullanici_adi: str, mesaj_id: int):
    veri = json.dumps(
        {"tip": "mesaj_silindi", "kullanici_adi": kullanici_adi, "id": mesaj_id}
    )
    kopmus_soketler = []
    for soket in ADMIN_SOCKETS:
        try:
            await soket.send_text(veri)
        except Exception:
            kopmus_soketler.append(soket)
    for soket in kopmus_soketler:
        if soket in ADMIN_SOCKETS:
            ADMIN_SOCKETS.remove(soket)


async def secili_suruculere_yayinla(kullanici_adlari: list, veri: dict):
    metin = json.dumps(veri)
    for kullanici_adi in kullanici_adlari:
        info = DRIVERS.get(kullanici_adi)
        if info and info.get("websocket"):
            try:
                await info["websocket"].send_text(metin)
            except Exception:
                pass


async def tum_suruculere_yayinla(veri: dict):
    metin = json.dumps(veri)
    for info in list(DRIVERS.values()):
        if info.get("websocket"):
            try:
                await info["websocket"].send_text(metin)
            except Exception:
                pass


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


def ws_token_dogrula(token: str) -> bool:
    if not token:
        return False
    try:
        decoded = base64.b64decode(token).decode()
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
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_version (
                id INTEGER PRIMARY KEY DEFAULT 1,
                surum_kodu INTEGER NOT NULL DEFAULT 1,
                surum_adi TEXT NOT NULL DEFAULT '1.0.0',
                apk_url TEXT NOT NULL DEFAULT '',
                notlar TEXT NOT NULL DEFAULT '',
                guncellendi TIMESTAMP DEFAULT now(),
                CHECK (id = 1)
            )
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                driver_username TEXT NOT NULL,
                gonderen TEXT NOT NULL,
                mesaj TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT now()
            )
            """
        )
        await conn.execute(
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS tip TEXT NOT NULL DEFAULT 'metin'"
        )
        await conn.execute(
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS okundu BOOLEAN NOT NULL DEFAULT false"
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_zones (
                id SERIAL PRIMARY KEY,
                lat DOUBLE PRECISION NOT NULL,
                lng DOUBLE PRECISION NOT NULL,
                not_metni TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT now(),
                bitis_zamani TIMESTAMP
            )
            """
        )
        await conn.execute(
            "INSERT INTO app_version (id) VALUES (1) ON CONFLICT (id) DO NOTHING"
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
            try:
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
                    gun_str = payload.get("gun", "")
                    try:
                        gun_tarih = datetime.strptime(gun_str, "%Y-%m-%d").date()
                    except ValueError:
                        await websocket.send_text(
                            json.dumps({"tip": "gecmis_sonuc", "gun": gun_str, "yolculuklar": []})
                        )
                        continue
                    async with DB_POOL.acquire() as conn:
                        kayitlar = await conn.fetch(
                            "SELECT nereden, nereye, fiyat, tamamlanma_zamani FROM jobs "
                            "WHERE driver_username=$1 AND durum='tamamlandi' "
                            "AND tamamlanma_zamani::date = $2 "
                            "ORDER BY tamamlanma_zamani DESC",
                            surucu_id, gun_tarih,
                        )
                    await websocket.send_text(
                        json.dumps(
                            {
                                "tip": "gecmis_sonuc",
                                "gun": gun_str,
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

                if payload.get("tip") == "sohbet_mesaji":
                    mesaj_metni = payload.get("mesaj", "").strip()
                    if mesaj_metni:
                        async with DB_POOL.acquire() as conn:
                            yeni_id = await conn.fetchval(
                                "INSERT INTO messages (driver_username, gonderen, mesaj, tip) "
                                "VALUES ($1, 'surucu', $2, 'metin') RETURNING id",
                                surucu_id, mesaj_metni,
                            )
                        isim = DRIVERS.get(surucu_id, {}).get("isim", surucu_id)
                        await adminlere_sohbet_yayinla(
                            surucu_id, isim, "surucu", mesaj_metni, yeni_id, "metin"
                        )
                    continue

                if payload.get("tip") == "sohbet_ses":
                    ses_verisi = payload.get("ses_base64", "")
                    if ses_verisi:
                        async with DB_POOL.acquire() as conn:
                            yeni_id = await conn.fetchval(
                                "INSERT INTO messages (driver_username, gonderen, mesaj, tip) "
                                "VALUES ($1, 'surucu', $2, 'ses') RETURNING id",
                                surucu_id, ses_verisi,
                            )
                        isim = DRIVERS.get(surucu_id, {}).get("isim", surucu_id)
                        await adminlere_sohbet_yayinla(
                            surucu_id, isim, "surucu", "[Sesli mesaj]", yeni_id, "ses"
                        )
                    continue

                if payload.get("tip") == "sohbet_gecmisi_getir":
                    async with DB_POOL.acquire() as conn:
                        kayitlar = await conn.fetch(
                            "SELECT id, gonderen, mesaj, tip, okundu, created_at FROM messages "
                            "WHERE driver_username=$1 ORDER BY created_at ASC",
                            surucu_id,
                        )
                        await conn.execute(
                            "UPDATE messages SET okundu=true WHERE driver_username=$1 AND gonderen='admin'",
                            surucu_id,
                        )
                    await websocket.send_text(
                        json.dumps(
                            {
                                "tip": "sohbet_gecmisi_sonuc",
                                "mesajlar": [
                                    {
                                        "id": k["id"],
                                        "gonderen": k["gonderen"],
                                        "mesaj": k["mesaj"],
                                        "tip": k["tip"],
                                        "okundu": k["okundu"],
                                        "zaman": k["created_at"].strftime("%H:%M"),
                                    }
                                    for k in kayitlar
                                ],
                            }
                        )
                    )
                    continue

                if payload.get("tip") == "mesaj_sil_herkesten":
                    silinecek_id = payload.get("id")
                    async with DB_POOL.acquire() as conn:
                        silindi = await conn.fetchval(
                            "DELETE FROM messages WHERE id=$1 AND driver_username=$2 "
                            "AND gonderen='surucu' RETURNING id",
                            silinecek_id, surucu_id,
                        )
                    if silindi:
                        await adminlere_mesaj_silindi_yayinla(surucu_id, silinecek_id)
                    continue

                if payload.get("tip") == "riskleri_getir":
                    async with DB_POOL.acquire() as conn:
                        kayitlar = await conn.fetch(
                            "SELECT id, lat, lng, not_metni FROM risk_zones "
                            "WHERE bitis_zamani IS NULL OR bitis_zamani > now() "
                            "ORDER BY created_at DESC"
                        )
                    await websocket.send_text(
                        json.dumps(
                            {
                                "tip": "riskler_sonuc",
                                "riskler": [
                                    {
                                        "id": k["id"],
                                        "lat": k["lat"],
                                        "lng": k["lng"],
                                        "not": k["not_metni"],
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
            except (WebSocketDisconnect, ConnectionResetError):
                raise
            except Exception as e:
                print(f" Mesaj işlenirken hata (sürücü {surucu_id}): {e}")
                continue
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
    token = websocket.query_params.get("token", "")
    if not ws_token_dogrula(token) and not ws_admin_auth(
        websocket.headers.get("authorization")
    ):
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
        kayit = await conn.fetchrow("SELECT username FROM drivers WHERE id=$1", driver_id)
        if kayit:
            username = kayit["username"]
            await conn.execute("DELETE FROM jobs WHERE driver_username=$1", username)
            await conn.execute("DELETE FROM messages WHERE driver_username=$1", username)

            aktif = DRIVERS.get(username)
            if aktif and aktif.get("websocket"):
                try:
                    await aktif["websocket"].send_text(
                        json.dumps(
                            {
                                "tip": "hesap_silindi",
                                "mesaj": "Kaydınızın süresi dolmuştur.",
                            }
                        )
                    )
                    await aktif["websocket"].close()
                except Exception:
                    pass
                DRIVERS.pop(username, None)

        await conn.execute("DELETE FROM drivers WHERE id=$1", driver_id)
    return {"basarili": True}


@app.get("/admin/api/suruculer")
async def aktif_suruculer(yetki: bool = Depends(admin_auth)):
    return {
        s_id: {"lat": info["lat"], "lng": info["lng"], "status": info["status"], "isim": info["isim"]}
        for s_id, info in DRIVERS.items()
    }


# --- HARİTALI WEB ARAYÜZÜ (şifre korumalı) ---
@app.get("/api/surum")
async def surum_getir():
    async with DB_POOL.acquire() as conn:
        kayit = await conn.fetchrow(
            "SELECT surum_adi, apk_url, notlar FROM app_version WHERE id=1"
        )
    return {
        "surum_adi": kayit["surum_adi"],
        "apk_url": kayit["apk_url"],
        "notlar": kayit["notlar"],
    }


class SurumGuncelle(BaseModel):
    surum_adi: str
    apk_url: str
    notlar: str = ""


@app.post("/admin/api/surum")
async def surum_guncelle(surum: SurumGuncelle, yetki: bool = Depends(admin_auth)):
    async with DB_POOL.acquire() as conn:
        mevcut = await conn.fetchrow("SELECT surum_adi FROM app_version WHERE id=1")
        if mevcut and surum_tuple(surum.surum_adi) <= surum_tuple(mevcut["surum_adi"]):
            raise HTTPException(
                status_code=400,
                detail=f"Yeni sürüm ({surum.surum_adi}), mevcut olandan ({mevcut['surum_adi']}) büyük olmalı.",
            )
        await conn.execute(
            """
            UPDATE app_version
            SET surum_adi=$1, apk_url=$2, notlar=$3, guncellendi=now()
            WHERE id=1
            """,
            surum.surum_adi, surum.apk_url, surum.notlar,
        )
    return {"basarili": True}


@app.get("/admin/api/surum")
async def surum_getir_admin(yetki: bool = Depends(admin_auth)):
    return await surum_getir()


@app.get("/admin/api/sohbetler")
async def sohbetleri_listele(yetki: bool = Depends(admin_auth)):
    async with DB_POOL.acquire() as conn:
        kayitlar = await conn.fetch(
            """
            SELECT m.driver_username,
                   d.display_name,
                   (SELECT mesaj FROM messages m2
                    WHERE m2.driver_username = m.driver_username
                    ORDER BY m2.created_at DESC LIMIT 1) AS son_mesaj,
                   MAX(m.created_at) AS son_zaman
            FROM messages m
            LEFT JOIN drivers d ON d.username = m.driver_username
            GROUP BY m.driver_username, d.display_name
            ORDER BY son_zaman DESC
            """
        )
    return [
        {
            "kullanici_adi": k["driver_username"],
            "isim": k["display_name"] or k["driver_username"],
            "son_mesaj": k["son_mesaj"],
            "son_zaman": k["son_zaman"].isoformat() if k["son_zaman"] else None,
        }
        for k in kayitlar
    ]


@app.get("/admin/api/sohbet/{kullanici_adi}")
async def sohbet_getir(kullanici_adi: str, yetki: bool = Depends(admin_auth)):
    async with DB_POOL.acquire() as conn:
        kayitlar = await conn.fetch(
            "SELECT id, gonderen, mesaj, tip, okundu, created_at FROM messages "
            "WHERE driver_username=$1 ORDER BY created_at ASC",
            kullanici_adi,
        )
        await conn.execute(
            "UPDATE messages SET okundu=true WHERE driver_username=$1 AND gonderen='surucu'",
            kullanici_adi,
        )

    info = DRIVERS.get(kullanici_adi)
    if info and info.get("websocket"):
        try:
            await info["websocket"].send_text(json.dumps({"tip": "mesajlar_okundu"}))
        except Exception:
            pass

    return [
        {
            "id": k["id"],
            "gonderen": k["gonderen"],
            "mesaj": k["mesaj"],
            "tip": k["tip"],
            "okundu": k["okundu"],
            "zaman": k["created_at"].strftime("%H:%M"),
        }
        for k in kayitlar
    ]


class YeniMesaj(BaseModel):
    mesaj: str
    tip: str = "metin"


@app.post("/admin/api/sohbet/{kullanici_adi}")
async def sohbet_gonder(
    kullanici_adi: str, veri: YeniMesaj, yetki: bool = Depends(admin_auth)
):
    mesaj_metni = veri.mesaj.strip() if veri.tip == "metin" else veri.mesaj
    if not mesaj_metni:
        raise HTTPException(status_code=400, detail="Mesaj boş olamaz")

    async with DB_POOL.acquire() as conn:
        yeni_id = await conn.fetchval(
            "INSERT INTO messages (driver_username, gonderen, mesaj, tip) "
            "VALUES ($1, 'admin', $2, $3) RETURNING id",
            kullanici_adi, mesaj_metni, veri.tip,
        )

    info = DRIVERS.get(kullanici_adi)
    if info and info.get("websocket"):
        try:
            await info["websocket"].send_text(
                json.dumps(
                    {
                        "tip": "sohbet_gelen",
                        "gonderen": "admin",
                        "mesaj": mesaj_metni,
                        "id": yeni_id,
                        "mesaj_tipi": veri.tip,
                    }
                )
            )
        except Exception:
            pass

    return {"basarili": True, "id": yeni_id}


@app.delete("/admin/api/sohbet/{kullanici_adi}/mesaj/{mesaj_id}")
async def sohbet_mesaj_sil(
    kullanici_adi: str, mesaj_id: int, yetki: bool = Depends(admin_auth)
):
    async with DB_POOL.acquire() as conn:
        silindi = await conn.fetchval(
            "DELETE FROM messages WHERE id=$1 AND driver_username=$2 "
            "AND gonderen='admin' RETURNING id",
            mesaj_id, kullanici_adi,
        )
    if silindi:
        info = DRIVERS.get(kullanici_adi)
        if info and info.get("websocket"):
            try:
                await info["websocket"].send_text(
                    json.dumps({"tip": "mesaj_silindi", "id": mesaj_id})
                )
            except Exception:
                pass
    return {"basarili": True}


@app.delete("/admin/api/sohbet/{kullanici_adi}")
async def sohbeti_tamamen_sil(kullanici_adi: str, yetki: bool = Depends(admin_auth)):
    async with DB_POOL.acquire() as conn:
        await conn.execute("DELETE FROM messages WHERE driver_username=$1", kullanici_adi)
    return {"basarili": True}


class YeniRisk(BaseModel):
    lat: float
    lng: float
    not_metni: str
    sure_saat: float | None = None  # None ise manuel silinene kadar kalır
    bildirilecek_soforler: list[str] = []


@app.post("/admin/api/riskler")
async def risk_ekle(risk: YeniRisk, yetki: bool = Depends(admin_auth)):
    bitis = None
    if risk.sure_saat:
        bitis = datetime.now() + timedelta(hours=risk.sure_saat)

    async with DB_POOL.acquire() as conn:
        yeni_id = await conn.fetchval(
            "INSERT INTO risk_zones (lat, lng, not_metni, bitis_zamani) "
            "VALUES ($1, $2, $3, $4) RETURNING id",
            risk.lat, risk.lng, risk.not_metni, bitis,
        )

    if risk.bildirilecek_soforler:
        await secili_suruculere_yayinla(
            risk.bildirilecek_soforler,
            {
                "tip": "risk_bildirimi",
                "id": yeni_id,
                "lat": risk.lat,
                "lng": risk.lng,
                "not": risk.not_metni,
            },
        )

    return {"basarili": True, "id": yeni_id}


@app.get("/admin/api/riskler")
async def riskleri_listele(yetki: bool = Depends(admin_auth)):
    async with DB_POOL.acquire() as conn:
        kayitlar = await conn.fetch(
            "SELECT id, lat, lng, not_metni, created_at, bitis_zamani FROM risk_zones "
            "WHERE bitis_zamani IS NULL OR bitis_zamani > now() "
            "ORDER BY created_at DESC"
        )
    return [
        {
            "id": k["id"],
            "lat": k["lat"],
            "lng": k["lng"],
            "not": k["not_metni"],
            "olusturma": k["created_at"].isoformat(),
            "bitis": k["bitis_zamani"].isoformat() if k["bitis_zamani"] else None,
        }
        for k in kayitlar
    ]


@app.delete("/admin/api/riskler/{risk_id}")
async def risk_sil(risk_id: int, yetki: bool = Depends(admin_auth)):
    async with DB_POOL.acquire() as conn:
        await conn.execute("DELETE FROM risk_zones WHERE id=$1", risk_id)
    await tum_suruculere_yayinla({"tip": "risk_silindi", "id": risk_id})
    return {"basarili": True}


@app.get("/admin", response_class=HTMLResponse)
async def get_admin_panel(credentials: HTTPBasicCredentials = Depends(security)):
    if not (
        secrets.compare_digest(credentials.username, ADMIN_USER)
        and secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    ):
        raise HTTPException(
            status_code=401, detail="Yetkisiz", headers={"WWW-Authenticate": "Basic"}
        )
    token = base64.b64encode(
        f"{credentials.username}:{credentials.password}".encode()
    ).decode()
    return _ADMIN_HTML.replace("__WS_TOKEN__", token)


_ADMIN_HTML = """
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
            #haritaSarmalayici {
                flex: 1;
                position: relative;
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 4px 16px rgba(0,0,0,0.4);
            }
            #map {
                width: 100%;
                height: 100%;
            }
            #riskModuBtn {
                position: absolute;
                bottom: 16px;
                right: 16px;
                z-index: 900;
                width: 50px;
                height: 50px;
                border-radius: 50%;
                border: none;
                background: #1e293b;
                font-size: 24px;
                cursor: pointer;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            #riskModuBtn.aktif {
                background: #dc2626;
                box-shadow: 0 0 0 4px rgba(220,38,38,0.3);
            }
            #riskFormuOrtusu {
                display: none;
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: rgba(0,0,0,0.6);
                align-items: center; justify-content: center;
                z-index: 1000;
            }
            #riskFormuKutu {
                background: #1e293b; padding: 24px; border-radius: 12px;
                width: 340px; max-width: 90%;
                box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            }
            #riskFormuKutu h4 { margin-top: 0; color: #f1f5f9; }
            #riskFormuKutu label { display: block; margin-top: 12px; font-size: 13px; font-weight: 600; color: #94a3b8; }
            #riskFormuKutu input, #riskFormuKutu select {
                width: 100%; padding: 10px; margin-top: 4px; box-sizing: border-box;
                border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0;
            }
            #riskSoforListesi {
                max-height: 140px; overflow-y: auto; margin-top: 4px;
                background: #0f172a; border-radius: 8px; padding: 8px;
                border: 1px solid #334155;
            }
            #riskSoforListesi label {
                display: flex; align-items: center; gap: 6px;
                font-weight: 400; color: #e2e8f0; margin: 4px 0; font-size: 13px;
            }
            #riskFormuKutu .butonlar { margin-top: 18px; display: flex; gap: 8px; justify-content: flex-end; }
            #riskFormuKutu .butonlar button {
                padding: 9px 14px; border-radius: 8px; border: none;
                background: #22c55e; color: white; font-weight: 600; cursor: pointer; font-size: 13px;
            }
            #riskFormuKutu .butonlar button:first-child { background: #475569; }
            #riskYonetimBolumu {
                margin: 0 20px 32px;
                background: #1e293b;
                border-radius: 12px;
                padding: 20px;
                box-shadow: 0 4px 16px rgba(0,0,0,0.4);
            }
            #riskYonetimBolumu h4 { margin: 0 0 12px; color: #f1f5f9; font-size: 14px; }
            .riskSatir {
                background: #0f172a; border-radius: 8px; padding: 10px 14px;
                display: flex; justify-content: space-between; align-items: center;
                margin-bottom: 8px; font-size: 13.5px; color: #e2e8f0;
            }
            .riskSatir button {
                padding: 6px 12px; border-radius: 6px; border: none;
                background: #dc2626; color: white; cursor: pointer; font-size: 12px;
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
            #surumBolumu {
                margin: 0 20px 32px;
                background: #1e293b;
                border-radius: 12px;
                padding: 20px;
                box-shadow: 0 4px 16px rgba(0,0,0,0.4);
            }
            #surumBolumu h4 { margin: 0 0 12px; color: #f1f5f9; font-size: 14px; }
            #surumBolumu .satir { display: flex; gap: 10px; flex-wrap: wrap; }
            #surumBolumu input {
                padding: 10px 12px;
                border-radius: 8px;
                border: 1px solid #334155;
                background: #0f172a;
                color: #e2e8f0;
                flex: 1;
                min-width: 140px;
                font-size: 13px;
            }
            #surumBolumu button {
                padding: 10px 16px;
                border-radius: 8px;
                border: none;
                background: #3b82f6;
                color: white;
                font-weight: 600;
                cursor: pointer;
            }
            #surumSonuc { font-size: 12px; color: #94a3b8; margin-top: 8px; }
            .surucu-etiket {
                background: rgba(15, 23, 42, 0.85) !important;
                color: #f1f5f9 !important;
                border: 1px solid #3b82f6 !important;
                border-radius: 6px !important;
                padding: 2px 8px !important;
                font-size: 12px !important;
                font-weight: 600 !important;
                box-shadow: none !important;
            }
            .surucu-etiket::before { display: none !important; }
            #sohbetBolumu {
                margin: 0 20px 32px;
                display: flex;
                gap: 16px;
                height: 380px;
            }
            #sohbetListesiKutu {
                width: 260px;
                flex-shrink: 0;
                background: #1e293b;
                border-radius: 12px;
                padding: 16px;
                box-shadow: 0 4px 16px rgba(0,0,0,0.4);
                display: flex;
                flex-direction: column;
            }
            #sohbetListesiKutu h4 { margin: 0 0 10px; color: #f1f5f9; font-size: 14px; }
            #sohbetListesi { overflow-y: auto; flex: 1; display: flex; flex-direction: column; gap: 6px; }
            .sohbetSatir {
                background: #0f172a;
                border-radius: 8px;
                padding: 10px;
                cursor: pointer;
                border: 1px solid transparent;
            }
            .sohbetSatir:hover { border-color: #3b82f6; }
            .sohbetSatir.secili { border-color: #3b82f6; background: #1e3a5f; }
            .sohbetSatir .isim { font-weight: 700; color: #f1f5f9; font-size: 13.5px; }
            .sohbetSatir .onizleme { font-size: 12px; color: #94a3b8; margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            #sohbetPenceresi {
                flex: 1;
                background: #1e293b;
                border-radius: 12px;
                padding: 16px;
                box-shadow: 0 4px 16px rgba(0,0,0,0.4);
                display: flex;
                flex-direction: column;
            }
            #sohbetBaslik { font-weight: 700; color: #f1f5f9; margin-bottom: 10px; font-size: 14px; }
            #sohbetMesajlari { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; padding-right: 4px; }
            .mesajBalon { max-width: 70%; padding: 8px 12px; border-radius: 10px; font-size: 13.5px; }
            .mesajSurucu { align-self: flex-start; background: #334155; color: #e2e8f0; }
            .mesajAdmin { align-self: flex-end; background: #3b82f6; color: white; }
            #sohbetGirisSatiri { display: flex; gap: 8px; margin-top: 10px; }
            #sohbetMesajGiris {
                flex: 1;
                padding: 10px 12px;
                border-radius: 8px;
                border: 1px solid #334155;
                background: #0f172a;
                color: #e2e8f0;
                font-size: 13px;
            }
            #sohbetGonderBtn {
                padding: 10px 16px;
                border-radius: 8px;
                border: none;
                background: #22c55e;
                color: white;
                font-weight: 600;
                cursor: pointer;
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
            <div id="haritaSarmalayici">
                <div id="map"></div>
                <button id="riskModuBtn" onclick="riskModunuAcKapat()" title="Riskli bölge ekle">🚓</button>
            </div>
            <div id="logPanel">
                <h4>Canlı Akış</h4>
                <div id="logIcerik"></div>
            </div>
        </div>

        <div id="riskFormuOrtusu">
            <div id="riskFormuKutu">
                <h4>Riskli Bölge Ekle</h4>
                <label>Not:</label>
                <input id="riskNot" placeholder="örn. Radar var, kaza var..." />
                <label>Süre:</label>
                <select id="riskSure">
                    <option value="">Manuel silinene kadar kalsın</option>
                    <option value="1">1 saat</option>
                    <option value="4">4 saat</option>
                    <option value="24">24 saat</option>
                </select>
                <label>Bildirim gönderilecek sürücüler:</label>
                <div id="riskSoforListesi"></div>
                <div class="butonlar">
                    <button onclick="riskFormuKapat()">İptal</button>
                    <button onclick="riskEkle()">Ekle</button>
                </div>
            </div>
        </div>

        <div id="riskYonetimBolumu">
            <h4>Aktif Riskli Bölgeler</h4>
            <div id="riskListesi"></div>
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

        <div id="surumBolumu">
            <h4>Uygulama Sürümü (Şoför App)</h4>
            <div class="satir">
                <input id="surumAdi" placeholder="Sürüm (örn. 1.0.1)" />
                <input id="apkLinki" placeholder="APK indirme linki" style="flex: 2;" />
            </div>
            <div class="satir" style="margin-top:8px;">
                <input id="surumNotlari" placeholder="Bu sürümde neler değişti? (isteğe bağlı)" style="flex: 1;" />
                <button onclick="surumGuncelle()">Sürümü Güncelle</button>
            </div>
            <div id="surumSonuc"></div>
            <div id="mevcutSurum" style="margin-top:10px; font-size:13px; color:#94a3b8;"></div>
        </div>

        <div id="sohbetBolumu">
            <div id="sohbetListesiKutu">
                <h4>Sohbetler</h4>
                <div id="sohbetListesi"></div>
            </div>
            <div id="sohbetPenceresi">
                <div id="sohbetUst" style="display:flex; justify-content:space-between; align-items:center;">
                    <div id="sohbetBaslik">Bir sürücü seç</div>
                    <button id="sohbetSilBtn" onclick="sohbetiSil()" style="display:none; background:#dc2626; padding:6px 10px; font-size:12px;">Sohbeti Sil</button>
                </div>
                <div id="sohbetMesajlari"></div>
                <div id="sohbetGirisSatiri">
                    <input id="sohbetMesajGiris" placeholder="Mesaj yaz..." onkeypress="if(event.key==='Enter') sohbetGonder()" />
                    <button id="sohbetGonderBtn" onclick="sohbetGonder()">Gönder</button>
                </div>
            </div>
        </div>

        <script>
            var map = L.map('map', {zoomControl: true}).setView([41.0082, 28.9784], 11);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
            var surucuMarkerlari = {};
            var secilenSurucuId = null;
            var logIcerik = document.getElementById('logIcerik');
            var ws = new WebSocket("wss://" + window.location.host + "/admin/ws?token=__WS_TOKEN__");

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
                if (data.tip === 'sohbet_bildirim') {
                    logaYaz('[' + data.isim + '] yeni mesaj: ' + (data.mesaj_tipi === 'ses' ? '[Sesli mesaj]' : data.mesaj));
                    sohbetleriYukle();
                    if (secilenSohbetKullanici === data.kullanici_adi) {
                        sohbetMesajlariniGoster([{id: data.id, gonderen: data.gonderen, mesaj: data.mesaj, tip: data.mesaj_tipi, okundu: false}], true);
                    }
                }
                if (data.tip === 'mesaj_silindi') {
                    var balon = document.querySelector('[data-mesaj-id="' + data.id + '"]');
                    if (balon) balon.remove();
                }
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

            function mesajAtSayfasinaGit(surucuId, surucuIsim) {
                sohbetAc(surucuId, surucuIsim);
                document.getElementById('sohbetBolumu').scrollIntoView({behavior: 'smooth', block: 'start'});
                document.getElementById('sohbetMesajGiris').focus();
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
                            '<button onclick="isVerFormAc(&quot;' + id + '&quot;, &quot;' + isim + '&quot;)">İş Ver</button> ' +
                            '<button onclick="mesajAtSayfasinaGit(&quot;' + id + '&quot;, &quot;' + isim + '&quot;)">Mesaj At</button>';
                        if (surucuMarkerlari[id]) {
                            surucuMarkerlari[id].setLatLng([s.lat, s.lng]);
                            surucuMarkerlari[id].setPopupContent(popupHtml);
                            surucuMarkerlari[id].setIcon(ikon);
                        } else {
                            surucuMarkerlari[id] = L.marker([s.lat, s.lng], {icon: ikon})
                                .addTo(map)
                                .bindPopup(popupHtml)
                                .bindTooltip(isim, {permanent: true, direction: 'top', offset: [0, -8], className: 'surucu-etiket'});
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

            function mevcutSurumuGoster() {
                fetch('/admin/api/surum').then(res => res.json()).then(s => {
                    document.getElementById('surumAdi').value = s.surum_adi;
                    document.getElementById('apkLinki').value = s.apk_url;
                    document.getElementById('surumNotlari').value = s.notlar;
                    document.getElementById('mevcutSurum').innerText =
                        'Şu an yayında: v' + s.surum_adi;
                });
            }

            function surumGuncelle() {
                var ad = document.getElementById('surumAdi').value.trim();
                var link = document.getElementById('apkLinki').value.trim();
                var notlar = document.getElementById('surumNotlari').value.trim();
                if (!ad || !link) {
                    document.getElementById('surumSonuc').innerText = 'Sürüm ve APK linki zorunlu.';
                    return;
                }
                fetch('/admin/api/surum', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({surum_adi: ad, apk_url: link, notlar: notlar})
                }).then(res => res.json().then(data => ({status: res.status, data: data})))
                  .then(({status, data}) => {
                    if (status === 200) {
                        document.getElementById('surumSonuc').innerText = 'Güncellendi! Şoförler bir sonraki açılışta yeni sürümü görecek.';
                        mevcutSurumuGoster();
                    } else {
                        document.getElementById('surumSonuc').innerText = 'Hata: ' + (data.detail || 'bilinmeyen hata');
                    }
                  });
            }

            surucuListesiniYukle();
            mevcutSurumuGoster();

            var secilenSohbetKullanici = null;

            function sohbetleriYukle() {
                fetch('/admin/api/sohbetler').then(res => res.json()).then(liste => {
                    var kapsayici = document.getElementById('sohbetListesi');
                    kapsayici.innerHTML = '';
                    if (liste.length === 0) {
                        kapsayici.innerHTML = '<div style="color:#64748b; font-size:13px;">Henüz mesaj yok.</div>';
                        return;
                    }
                    liste.forEach(function(s) {
                        var satir = document.createElement('div');
                        satir.className = 'sohbetSatir' + (secilenSohbetKullanici === s.kullanici_adi ? ' secili' : '');
                        satir.innerHTML =
                            '<div class="isim">' + s.isim + '</div>' +
                            '<div class="onizleme">' + (s.son_mesaj || '') + '</div>';
                        satir.onclick = function() { sohbetAc(s.kullanici_adi, s.isim); };
                        kapsayici.appendChild(satir);
                    });
                });
            }

            function sohbetAc(kullaniciAdi, isim) {
                secilenSohbetKullanici = kullaniciAdi;
                document.getElementById('sohbetBaslik').innerText = isim;
                document.getElementById('sohbetSilBtn').style.display = 'inline-block';
                fetch('/admin/api/sohbet/' + kullaniciAdi).then(res => res.json()).then(mesajlar => {
                    sohbetMesajlariniGoster(mesajlar, false);
                });
                sohbetleriYukle();
            }

            function sohbetiSil() {
                if (!secilenSohbetKullanici) return;
                if (!confirm('Bu sohbetin tüm geçmişini kalıcı olarak silmek istediğine emin misin?')) return;
                fetch('/admin/api/sohbet/' + secilenSohbetKullanici, {method: 'DELETE'}).then(function() {
                    document.getElementById('sohbetMesajlari').innerHTML = '';
                    sohbetleriYukle();
                });
            }

            function mesajSil(mesajId) {
                if (!secilenSohbetKullanici) return;
                fetch('/admin/api/sohbet/' + secilenSohbetKullanici + '/mesaj/' + mesajId, {method: 'DELETE'}).then(function() {
                    var balon = document.querySelector('[data-mesaj-id="' + mesajId + '"]');
                    if (balon) balon.remove();
                });
            }

            function sohbetMesajlariniGoster(mesajlar, ekle) {
                var kutu = document.getElementById('sohbetMesajlari');
                if (!ekle) { kutu.innerHTML = ''; }
                mesajlar.forEach(function(m) {
                    var balon = document.createElement('div');
                    balon.className = 'mesajBalon ' + (m.gonderen === 'admin' ? 'mesajAdmin' : 'mesajSurucu');
                    balon.setAttribute('data-mesaj-id', m.id || '');
                    if (m.tip === 'ses') {
                        var ses = document.createElement('audio');
                        ses.controls = true;
                        ses.style.maxWidth = '220px';
                        ses.src = 'data:audio/aac;base64,' + m.mesaj;
                        balon.appendChild(ses);
                    } else {
                        var metinDiv = document.createElement('div');
                        metinDiv.innerText = m.mesaj;
                        balon.appendChild(metinDiv);
                    }
                    if (m.gonderen === 'admin' && m.id) {
                        var silBtn = document.createElement('span');
                        silBtn.innerText = ' ✕';
                        silBtn.style.cursor = 'pointer';
                        silBtn.style.opacity = '0.6';
                        silBtn.style.fontSize = '11px';
                        silBtn.onclick = function() { mesajSil(m.id); };
                        balon.appendChild(silBtn);
                    }
                    kutu.appendChild(balon);
                });
                kutu.scrollTop = kutu.scrollHeight;
            }

            function sohbetGonder() {
                if (!secilenSohbetKullanici) {
                    alert('Önce soldan bir sohbet seç.');
                    return;
                }
                var giris = document.getElementById('sohbetMesajGiris');
                var mesaj = giris.value.trim();
                if (!mesaj) return;
                fetch('/admin/api/sohbet/' + secilenSohbetKullanici, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({mesaj: mesaj, tip: 'metin'})
                }).then(res => res.json()).then(function(sonuc) {
                    sohbetMesajlariniGoster([{id: sonuc.id, gonderen: 'admin', mesaj: mesaj, tip: 'metin'}], true);
                    giris.value = '';
                });
            }

            sohbetleriYukle();

            // ---------------- Riskli Bölgeler ----------------
            var riskModuAcik = false;
            var riskMarkerlari = {};
            var secilenRiskKonumu = null;
            var polisIkonu = L.divIcon({
                html: '<div style="font-size:26px;">🚓</div>',
                className: '',
                iconSize: [30, 30],
                iconAnchor: [15, 15]
            });

            function riskModunuAcKapat() {
                riskModuAcik = !riskModuAcik;
                document.getElementById('riskModuBtn').classList.toggle('aktif', riskModuAcik);
            }

            map.on('click', function(e) {
                if (!riskModuAcik) return;
                secilenRiskKonumu = {lat: e.latlng.lat, lng: e.latlng.lng};
                riskFormuAc();
            });

            function riskFormuAc() {
                document.getElementById('riskNot').value = '';
                document.getElementById('riskSure').value = '';
                fetch('/admin/api/drivers').then(res => res.json()).then(liste => {
                    var kutu = document.getElementById('riskSoforListesi');
                    kutu.innerHTML = '';
                    if (liste.length === 0) {
                        kutu.innerHTML = '<div style="color:#64748b;">Kayıtlı sürücü yok.</div>';
                    }
                    liste.forEach(function(s) {
                        var etiket = document.createElement('label');
                        etiket.innerHTML = '<input type="checkbox" value="' + s.kullanici_adi + '"> ' + s.isim;
                        kutu.appendChild(etiket);
                    });
                });
                document.getElementById('riskFormuOrtusu').style.display = 'flex';
            }

            function riskFormuKapat() {
                document.getElementById('riskFormuOrtusu').style.display = 'none';
                riskModuAcik = false;
                document.getElementById('riskModuBtn').classList.remove('aktif');
            }

            function riskEkle() {
                if (!secilenRiskKonumu) return;
                var not = document.getElementById('riskNot').value.trim();
                if (!not) { alert('Lütfen bir not gir.'); return; }
                var sureDegeri = document.getElementById('riskSure').value;
                var secilenSoforler = Array.from(
                    document.querySelectorAll('#riskSoforListesi input:checked')
                ).map(function(el) { return el.value; });

                fetch('/admin/api/riskler', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        lat: secilenRiskKonumu.lat,
                        lng: secilenRiskKonumu.lng,
                        not_metni: not,
                        sure_saat: sureDegeri ? parseFloat(sureDegeri) : null,
                        bildirilecek_soforler: secilenSoforler
                    })
                }).then(res => res.json()).then(function() {
                    logaYaz('Riskli bölge eklendi: ' + not);
                    riskleriYukle();
                    riskFormuKapat();
                });
            }

            function riskSil(riskId) {
                if (!confirm('Bu riskli bölgeyi kaldırmak istediğine emin misin?')) return;
                fetch('/admin/api/riskler/' + riskId, {method: 'DELETE'}).then(function() {
                    riskleriYukle();
                });
            }

            function riskleriYukle() {
                fetch('/admin/api/riskler').then(res => res.json()).then(liste => {
                    var mevcutIdler = liste.map(r => r.id);
                    for (var id in riskMarkerlari) {
                        if (mevcutIdler.indexOf(parseInt(id)) === -1) {
                            map.removeLayer(riskMarkerlari[id]);
                            delete riskMarkerlari[id];
                        }
                    }
                    liste.forEach(function(r) {
                        if (!riskMarkerlari[r.id]) {
                            riskMarkerlari[r.id] = L.marker([r.lat, r.lng], {icon: polisIkonu})
                                .addTo(map)
                                .bindPopup('<b>Riskli Bölge</b><br>' + r.not);
                        }
                    });

                    var kapsayici = document.getElementById('riskListesi');
                    kapsayici.innerHTML = '';
                    if (liste.length === 0) {
                        kapsayici.innerHTML = '<div style="color:#64748b; font-size:13px;">Aktif riskli bölge yok.</div>';
                        return;
                    }
                    liste.forEach(function(r) {
                        var satir = document.createElement('div');
                        satir.className = 'riskSatir';
                        satir.innerHTML = '<span>' + r.not + '</span>' +
                            '<button onclick="riskSil(' + r.id + ')">Kaldır</button>';
                        kapsayici.appendChild(satir);
                    });
                });
            }
            riskleriYukle();
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
