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

        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
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

            is_emri = {
                "is_tipi": "YENI_CAGRI",
                "nereden": nereden,
                "nereye": nereye,
                "fiyat": fiyat,
                "numara": numara,
            }
            await info["websocket"].send_text(json.dumps(is_emri))
            await websocket.send_text(
                json.dumps({"bilgi": f"İş {hedef_surucu} sürücüsüne gönderildi!"})
            )
    except WebSocketDisconnect:
        pass


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
                "INSERT INTO drivers (username, password_hash, display_name) VALUES ($1, $2, $3)",
                surucu.kullanici_adi,
                sifre_hashle(surucu.sifre),
                surucu.isim,
            )
        except asyncpg.UniqueViolationError:
            raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten kayıtlı")
    return {"basarili": True}


@app.get("/admin/api/drivers")
async def surucu_listele(yetki: bool = Depends(admin_auth)):
    async with DB_POOL.acquire() as conn:
        kayitlar = await conn.fetch(
            "SELECT id, username, display_name, created_at FROM drivers ORDER BY id DESC"
        )
    return [
        {
            "id": k["id"],
            "kullanici_adi": k["username"],
            "isim": k["display_name"],
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
            body { font-family: sans-serif; margin: 0; }
            #map { height: 65vh; width: 100%; }
            #log { height: 10vh; background: #222; color: #0f0; padding: 10px; overflow-y: scroll; font-family: monospace; }
            #panel { padding: 12px; background: #f4f4f4; }
            #panel input { padding: 6px; margin-right: 6px; }
            #panel button { padding: 6px 12px; }
            #surucuListesi { padding: 0 12px 12px; }
            #surucuListesi table { border-collapse: collapse; width: 100%; }
            #surucuListesi td, #surucuListesi th { border: 1px solid #ccc; padding: 4px 8px; text-align: left; font-size: 14px; }
            #isFormuOrtusu {
                display: none;
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: rgba(0,0,0,0.5);
                align-items: center; justify-content: center;
                z-index: 1000;
            }
            #isFormuKutu {
                background: white; padding: 20px; border-radius: 8px;
                width: 320px; max-width: 90%;
            }
            #isFormuKutu h4 { margin-top: 0; }
            #isFormuKutu label { display: block; margin-top: 10px; font-size: 13px; font-weight: bold; }
            #isFormuKutu input { width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box; }
            #isFormuKutu .butonlar { margin-top: 16px; display: flex; gap: 8px; justify-content: flex-end; }
        </style>
    </head>
    <body>
        <h3 style="margin:8px;">Canlı Takip Paneli (İş Vermek İçin Bir Sürücüye Tıklayın)</h3>
        <div id="map"></div>
        <div id="log">Sistem hazır. Şoförlerin bağlanması bekleniyor...</div>

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

        <div id="panel">
            <b>Yeni Sürücü Ekle:</b><br><br>
            <input id="yeniKullaniciAdi" placeholder="Kullanıcı adı" />
            <input id="yeniSifre" placeholder="Şifre" type="password" />
            <input id="yeniIsim" placeholder="Görünen isim / tabela" />
            <button onclick="surucuEkle()">Ekle</button>
            <span id="ekleSonuc"></span>
        </div>
        <div id="surucuListesi">
            <b>Kayıtlı Sürücüler:</b>
            <table id="tabloSurucular"><thead><tr><th>Kullanıcı Adı</th><th>İsim</th><th></th></tr></thead><tbody></tbody></table>
        </div>

        <script>
            var map = L.map('map').setView([41.0082, 28.9784], 11);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
            var surucuMarkerlari = {};
            var secilenSurucuId = null;
            var logDiv = document.getElementById('log');
            var ws = new WebSocket("wss://" + window.location.host + "/admin/ws");

            var maviIkon = L.icon({
                iconUrl: 'https://cdn.jsdelivr.net/gh/pointhi/leaflet-color-markers@master/img/marker-icon-blue.png',
                shadowUrl: 'https://cdn.jsdelivr.net/gh/pointhi/leaflet-color-markers@master/img/marker-shadow.png',
                iconSize: [25, 41], iconAnchor: [12, 41], popupAnchor: [1, -34], shadowSize: [41, 41]
            });
            var kirmiziIkon = L.icon({
                iconUrl: 'https://cdn.jsdelivr.net/gh/pointhi/leaflet-color-markers@master/img/marker-icon-red.png',
                shadowUrl: 'https://cdn.jsdelivr.net/gh/pointhi/leaflet-color-markers@master/img/marker-shadow.png',
                iconSize: [25, 41], iconAnchor: [12, 41], popupAnchor: [1, -34], shadowSize: [41, 41]
            });

            ws.onmessage = function(event) {
                var data = JSON.parse(event.data);
                if(data.bilgi) { logDiv.innerHTML += "<br>> " + data.bilgi; logDiv.scrollTop = logDiv.scrollHeight; }
            };

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

            function surucuListesiniYukle() {
                fetch('/admin/api/drivers').then(res => res.json()).then(liste => {
                    var tbody = document.querySelector('#tabloSurucular tbody');
                    tbody.innerHTML = '';
                    liste.forEach(function(s) {
                        var tr = document.createElement('tr');
                        tr.innerHTML = '<td>' + s.kullanici_adi + '</td><td>' + s.isim + '</td>' +
                            '<td><button onclick="surucuSil(' + s.id + ')">Sil</button></td>';
                        tbody.appendChild(tr);
                    });
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
