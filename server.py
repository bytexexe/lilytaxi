import json
import math
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

app = FastAPI()

# Aktif sürücülerin anlık konumları ve hatları burada tutulur
DRIVERS = {}

def calculate_distance(lat1, lon1, lat2, lon2):
    """İki koordinat arasındaki mesafeyi (KM) Haversine formülü ile hesaplar."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

# --- ŞOFÖR WEBSOCKET BAĞLANTISI ---
@app.websocket("/ws/surucu/{surucu_id}")
async def surucu_websocket(websocket: WebSocket, surucu_id: str):
    await websocket.accept()
    DRIVERS[surucu_id] = {"lat": 0.0, "lng": 0.0, "status": "Musait", "websocket": websocket}
    print(f" Sürücü bağlandı: {surucu_id}")
    
    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
            if surucu_id in DRIVERS:
                DRIVERS[surucu_id]["lat"] = payload.get("lat", 0.0)
                DRIVERS[surucu_id]["lng"] = payload.get("lng", 0.0)
                DRIVERS[surucu_id]["status"] = payload.get("status", "Musait")
    except WebSocketDisconnect:
        print(f" Sürücü koptu: {surucu_id}")
        if surucu_id in DRIVERS:
            del DRIVERS[surucu_id]

# --- YÖNETİCİ PANELİ BAĞLANTISI ---
@app.websocket("/ws/admin")
async def admin_websocket(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
            t_lat = payload["target_lat"]
            t_lng = payload["target_lng"]
            
            en_yakin_surucu = None
            en_kisa_mesafe = float('inf')
            
            for s_id, info in DRIVERS.items():
                if info["status"] == "Musait":
                    mesafe = calculate_distance(t_lat, t_lng, info["lat"], info["lng"])
                    if mesafe < en_kisa_mesafe:
                        en_kisa_mesafe = mesafe
                        en_yakin_surucu = s_id
            
            if en_yakin_surucu and DRIVERS[en_yakin_surucu]["websocket"]:
                is_emri = {"is_tipi": "YENI_CAGRI", "musteri_lat": t_lat, "musteri_lng": t_lng}
                await DRIVERS[en_yakin_surucu]["websocket"].send_text(json.dumps(is_emri))
                await websocket.send_text(json.dumps({"bilgi": f"İş {en_yakin_surucu} sürücüsüne gönderildi! Mesafe: {round(en_kisa_mesafe,2)} km"}))
            else:
                await websocket.send_text(json.dumps({"bilgi": "Etrafta müsait sürücü bulunamadı!"}))
    except WebSocketDisconnect:
        pass

# --- HARİTALI WEB ARAYÜZÜ ---
@app.get("/", response_class=HTMLResponse)
async def get_admin_panel():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Taksi Yönetim Paneli</title>
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <style>
            #map { height: 85vh; width: 100%; }
            #log { height: 10vh; background: #222; color: #0f0; padding: 10px; overflow-y: scroll; font-family: monospace; }
        </style>
    </head>
    <body>
        <h3 style="margin:5px;">Canlı Takip Paneli (İş Göndermek İçin Haritaya Tıklayın)</h3>
        <div id="map"></div>
        <div id="log">Sistem hazır. Şoförlerin bağlanması bekleniyor...</div>
        <script>
            var map = L.map('map').setView([41.0082, 28.9784], 11);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
            var surucuMarkerlari = {};
            var logDiv = document.getElementById('log');
            var ws = new WebSocket("ws://" + window.location.host + "/ws/admin");
            
            ws.onmessage = function(event) {
                var data = JSON.parse(event.data);
                if(data.bilgi) { logDiv.innerHTML += "<br>> " + data.bilgi; logDiv.scrollTop = logDiv.scrollHeight; }
            };

            map.on('click', function(e) {
                var c = e.latlng;
                logDiv.innerHTML += "<br>> Konum Seçildi: " + c.lat.toFixed(4) + ", " + c.lng.toFixed(4);
                ws.send(JSON.stringify({target_lat: c.lat, target_lng: c.lng}));
            });

            setInterval(function() {
                fetch('/api/suruculer').then(res => res.json()).then(suruculer => {
                    for (var id in suruculer) {
                        var s = suruculer[id];
                        if (s.lat === 0) continue;
                        if (surucuMarkerlari[id]) {
                            surucuMarkerlari[id].setLatLng([s.lat, s.lng]);
                        } else {
                            surucuMarkerlari[id] = L.marker([s.lat, s.lng]).addTo(map).bindPopup(id).openPopup();
                        }
                    }
                });
            }, 3000);
        </script>
    </body>
    </html>
    """

@app.get("/api/suruculer")
async def get_drivers_api():
    return {s_id: {"lat": info["lat"], "lng": info["lng"], "status": info["status"]} for s_id, info in DRIVERS.items()}

if __name__ == "__main__":
    import os
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)