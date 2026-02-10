import threading
import webbrowser
import time

import server
from core import init_db, update_feed
from kev import enrich_with_kev

def bootstrap():
    print("🔧 Veritabanı hazırlanıyor...")
    conn = init_db()
    print("⬇️ CVE feed güncelleniyor...")
    update_feed(conn)
    print("🔥 KEV kontrolü yapılıyor...")
    enrich_with_kev(conn)
    conn.close()
    print("✅ Sistem hazır.")

def start_server():
    server.app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    bootstrap()
    thread = threading.Thread(target=start_server, daemon=True)
    thread.start()
    time.sleep(2)
    webbrowser.open("http://127.0.0.1:5000")
    print("🚀 CVE Vulnerability Manager çalışıyor.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("⛔ Kapatılıyor...")
