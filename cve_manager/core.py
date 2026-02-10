import sqlite3
import requests
import datetime
import os

DB_FILE = "cve.db"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 1000

# İlk kurulumda geriye dönük kaç gün indirilip veritabanının "şişirileceği".
# Örneğin 5 yıl: 365 * 5. Bunu bir defaya mahsus geniş tutuyoruz.
INITIAL_DAYS_BACK = 365 * 5

# İsteğe bağlı NVD API anahtarı (oran limitlerini ve 403 sorunlarını azaltmak için)
NVD_API_KEY = os.getenv("NVD_API_KEY")


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cve (
        id TEXT PRIMARY KEY,
        description TEXT,
        severity TEXT,
        cvss_score REAL,
        published TEXT,
        cpe TEXT,
        remediation TEXT,
        kev_flag INTEGER DEFAULT 0,
        fixed INTEGER DEFAULT 0
    )
    """)

    conn.commit()
    return conn


def _fetch_range(conn, start: datetime.datetime, end: datetime.datetime) -> bool:
    """
    Verilen tarih aralığı için (start, end) NVD'den CVE verisi indirir.
    Başarılı olursa True, HTTP/JSON hatasında False döner.
    """
    cursor = conn.cursor()
    print(f"⬇️ CVE feed {start.isoformat()} -> {end.isoformat()} aralığı indiriliyor...")

    start_index = 0
    while True:
        url = (
            f"{NVD_API}?"
            f"pubStartDate={start.isoformat().replace('+00:00','Z')}&"
            f"pubEndDate={end.isoformat().replace('+00:00','Z')}&"
            f"resultsPerPage={RESULTS_PER_PAGE}&"
            f"startIndex={start_index}"
        )

        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        r = requests.get(url, headers=headers, timeout=30)

        if r.status_code != 200:
            print(f"❌ NVD API isteği başarısız: HTTP {r.status_code}")
            print(f"URL: {url}")
            print(r.text[:300])
            return False

        try:
            data = r.json()
        except ValueError:
            print("❌ NVD API yanıtı JSON formatında değil, indirme durduruluyor.")
            print(f"URL: {url}")
            print(r.text[:300])
            return False

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for v in vulns:
            cve = v["cve"]
            cve_id = cve["id"]
            desc = cve["descriptions"][0]["value"]
            published = cve["published"]

            severity = "UNKNOWN"
            score = None

            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                d = metrics["cvssMetricV31"][0]["cvssData"]
                severity = d["baseSeverity"]
                score = d["baseScore"]

            cpes = []
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        if m.get("vulnerable"):
                            cpes.append(m["criteria"])

            rem = []
            for ref in cve.get("references", []):
                if "Patch" in ref.get("tags", []):
                    rem.append(ref["url"])

            cursor.execute("""
                INSERT OR IGNORE INTO cve
                (id, description, severity, cvss_score, published, cpe, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id,
                desc,
                severity,
                score,
                published,
                ";".join(cpes),
                ";".join(rem)
            ))

        conn.commit()

        total = data.get("totalResults", 0)
        start_index += RESULTS_PER_PAGE
        if start_index >= total:
            break

    return True


def update_feed(conn):
    """
    Artımlı (incremental) CVE güncelleme.

    - Eğer veritabanı boşsa:
        -> INITIAL_DAYS_BACK kadar geriye gidip, 120 günlük pencerelerle
           parça parça indirir (NVD'nin limitlerine daha uyumlu).
    - Eğer veritabanında veri varsa:
        -> En son 'published' tarihini bulur ve sadece ondan SONRAKİ
           CVE'leri indirir (tek aralıkta).
    """
    cursor = conn.cursor()

    # En son hangi tarihe kadar veri aldığımızı bul
    cursor.execute("SELECT MAX(published) FROM cve")
    row = cursor.fetchone()

    now = datetime.datetime.now(datetime.UTC)

    if row and row[0]:
        # Veritabanında veri var -> incremental mod
        try:
            last_published = datetime.datetime.fromisoformat(
                row[0].replace("Z", "+00:00")
            )
        except ValueError:
            last_published = now - datetime.timedelta(days=1)

        start = last_published + datetime.timedelta(seconds=1)
        ok = _fetch_range(conn, start, now)
        if ok:
            print("✅ CVE verisi (incremental) güncellendi.")
        else:
            print("⚠️ Incremental güncelleme sırasında hata oluştu.")
    else:
        # İlk kurulum -> INITIAL_DAYS_BACK kadar geriye gidip 120 günlük parçalara böl
        total_days = INITIAL_DAYS_BACK
        end = now
        print(f"⬇️ CVE feed (initial) toplam {INITIAL_DAYS_BACK} gün, 120 günlük segmentlerle indirilecek...")

        while total_days > 0:
            window_days = min(120, total_days)
            start = end - datetime.timedelta(days=window_days)
            ok = _fetch_range(conn, start, end)
            if not ok:
                print("⚠️ Bu segmentte hata oluştu, kalan segmentler atlanıyor.")
                break
            end = start
            total_days -= window_days

        print("✅ CVE verisi (initial) güncelleme denemesi tamamlandı.")
