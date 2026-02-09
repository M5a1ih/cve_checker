import wmi
import sqlite3
import requests
import csv
import os
import datetime
from tabulate import tabulate

DB_FILE = "cve.db"
LASTUPDATEFILE = "last_update.txt"
DESKTOP = os.path.join(os.path.expanduser("~"), "Desktop")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cve (
        id TEXT PRIMARY KEY,
        description TEXT,
        severity TEXT,
        published DATE
    )
    """)
    conn.commit()
    return conn

def update_feed(conn):
    today = datetime.datetime.now()
    three_months_ago = today - datetime.timedelta(days=90)

    NVDFEEDURL = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?"
        f"pubStartDate={three_months_ago.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z&"
        f"pubEndDate={today.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z&"
        "resultsPerPage=100"
    )

    print("Yeni feed indiriliyor...")
    try:
        response = requests.get(NVDFEEDURL)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print("\n[!] Feed indirilemedi veya JSON hatalı:")
        print(f"    Hata: {e}")
        return

    cursor = conn.cursor()
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln["cve"]["id"]
        desc = vuln["cve"]["descriptions"][0]["value"]
        severity = vuln["cve"].get("metrics", {}).get("cvssMetricV2", [{}])[0].get("baseSeverity", "UNKNOWN")
        published = vuln["cve"]["published"]

        cursor.execute("""
        INSERT OR IGNORE INTO cve (id, description, severity, published)
        VALUES (?, ?, ?, ?)
        """, (cve_id, desc, severity, published))
    conn.commit()

    with open(LASTUPDATEFILE, "w") as f:
        f.write(datetime.datetime.now().isoformat())

    print("\nİndirilen CVE örnekleri (son 3 ay):")
    cursor.execute("SELECT id, description, severity, published FROM cve ORDER BY published DESC LIMIT 5")
    for row in cursor.fetchall():
        print(f"  {row[0]} | {row[2]} | {row[3]}")
        print(f"    {row[1][:100]}...")

def collect_devices():
    c = wmi.WMI()
    devices = []
    for device in c.Win32_PnPEntity():
        version = getattr(device, "DriverVersion", None)
        if not version:
            version = "Versiyon bulunamadı"
        devices.append({"name": device.Name, "version": version})
    return devices

def export_csv(results, filename="report.csv", headers=None):
    filepath = os.path.join(DESKTOP, filename)
    with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
    writer = csv.writer(f)
        if headers:
            writer.writerow(headers)
        for row in results:
            writer.writerow(row)
    print(f"\n[+] Dosya kaydedildi: {filepath}")

def search_cve(conn, keyword):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cve WHERE description LIKE ? OR id LIKE ?", (f"%{keyword}%", f"%{keyword}%"))
    return cursor.fetchall()

def manual_query(conn):
    keyword = input("Manuel sorgu için cihaz/versiyon girin: ")
    results = search_cve(conn, keyword)
    headers = ["CVE ID", "Description", "Severity", "Published"]
    if results:
        print(tabulate(results, headers=headers, tablefmt="grid"))
    else:
        print("Sonuç bulunamadı.")
    save = input("Bu listeyi dosyaya kaydetmek ister misiniz? (e/h): ")
    if save.lower() == "e":
        export_csv(results, "manual_report.csv", headers)

def print_results(results):
    headers = ["Device", "Version", "CVE ID", "Severity", "Description", "Published"]
    print("\nTarama Sonuçları:\n")
    if results:
        print(tabulate(results, headers=headers, tablefmt="grid"))
    else:
        print("Hiç eşleşme bulunamadı.")
    save = input("Bu listeyi dosyaya kaydetmek ister misiniz? (e/h): ")
    if save.lower() == "e":
        export_csv(results, "report.csv", headers)

def generate_report(conn, devices):
    all_results = []
    for d in devices:
        results = search_cve(conn, d["name"])
        if results:
            for r in results:
                all_results.append([d["name"], d["version"], r[0], r[2], r[1], r[3]])
        else:
            all_results.append([d["name"], d["version"], "-", "-", "-", "-"])
    print_results(all_results)
    return all_results

def main_menu(conn, devices):
    all_results = []
    while True:
        print("\n=== Ana Menü ===")
        print("1 - Yüklü cihazları listele")
        print("2 - Otomatik tarama raporu oluştur")
        print("3 - Manuel CVE sorgusu yap")
        print("4 - Logları incele (son indirilen CVE örnekleri)")
        print("5 - Çıkış")

        choice = input("Seçiminizi yapın: ")

        if choice == "1":
            print("\nToplanan cihazlar:")
            headers = ["Device", "Version"]
            results = [[d["name"], d["version"]] for d in devices]
            print(tabulate(results, headers=headers, tablefmt="grid"))
            save = input("Bu listeyi dosyaya kaydetmek ister misiniz? (e/h): ")
            if save.lower() == "e":
                export_csv(results, "devices.csv", headers)
        elif choice == "2":
            all_results = generate_report(conn, devices)
        elif choice == "3":
            manual_query(conn)
        elif choice == "4":
            cursor = conn.cursor()
            cursor.execute("SELECT id, description, severity, published FROM cve ORDER BY published DESC LIMIT 10")
            results = cursor.fetchall()
            headers = ["CVE ID", "Description", "Severity", "Published"]
            print(tabulate(results, headers=headers, tablefmt="grid"))
            save = input("Bu listeyi dosyaya kaydetmek ister misiniz? (e/h): ")
            if save.lower() == "e":
                export_csv(results, "logs.csv", headers)
        elif choice == "5":
            print("\nProgramdan çıkılıyor...")
            break
        else:
            print("Geçersiz seçim, tekrar deneyin.")

def main():
    conn = init_db()
    update_feed(conn)
    devices = collect_devices()
    main_menu(conn, devices)

if __name__ == "__main__":
    main()
    print("\nProgram tamamlandı.")
    input("Kapatmak için Enter'a basın...")