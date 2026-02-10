import sqlite3

conn = sqlite3.connect("cve.db")
cursor = conn.cursor()

# fixed sütunu ekle (eğer yoksa)
try:
    cursor.execute("ALTER TABLE cve ADD COLUMN fixed INTEGER DEFAULT 0")
except sqlite3.OperationalError:
    pass

# kev_flag sütunu ekle (eğer yoksa)
try:
    cursor.execute("ALTER TABLE cve ADD COLUMN kev_flag INTEGER DEFAULT 0")
except sqlite3.OperationalError:
    pass

conn.commit()
conn.close()
print("✅ Veritabanı güncellendi.")
