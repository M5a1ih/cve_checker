def enrich_with_kev(conn):
    # Örnek: tüm KEV’leri flagle
    cursor = conn.cursor()
    cursor.execute("UPDATE cve SET kev_flag = 1 WHERE id LIKE 'CVE-%'")
    conn.commit()
