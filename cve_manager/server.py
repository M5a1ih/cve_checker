from flask import Flask, render_template, request, redirect, flash, Response, url_for
import sqlite3
import logging
import subprocess
import datetime
import os
from urllib.parse import urlparse

import requests

from inventory import get_installed_programs
from matcher import match_programs_to_cves
from core import init_db, update_feed
from kev import enrich_with_kev

app = Flask(__name__)
app.secret_key = "your-secret-key"

logging.basicConfig(
    filename="fix.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

DB_FILE = "cve.db"

# Opsiyonel: gerçek LLM entegrasyonu için OpenAI API anahtarı
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def build_ai_like_suggestion(cve_id: str, description: str, cpe: str, severity: str, cvss_score, remediation_urls: str) -> str:
    """
    Eğer OPENAI_API_KEY tanımlıysa, OpenAI Chat Completions API ile
    gerçek bir LLM'den remediation önerisi ister.
    Anahtar tanımlı değilse veya çağrı hata verirse, yerel (rule-based)
    fallback mantığı kullanılır.
    """
    # 1️⃣ Önce LLM'e sormayı dene
    if OPENAI_API_KEY:
        try:
            system_prompt = (
                "You are a cybersecurity assistant. Given a CVE record, "
                "generate concise, actionable remediation guidance for a Windows workstation administrator. "
                "Focus on concrete steps (patch/update/mitigation), do not invent patches, and keep it under 15 lines."
            )
            user_prompt = f"""
CVE ID: {cve_id}
Severity: {severity or "UNKNOWN"}
CVSS score: {cvss_score if cvss_score is not None else "unknown"}
CPE: {cpe or "-"}
Description: {description}
Remediation URLs (from NVD, if any): {remediation_urls or "-"}

Generate remediation steps in Turkish. Use numbered or bulleted steps if appropriate.
"""
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.3,
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            content = (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
            if content:
                return content.strip()
        except Exception as e:
            logging.warning(f"OpenAI çağrısı başarısız oldu ({cve_id}): {e}")
            # Fallback'e düşeceğiz

    # 2️⃣ Fallback: mevcut kural tabanlı öneri
    lines = []

    sev = (severity or "").upper()
    score = cvss_score if cvss_score is not None else "bilinmiyor"

    lines.append(f"CVE: {cve_id}")
    lines.append(f"Önem derecesi: {sev or 'UNKNOWN'} (CVSS: {score})")

    # CPE içinden ürün/vendor çıkarma denemesi
    product_hint = ""
    if cpe:
        # tipik format: cpe:2.3:a:vendor:product:version:...
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor = parts[3]
            product = parts[4]
            product_hint = f"{vendor} {product}".strip(":")

    if product_hint:
        lines.append(f"Etkilenen ürün: {product_hint}")

    # Remediation URL’leri varsa bunları kullan
    urls = [u for u in (remediation_urls or "").split(";") if u.strip()]
    if urls:
        lines.append("Vendor tarafından sağlanan olası patch / advisory adresleri:")
        for u in urls:
            host = urlparse(u).netloc or u
            lines.append(f"- {host} üzerindeki duyuruyu inceleyin: {u}")
        lines.append("Önerilen adımlar:")
        lines.append("- İlgili sürüm için yayınlanmış güvenlik güncellemesini / patch’i uygulayın.")
        lines.append("- Güncelleme sonrası uygulamayı/servisi yeniden başlatın ve log’ları kontrol edin.")
    else:
        lines.append("Bu CVE için NVD kaydında doğrudan bir 'Patch' URL’si bulunamadı.")
        lines.append("Genel önerilen adımlar:")
        if product_hint:
            lines.append(f"- {product_hint} yazılımını/ürününü en güncel sürüme yükseltin.")
        else:
            lines.append("- İlgili yazılımı/ürünü en güncel kararlı sürüme yükseltin.")
        lines.append("- Vendor’un güvenlik sayfasında bu CVE ID için ek duyuru/patch olup olmadığını kontrol edin.")
        lines.append("- Kullanılmayan/önemsiz bileşenleri devre dışı bırakmayı veya kaldırmayı değerlendirin.")

    if sev in ("CRITICAL", "HIGH"):
        lines.append("Not: Yüksek/kritik zafiyetler için değişikliği olabildiğince kısa sürede planlayın ve uygulayın.")

    return "\n".join(lines)


@app.route("/", methods=["GET", "POST"])
def index():
    conn = get_db_connection()

    # 1️⃣ POST işlemleri: Fix veya AI önerisi
    if request.method == "POST":
        # a) Fix butonu
        cve_id = request.form.get("fix_cve")
        suggested_fix = request.form.get("suggested_fix")
        execute_real = request.form.get("execute_real") == "1"

        # b) AI önerisi butonu
        ai_cve = request.form.get("ai_cve")

        if cve_id:
            try:
                # Varsayılan: sadece göster / simüle et
                if suggested_fix:
                    cmd_to_show = suggested_fix
                else:
                    cmd_to_show = f"winget upgrade --id <PRODUCT_ID>  # {cve_id} için örnek"

                if execute_real and suggested_fix:
                    # Kullanıcı açıkça onay verdiyse gerçek komutu çalıştır
                    result = subprocess.run(
                        suggested_fix,
                        shell=True,
                        capture_output=True,
                        text=True
                    )
                    if result.returncode != 0:
                        flash(
                            f"{cve_id} için remediation başarısız.\nKomut: {suggested_fix}\nHata: {result.stderr}",
                            "error",
                        )
                    else:
                        flash(
                            f"{cve_id} için remediation ÇALIŞTIRILDI.\nKomut: {suggested_fix}\nÇıktı:\n{result.stdout}",
                            "success",
                        )
                    logging.info(f"FIX executed for {cve_id}: {suggested_fix}")
                else:
                    # Sadece ne yapılacağını göster
                    flash(
                        f"{cve_id} için aşağıdaki komut ÖNERİLEN remediation’dır (simülasyon):\n{cmd_to_show}",
                        "info",
                    )
                    logging.info(f"FIX simulated for {cve_id}: {cmd_to_show}")
            except Exception as e:
                flash(f"{cve_id} için remediation hatası: {str(e)}", "error")

            conn.close()
            return redirect("/")

        if ai_cve:
            # Satırdan gelen verilerle AI-benzeri öneri oluştur
            ai_desc = request.form.get("ai_desc", "")
            ai_cpe = request.form.get("ai_cpe", "")
            ai_severity = request.form.get("ai_severity", "")
            ai_cvss = request.form.get("ai_cvss")
            ai_fix = request.form.get("ai_fix", "")

            try:
                ai_cvss_val = float(ai_cvss) if ai_cvss not in (None, "", "None") else None
            except ValueError:
                ai_cvss_val = None

            suggestion = build_ai_like_suggestion(
                cve_id=ai_cve,
                description=ai_desc,
                cpe=ai_cpe,
                severity=ai_severity,
                cvss_score=ai_cvss_val,
                remediation_urls=ai_fix,
            )

            flash(f"AI önerisi ({ai_cve}):\n{suggestion}", "info")

            conn.close()
            return redirect("/")

    # 2️⃣ Kullanıcı PC’sindeki yazılımları çek
    installed_programs = get_installed_programs()  # liste string olarak ['VLC 3.0.20', 'Firefox 122.0', ...]

    # 3️⃣ Filtreleme: tarih, CVSS ve arama terimi
    mode = request.args.get("mode", "recent")  # recent / since2022 / db_all
    cvss_threshold_raw = request.args.get("cvss", "0")  # default 0
    # Geriye dönük uyumluluk için parametre adı "vendor" ama aslında genel arama
    search_term = request.args.get("vendor", "").strip()

    try:
        cvss_threshold = float(cvss_threshold_raw)
    except ValueError:
        cvss_threshold = 0.0

    # Tarih filtresi
    since_date = datetime.date.today() - datetime.timedelta(days=120)
    date_filter_clause = ""
    date_params = []

    if mode == "recent":
        # Son 120 gün
        date_filter_clause = "AND DATE(published) >= ?"
        date_params.append(since_date.isoformat())
    elif mode == "since2022":
        # 2022 ve sonrası
        date_filter_clause = "AND CAST(strftime('%Y', published) AS INTEGER) >= 2022"
        # db_all: tarih filtresi yok

    # Arama filtresi (CVE ID, açıklama, CPE içinde geçen string vs.)
    search_clause = ""
    search_params = []
    if search_term:
        search_clause = """
          AND (
              LOWER(id) LIKE ?
              OR LOWER(description) LIKE ?
              OR LOWER(cpe) LIKE ?
          )
        """
        pattern = f"%{search_term.lower()}%"
        search_params = [pattern, pattern, pattern]

    # 4️⃣ CVE feed / KEV zenginleştirme
    # Uygulamayı normalde `run.py` ile başlattığınızda bootstrap zaten yapılmış olur.
    # Burada sadece DB boşsa minimal bir güncelleme tetikleyebiliriz.
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(1) FROM cve")
    total_in_db = cursor.fetchone()[0]
    if total_in_db == 0:
        update_feed(conn)
        enrich_with_kev(conn)

    # 5️⃣ Tüm uygun CVE’leri çek (tek sorgu)
    base_query = f"""
        SELECT
            id,
            description,
            severity,
            cvss_score,
            cpe,
            remediation AS suggested_fix,
            published,
            kev_flag
        FROM cve
        WHERE (fixed IS NULL OR fixed = 0)
          AND (cvss_score IS NULL OR cvss_score >= ?)
          {date_filter_clause}
          {search_clause}
        ORDER BY kev_flag DESC, cvss_score DESC
    """
    params = [cvss_threshold] + date_params + search_params
    cursor.execute(base_query, params)
    all_cve_rows = cursor.fetchall()

    # Row'ları dict'e çevir ki matcher ile rahat çalışalım
    all_cves = [dict(r) for r in all_cve_rows]

    # 6️⃣ PC eşleşmeli CVE’ler
    matched_rows = []
    if installed_programs and all_cves:
        matched_rows = match_programs_to_cves(installed_programs, all_cves)

    matched_ids = {r["id"] for r in matched_rows}

    # 7️⃣ Diğer CVE’ler (PC ile eşleşmeyenler)
    other_rows = [r for r in all_cves if r["id"] not in matched_ids]

    conn.close()
    return render_template(
        "index.html",
        matched_rows=matched_rows,
        all_rows=other_rows,
        installed_programs=installed_programs,
        mode=mode,
        cvss_threshold=cvss_threshold,
        vendor=search_term,
        ai_enabled=bool(OPENAI_API_KEY),
    )


@app.route("/inventory_export", methods=["GET"])
def inventory_export():
    """
    Bu makinedeki yüklü programları (ad + versiyon) CSV olarak indirilebilir
    hale getirir. Notepad'de de açılabilir, Excel'de de düzgün görünür.
    """
    programs = get_installed_programs()

    lines = ["Program"]
    for p in programs:
        # Satır içi newline vs. bozuklukları temizle
        clean = (p or "").replace("\n", " ").strip()
        if clean:
            lines.append(clean)

    csv_content = "\n".join(lines)
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=installed_programs.csv"
        },
    )


if __name__ == "__main__":
    conn = init_db()
    update_feed(conn)
    enrich_with_kev(conn)
    conn.close()
    app.run(host="127.0.0.1", port=5000, debug=True)
