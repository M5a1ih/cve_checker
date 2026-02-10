# CVE Vulnerability Manager

Windows üzerinde yüklü uygulamaları tarayıp, NVD CVE veritabanıyla eşleştiren, KEV bilgisiyle zenginleştiren ve remediation (düzeltme) önerileri sunan mini dashboard.

---

## 🚀 Özellikler

### Envanter Çıkarma
- `wmic product get Name, Version` ile Windows PC’deki yüklü uygulama + versiyon listesini çeker.
- Arayüzde tablo halinde gösterir.
- `installed_programs.csv` olarak indirilebilir CSV/Excel çıktısı verir.

### CVE Veritabanı (SQLite)
- NVD `cves/2.0` API’sinden CVE kayıtlarını indirip `cve.db` içinde saklar.
- İlk kurulumda son X yıl (konfigüre edilebilir) için veriyi **120 günlük segmentler** halinde çeker.
- Sonraki çalıştırmalarda **artımlı güncelleme** yapar:
  - Veritabanındaki en son `published` tarihini bulur,
  - Sadece bu tarihten sonraki yeni CVE’leri indirir.
- `INSERT OR IGNORE` ile aynı kaydı tekrar eklemez.

### PC’ye Özel CVE Eşleştirme
- `inventory.py` ile toplanan program listesi,
- `matcher.py` içindeki `normalize` mantığı ile CPE alanlarıyla karşılaştırılır.
- Bu PC’de yüklü uygulamalarla eşleşen CVE’ler **üst tabloda** gösterilir.
- Eşleşmeyen fakat filtreye uyan diğer CVE’ler **alt tabloda** listelenir.

### Filtreleme ve Sıralama
- Gösterim modu:
  - `Son 120 gün`
  - `2022 sonrası`
  - `Veritabanındaki tüm CVE’ler`
- CVSS alt sınırı (`CVSS ≥ x.x`)
- Serbest metin arama:
  - CVE ID, Description ve CPE alanlarında eş zamanlı arar.
  - Örnek: `chrome`, `144.0.7559.59`, `intel`, `CVE-2019-18278`
- Sıralama:
  - Önce `kev_flag` (Known Exploited Vulnerabilities),
  - Sonra `cvss_score` (yüksekten düşüğe).

### KEV (Known Exploited Vulnerabilities) Entegrasyonu
- `kev.py` ile KEV bilgisi işlenip `kev_flag` alanı set edilir.
- Arayüzde KEV / kritik / yüksek CVE’ler renkli arka planla vurgulanır:
  - KEV: sarımsı (`kev-row`)
  - Kritik (CVSS ≥ 9): kırmızımsı (`critical-row`)
  - Yüksek (CVSS ≥ 7): turuncumsu (`high-row`)

### Fix Butonu ve Komut Çalıştırma
- Her CVE satırında:
  - `Fix` butonu
  - **Varsayılan**: önerilen komutu (ör. `winget`) **simülasyon** olarak gösterir.
  - `Gerçek komutu çalıştır` checkbox’ı işaretlenirse:
    - İlgili komutu gerçekten `subprocess.run` ile çalıştırır,
    - Çıktıyı/hatayı flash mesajında gösterir,
    - `fix.log` dosyasına log yazar.
- Yanlışlıkla otomatik güncelleme riski olmadan kontrollü remediation yapılabilir.

### AI’den Remediation Önerisi (Opsiyonel)
- Her CVE satırında **“AI’dan öneri al”** butonu:
  - Tek bir CVE için öneri üretir.
- Çalışma mantığı:
  1. Eğer ortamda `OPENAI_API_KEY` tanımlıysa:
     - OpenAI Chat Completions API (`gpt-4o-mini`) çağrılır.
     - CVE ID, severity, CVSS, CPE, description ve NVD `remediation` URL’lerinden yola çıkarak **Türkçe, kısa ve adım adım** öneri üretir.
  2. Eğer:
     - `OPENAI_API_KEY` yoksa,
     - Veya API çağrısı hata verirse,
     - Sistem otomatik olarak **kural tabanlı fallback** metin üretir.
- Arayüz:
  - Eğer `OPENAI_API_KEY` yoksa:
    - Üstte bilgi mesajı: `OPENAI_API_KEY tanımlandığında AI’dan öneri al butonları aktif olur.`
    - Satırlarda: “AI devre dışı (OPENAI_API_KEY yok)” bilgisi görünür.
  - Eğer tanımlıysa:
    - “AI’dan öneri al” butonları aktifleşir.

### Basit ve Anlaşılır Arayüz
- İki ana tablo:
  - PC’ye özel eşleşen CVE’ler,
  - Diğer (eşleşmeyen) CVE’ler.
- İlgili sütunlar:
  - CVE ID (link olarak),
  - Description (kısaltılmış),
  - Severity, CVSS,
  - CPE (Affected Products),
  - Suggested Fix (NVD remediation),
  - Published,
  - Action (Fix / AI’dan öneri al).
- Flash mesajlar:
  - Başarılı işlem (yeşil),
  - Hata (kırmızı),
  - Bilgi / AI önerisi (mavi),
  - Komut çıktıları düzgün formatta gösterilir.

---

## 📂 Dosya Yapısı
- `run.py` → Uygulamanın giriş noktası, bootstrap ve Flask başlatma.
- `server.py` → Flask web sunucusu ve HTTP endpoint’ler.
- `core.py` → Veritabanı şeması ve NVD feed yönetimi.
- `inventory.py` → Yüklü programları çeker.
- `matcher.py` → Program isimleri ile CPE eşleştirme.
- `kev.py` → KEV işaretleme mantığı.
- `templates/index.html` → Dashboard HTML + CSS şablonu.

---

## 🔧 Kurulum

1. Depoyu klonla:
   ```bash
   git clone https://github.com/USERNAME/cve-vulnerability-manager.git
   cd cve-vulnerability-manager
2.	Gerekli paketleri yükle: 
3.	pip install -r requirements.txt
(Yoksa en azından Flask ve requests kurulu olmalı.)
4.	(Opsiyonel) OpenAI API anahtarı ile AI önerilerini aktif et: 
5.	setx OPENAI_API_KEY "SENIN_OPENAI_API_KEYIN"
Terminali kapatıp aç.
6.	Uygulamayı çalıştır: 
7.	python run.py
o	Terminalde bootstrap log’larını görürsün.
o	Ardından tarayıcıda http://127.0.0.1:5000 otomatik açılır.
________________________________________
🔒 Güvenlik Notları
•	API anahtarları hiçbir zaman koda gömülmemiştir.
•	OPENAI_API_KEY yalnızca ortam değişkeninden okunur.
•	NVD API key’i kullanmak isterseniz, NVD_API_KEY ortam değişkeni üzerinden tanımlanabilir.
•	Bu repo’ya asla gerçek API key’lerinizi, .env dosyalarınızı veya log’larınızı commit etmeyin.
•	Fix butonunun gerçek komut çalıştırma özelliği açıkça onay gerektirir.
•	Varsayılan davranış yalnızca önerilen komutu simülasyon olarak göstermektir.
________________________________________
🛠 Yol Haritası / Geliştirme Fikirleri
•	Gerçek KEV feed entegrasyonu.
•	NVD tarafında vendor / ürün bazlı daha akıllı filtreler.
•	Uygulama sürümlerine göre daha hassas CPE eşleştirme.
•	Kullanıcı profil ayarları (varsayılan CVSS eşiği, varsayılan filtreler, vb.).
________________________________________


