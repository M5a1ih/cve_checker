# Windows Device & CVE Reporter

Bu proje, Windows üzerinde yüklü cihazları ve sürücüleri listeleyen, 
NVD API üzerinden son 3 ayda yayınlanan CVE kayıtlarını indiren ve 
raporlayan bir Python uygulamasıdır.

## Özellikler
- Yüklü cihazları listeleme
- CVE veritabanını güncelleme
- Otomatik tarama raporu oluşturma
- Manuel CVE sorgusu yapma
- Logları inceleme
- Çıktıları CSV olarak masaüstüne kaydetme

## Kurulum
```bash
git clone https://github.com/kullaniciadi/cve-reporter.git
cd cve-reporter
pip install -r requirements.txt
