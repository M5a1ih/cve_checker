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

##Örnek Çıktı

=== Ana Menü ===
1 - Yüklü cihazları listele
2 - Otomatik tarama raporu oluştur
3 - Manuel CVE sorgusu yap
4 - Logları incele
5 - Çıkış

+----------------------------+-------------------+
| Device                     | Version           |
+----------------------------+-------------------+
| Intel(R) Ethernet Controller | 12.18.9         |
| NVIDIA GeForce GTX 1050    | 31.0.15.5222      |
| Realtek Audio Device       | Versiyon bulunamadı |
+----------------------------+-------------------+



