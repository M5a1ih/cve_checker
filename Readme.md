# CVE Checker

Windows cihazlarını ve sürücüleri listeleyen, NVD’den son 3 ayın CVE verilerini çeken ve güvenlik raporları oluşturan Python aracı.

## Özellikler
- Yüklü cihazları ve sürücüleri listeleme (versiyon bilgisi varsa gösterir)
- NVD’den son 3 ayın CVE verilerini indirme
- Otomatik tarama raporu oluşturma
- Manuel CVE sorgusu yapma
- Son indirilen CVE kayıtlarını log olarak inceleme
- Çıktıları masaüstüne CSV olarak kaydetme

## Kurulum
```bash
git clone https://github.com/M5a1ih/cve_checker.git
cd cve_checker
pip install -r requirements.txt

##Kullanım
python cve_checker.py


=== Ana Menü ===
1 - Yüklü cihazları listele
2 - Otomatik tarama raporu oluştur
3 - Manuel CVE sorgusu yap
4 - Logları incele
5 - Çıkış
