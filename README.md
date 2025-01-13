# Nessus Parser

Bu proje, **Nessus** tarayıcısının oluşturduğu `.nessus` dosyalarını **etkileşimli** bir şekilde işleyip **iki farklı Excel çıktısı** üreten bir **Python** aracı sunar.

## Özellikler

- **Etkileşimli Kullanım:**  
  Çalıştırıldığında terminal üzerinden  
  1. `.nessus` dosyasının yolu,  
  2. Çıktı Excel dosyasının adı (varsayılan: `nessus_output.xlsx`),  
  3. Dahil edilmek istenen risk seviyeleri (ör. `None, Info, Low, Medium, High, Critical`)  
  bilgileri istenir.

- **Çift Çıktı Üretimi:**  
  1. **Ana Rapor Excel (ör. `cikti.xlsx`)**  
     - Her bir zafiyet “Host, Port, Risk, Zafiyet Adı, CVE, CVSS vb.” sütunlarıyla listelenir.  
     - “Durum” (drop-down list) ve “Notlar” sütunları eklenerek operasyonel takibi kolaylaştırır.  
     - Risk sütunu, zafiyetin kritiklik seviyesine göre (Critical, High, vb.) **renklendirilir**.  

  2. **İstatistik Excel (ör. `istatistik_cikti.xlsx`)**  
     - Toplam taranan sistem (host) sayısı,  
     - Toplam zafiyet (bulgu) sayısı,  
     - Farklı (uniq) zafiyet adı adedi,  
     - Her risk seviyesi için toplam/farklı zafiyet adedi,  
     gibi bilgileri içerir.

- **Risk Seviyesi Filtreleme:**  
  - `High,Medium` şeklinde girdiğinizde sadece bu seviyelerdeki zafiyetler eklenir.  
  - Boş bırakılırsa tüm seviyeler (Critical, High, Medium, Low, Info, None) dahil edilir.

- **Colorama ile Renkli Terminal Çıktısı:**  
  - Terminalde `Critical` = kırmızı, `High` = açık kırmızı, `Medium` = sarı, vb. renkler kullanılır.

## Kurulum

1. **Python 3.6+** kurulu olmalıdır.  
2. Aşağıdaki kütüphaneleri yükleyin:
   ```bash
   pip install openpyxl colorama
Bu repodaki nessus_parser.py dosyasını UTF-8 formatında indirin veya kopyalayın.
Başında # -*- coding: utf-8 -*- satırı bulunmalıdır.
Türkçe karakterler için UTF-8 kaydı önemlidir.
Nasıl Çalıştırılır?
Terminal/Powershell üzerinde kodun bulunduğu klasöre gidin.

Şu komutu verin:

bash
Kodu kopyala
python nessus_parser.py
Program sırasıyla:

.nessus dosyasının yolunu (ör. C:\tarama\rapor.nessus),
Çıktı Excel dosyasının adını (boş bırakırsanız nessus_output.xlsx),
Dahil edilmesi istenen risk seviyelerini (ör. High, Medium), isteyecektir.
Seçimlerinize göre parse işlemi yapılır ve:

Ana rapor dosyası (ör. cikti.xlsx),
İstatistik dosyası (ör. istatistik_cikti.xlsx) oluşturulur.
Örnek Terminal Çıktısı
plaintext
Kodu kopyala
[DETAIL] Host: 192.168.0.10, Port: 443, Risk: High, Zafiyet: SSL Certificate Issues
[INFO] 192.168.0.10 adresinde 3 adet zafiyet bulundu.
...
[INFO] Ana rapor Excel oluşturuldu: cikti.xlsx
[INFO] İstatistik dosyası oluşturuldu: istatistik_cikti.xlsx
Özelleştirme
Renk Kodları:
risk_colors sözlüğünden Excel hücre renklerini değiştirebilirsiniz.
terminal_color_map ise terminaldeki renklendirme içindir.
İstatistikler:
Kodun istatistik_<rapor_dosyası> kısmına, ortalama CVSS veya en sık görülen zafiyet gibi ek satırlar eklenebilir.
“Durum” Sütunu:
Varsayılan olarak Giderildi, Giderilemedi, Devam Ediyor, False Positive seçenekleri mevcuttur.
DataValidation kısmında bu seçenekleri güncelleyebilirsiniz.
