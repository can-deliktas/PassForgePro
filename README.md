# PassForge Pro | Indestructible Identity Vault

<div align="center">

![PassForge Pro](https://img.shields.io/badge/PassForge-Pro-00FFD0?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

**[🇬🇧 English](#english) | [🇹🇷 Türkçe](#türkçe)**

</div>

---

# English

## 🔐 About PassForge Pro

PassForge Pro is a **zero-knowledge**, **local-first** password vault built with **paranoia-grade security**. Designed to withstand even aggressive state-level forensic analysis, it stores your credentials in an AES-256 encrypted SQLite database that never leaves your machine.

This is not just a password manager—it is a **cryptographic fortress** designed for advanced security professionals and individuals requiring absolute digital sovereignty.

### 🎯 Core Philosophy

- **Zero-Knowledge Architecture**: Your master password never leaves RAM. We can't access your data—ever.
- **Local-First**: No cloud sync, no telemetry, no network connections. Your vault = your machine.
- **Memory-Safe**: Sensitive data is wiped from RAM immediately after use.
- **Open Source**: Every line of code is auditable on GitHub.

### 🛡️ Strategic Security Protocols

- **Military-Grade Encryption**: AES-256 GCM / Fernet authenticated encryption
- **Adaptive KDF**: PBKDF2-HMAC-SHA256 (150,000 iterations) + BCrypt (12 rounds)
- **Ghost Protocol**: Signature masking in system directories to evade static analysis
- **Noisy Wipe**: Multi-pass recursive sector overwriting for secure data destruction
- **Autonomous Locking**: Inactivity-based memory purging and vault closure
- **Clipboard Sanitation**: Automated background wiping of sensitive data from OS clipboard

---

## ⚠️ Legal Disclaimer

> **IMPORTANT**: This application is provided "AS-IS" without any warranty. We do NOT provide state-level, government-certified, or military-grade security guarantees.

By using this software:
1. **You accept full responsibility** for your data security and vault management.
2. **You acknowledge compliance** with local laws (TCK, KVKK, BTK for Turkish users).
3. **You understand** that **lost master passwords result in irreversible data loss**. No recovery mechanism exists by design.
4. **Legal Compliance**: Users are responsible for ensuring their use complies with all local and international digital privacy and encryption laws.
5. **Security Auditing**: While designed for high-end security, PassForge Pro should be used with robust operational security (OpSec) practices (e.g., air-gapped devices for maximum protection).

For more details, review our [Privacy & Security Policy](https://can-deliktas.github.io/PassForgePro/legal.html).

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔒 **AES-256 GCM Encryption** | Military-standard authenticated encryption |
| 🔑 **PBKDF2-HMAC-SHA256** | 150,000+ iterations for key derivation |
| 🧠 **Memory Purging** | RAM wiped on lock, exit, or inactivity |
| 📋 **Clipboard Sanitization** | Auto-clear after 10-60 seconds |
| ⏱️ **Auto-Lock Timer** | Configurable inactivity timeout |
| 🎨 **7 Premium Themes** | Cyberpunk, Midnight, Neon, and more |
| 📁 **Folder Hierarchy** | Unlimited nested categories |
| 🔄 **Trash Recovery** | 30-day soft delete before permanent wipe |
| 🎲 **Password Generator** | Cryptographically secure random passwords |

---

## 📥 Installation & Setup

### Prerequisites
- **Python 3.8+**
- **Windows 10/11**
- **Administrator privileges** (for system-level operations)

### Step 1: Clone Repository
```bash
git clone https://github.com/can-deliktas/PassForgePro.git
cd PassForgePro
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Launch Application
```bash
python PassForgePro.py
```

---

## 🎯 Usage (GUI)

### First Run
1. Launch the application
2. Enter a **strong master password** (minimum 8 characters)
3. Select or create a vault location (`.db` file)
4. Access your encrypted vault

### Interface Overview

| Screen | Purpose |
|--------|---------|
| **Login** | Master password entry with entropy indicator |
| **Vault** | Browse, search, and manage credentials |
| **Generator** | Create random passwords with custom rules |
| **Settings** | Configure auto-lock, clipboard timeout, themes |
| **Trash** | Recover or permanently delete entries |

### Preview Images

<details>
<summary>🖼️ Click to view screenshots</summary>

- `preview-en/login.png` - Authentication Screen
- `preview-en/active-vault.png` - Active Vault View
- `preview-en/generator.png` - Password Generator
- `preview-en/settings.png` - Settings Panel
- `preview-en/recycle-bin.png` - Trash Management

</details>

---

## 🗂️ Project Structure

```
PassforgeV2/
├── passforgepropy/          # Python Application
│   ├── PassForgePro.py      # Main application (GUI + Logic)
│   ├── requirements.txt     # Python dependencies
│   ├── LICENSE              # GNU GPL-3.0
│   ├── README.md            # This file
│   └── .github/
│       └── ISSUE_TEMPLATE/
│           ├── bug_report.md
│           └── feature_request.md
```

---

## 📝 License and Copyright

PassForge Pro is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

- ✅ You may use, modify, and distribute this software
- ✅ You must include the original copyright notice
- ✅ You must disclose source code for derivative works
- ❌ No warranty is provided

**© 2026 Can Arkadaş Deliktaş. All Rights Reserved.**

---

## 🤝 How to Contribute?

1. **Fork** the repository
2. Create a **feature branch**: `git checkout -b feature/AmazingFeature`
3. **Commit** your changes: `git commit -m 'Add AmazingFeature'`
4. **Push** to the branch: `git push origin feature/AmazingFeature`
5. Open a **Pull Request**

### Reporting Issues
- Use the [Bug Report Template](passforgepropy/.github/ISSUE_TEMPLATE/bug_report.md)
- Use the [Feature Request Template](passforgepropy/.github/ISSUE_TEMPLATE/feature_request.md)

---

## 👨‍💻 Developer Notes

### Security Architecture
- **Encryption**: Fernet (AES-256-GCM) via `cryptography` library
- **KDF**: PBKDF2 with HMAC-SHA256, 150k iterations, 16-byte salt
- **Memory**: `bytearray` for passwords, explicit zeroing
- **Database**: SQLite with encrypted BLOB storage

### Code Highlights
```python
# Key Derivation
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=150000
)

# Memory Wipe
def secure_wipe(data: bytearray):
    for i in range(len(data)):
        data[i] = 0
```

### Technology Stack
- **Foundations**: Python, CustomTkinter, Cryptography.io
- **Contributions**: We welcome PRs that enhance cryptographic entropy, improve anti-forensic measures, or expand localization

---

# Türkçe

## 🔐 PassForge Pro Hakkında

PassForge Pro, **sıfır bilgi** ve **yerel öncelikli** mimariye sahip, **paranoya seviyesinde güvenlik** sunan bir şifre kasasıdır. Kimlik bilgilerinizi asla makinenizden ayrılmayan AES-256 şifreli SQLite veritabanında saklar.

Bu sadece bir şifre yöneticisi değil—gelişmiş güvenlik profesyonelleri ve mutlak dijital egemenlik gerektiren bireyler için tasarlanmış bir **kriptografik kale**dir.

### 🎯 Temel Felsefe

- **Sıfır Bilgi Mimarisi**: Ana şifreniz asla RAM'den çıkmaz. Verilerinize bizler dahil erişemeyiz.
- **Yerel Öncelik**: Bulut senkronizasyonu yok, telemetri yok, ağ bağlantısı yok.
- **Bellek Güvenliği**: Hassas veriler kullanımdan sonra anında silinir.
- **Açık Kaynak**: Her satır kod GitHub'da denetlenebilir.

### 🛡️ Stratejik Güvenlik Protokolleri

- **Askeri Sınıf Şifreleme**: AES-256 GCM / Fernet kimlik doğrulamalı şifreleme
- **Uyarlanabilir KDF**: PBKDF2-HMAC-SHA256 (150.000 iterasyon) + BCrypt (12 tur)
- **Hayalet Protokolü**: Statik analizi atlatmak için sistem dizinlerinde imza maskeleme
- **Gürültülü Silme**: Güvenli veri imhası için çok geçişli özyinelemeli sektör üzerine yazma
- **Otonom Kilitleme**: Hareketsizlik tabanlı bellek temizleme ve kasa kapatma
- **Pano Temizliği**: İşletim sistemi panosundan hassas verilerin otomatik arka plan temizliği

---

## ⚠️ Yasal Uyarı

> **ÖNEMLİ**: Bu uygulama "OLDUĞU GİBİ" garanti olmaksızın sunulmaktadır. Devlet düzeyinde, resmi onaylı veya askeri sertifikalı güvenlik taahhüdü VERMİYORUZ.

Bu yazılımı kullanarak:
1. **Veri güvenliğiniz** ve kasa yönetiminiz için tam sorumluluk kabul edersiniz.
2. **Yerel yasalara** (TCK, KVKK, BTK) uyumu kabul edersiniz.
3. **Kaybedilen ana şifrelerin geri döndürülemez veri kaybına yol açacağını** anlarsınız. Tasarım gereği kurtarma mekanizması yoktur.
4. **Yasal Uyumluluk**: Kullanıcılar, kullanımlarının tüm yerel ve uluslararası dijital gizlilik ve şifreleme yasalarına uygun olduğundan emin olmaktan sorumludur.
5. **Güvenlik Denetimi**: Üst düzey güvenlik için tasarlanmış olsa da, PassForge Pro sağlam operasyonel güvenlik (OpSec) uygulamalarıyla kullanılmalıdır (örn. maksimum koruma için hava boşluklu cihazlar).

Daha fazla bilgi için [Gizlilik ve Güvenlik Politikamızı](https://can-deliktas.github.io/PassForgePro/legal.html) inceleyin.

---

## ✨ Özellikler

| Özellik | Açıklama |
|---------|----------|
| 🔒 **AES-256 GCM Şifreleme** | Askeri standart kimlik doğrulamalı şifreleme |
| 🔑 **PBKDF2-HMAC-SHA256** | Anahtar türetme için 150.000+ iterasyon |
| 🧠 **Bellek Temizleme** | Kilitlenmede, çıkışta veya hareketsizlikte RAM temizlenir |
| 📋 **Pano Temizliği** | 10-60 saniye sonra otomatik temizleme |
| ⏱️ **Otomatik Kilitleme** | Yapılandırılabilir hareketsizlik zaman aşımı |
| 🎨 **7 Premium Tema** | Cyberpunk, Midnight, Neon ve daha fazlası |
| 📁 **Klasör Hiyerarşisi** | Sınırsız iç içe kategori |
| 🔄 **Çöp Kutusu Kurtarma** | Kalıcı silmeden önce 30 günlük geçici silme |
| 🎲 **Şifre Üreteci** | Kriptografik olarak güvenli rastgele şifreler |

---

## 📥 Kurulum ve Başlatma

### Ön Koşullar
- **Python 3.8+**
- **Windows 10/11**
- **Yönetici yetkileri**

### Adım 1: Depoyu Klonla
```bash
git clone https://github.com/can-deliktas/PassForgePro.git
cd PassForgePro
```

### Adım 2: Bağımlılıkları Kur
```bash
pip install -r requirements.txt
```

### Adım 3: Uygulamayı Başlat
```bash
python PassForgePro.py
```

---

## 🎯 Kullanım (GUI)

### İlk Çalıştırma
1. Uygulamayı başlatın
2. **Güçlü bir ana şifre** girin (minimum 8 karakter)
3. Kasa konumunu seçin veya oluşturun (`.db` dosyası)
4. Şifreli kasanıza erişin

### Önizleme Görselleri

<details>
<summary>🖼️ Ekran görüntülerini görüntülemek için tıklayın</summary>

- `önizleme-tr/giriş.png` - Kimlik Doğrulama Ekranı
- `önizleme-tr/aktif-kasa.png` - Aktif Kasa Görünümü
- `önizleme-tr/üretec.png` - Şifre Üreteci
- `önizleme-tr/ayarlar.png` - Ayarlar Paneli
- `önizleme-tr/geri-donusum.png` - Çöp Kutusu Yönetimi

</details>

---

## 🗂️ Proje Yapısı

```
PassforgeV2/
├── passforgepropy/          # Python Uygulaması
│   ├── PassForgePro.py      # Ana uygulama (GUI + Mantık)
│   ├── requirements.txt     # Python bağımlılıkları
│   ├── LICENSE              # GNU GPL-3.0
│   ├── README.md            # Bu dosya
│   └── .github/
│       └── ISSUE_TEMPLATE/
│           ├── bug_report.md
│           └── feature_request.md
|           └── hata-raporu.md
|           └── özellik-i̇steği.md
```

---

## 📝 Lisans ve Telif Hakkı

PassForge Pro, **GNU Genel Kamu Lisansı v3.0 (GPL-3.0)** altında lisanslanmıştır.

- ✅ Bu yazılımı kullanabilir, değiştirebilir ve dağıtabilirsiniz
- ✅ Orijinal telif hakkı bildirimini eklemelisiniz
- ✅ Türev çalışmalar için kaynak kodunu ifşa etmelisiniz
- ❌ Garanti verilmez

**© 2026 Can Arkadaş Deliktaş. Tüm Hakları Saklıdır.**

---

## 🤝 Nasıl Katkıda Bulunulur?

1. Depoyu **Fork** edin
2. Bir **özellik dalı** oluşturun: `git checkout -b feature/HarikaOzellik`
3. Değişikliklerinizi **commit** edin: `git commit -m 'HarikaOzellik Ekle'`
4. Dalı **push** edin: `git push origin feature/HarikaOzellik`
5. Bir **Pull Request** açın

### Sorun Bildirme
- [Hata Raporu Şablonunu](passforgepropy/.github/ISSUE_TEMPLATE/hata-raporu.md) kullanın
- [Özellik İsteği Şablonunu](passforgepropy/.github/ISSUE_TEMPLATE/özellik-i̇steği.md) kullanın

---

## 👨‍💻 Geliştirici Notları

### Güvenlik Mimarisi
- **Şifreleme**: `cryptography` kütüphanesi ile Fernet (AES-256-GCM)
- **KDF**: PBKDF2 ile HMAC-SHA256, 150k iterasyon, 16-byte salt
- **Bellek**: Şifreler için `bytearray`, açık sıfırlama
- **Veritabanı**: Şifrelenmiş BLOB depolama ile SQLite

### Kod Örnekleri
```python
# Anahtar Türetme
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=150000
)

# Bellek Temizleme
def secure_wipe(data: bytearray):
    for i in range(len(data)):
        data[i] = 0
```

### Teknoloji Yığını
- **Temeller**: Python, CustomTkinter, Cryptography.io
- **Katkılar**: Kriptografik entropiyi artıran, adli önlemleri geliştiren veya yerelleştirmeyi genişleten PR'ları memnuniyetle karşılıyoruz

---

<div align="center">

**Made with 🔐 by [Can Arkadaş Deliktaş](https://github.com/can-deliktas)**

*Forged in the fires of advanced cryptography. Your identity belongs to you.*

</div>

