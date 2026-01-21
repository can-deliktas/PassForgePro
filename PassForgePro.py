import customtkinter as ctk
from tkinter import messagebox, Toplevel, filedialog, simpledialog
import random
import string
import re
import math
import os
import sqlite3
import pyperclip
import bcrypt
import base64
import json
import webbrowser
import shutil
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ctypes
import sys

# --- THEME ENGINE ---

THEMES = {
    "Midnight": {"accent": "#5D3FD3", "hover": "#4832A8", "bg_dark": "#0D0D0D", "bg_card": "#181818"},
    "Forest": {"accent": "#2D6A4F", "hover": "#1B4332", "bg_dark": "#081C15", "bg_card": "#162E25"},
    "Crimson": {"accent": "#A4161A", "hover": "#660708", "bg_dark": "#0B090A", "bg_card": "#1C1112"},
    "Ocean": {"accent": "#0077B6", "hover": "#023E8A", "bg_dark": "#020412", "bg_card": "#0A1B2E"},
    "Cyberpunk": {"accent": "#F3E600", "hover": "#C2B800", "bg_dark": "#000000", "bg_card": "#1A1A1A"},
    "Nebula": {"accent": "#00F5FF", "hover": "#00C2CC", "bg_dark": "#0A0E21", "bg_card": "#1B132B"},
    "Ghost": {"accent": "#FFFFFF", "hover": "#CCCCCC", "bg_dark": "#050505", "bg_card": "#111111"}
}

# --- GLOBAL SETTINGS ---
VERSION = "PRO"
APP_NAME = f"PassForge {VERSION}"

# --- LOCALIZATION (TR/EN) ---

class L10N:
    STRINGS = {
        "en": {
            "title": "PassForge Pro - Ultimate Security",
            "setup_title": "Initialize New Vault",
            "login_title": "System Locked",
            "restore_title": "Link Existing Vault",
            "master_pw": "Master Password",
            "set_master_pw": "Set Master Password",
            "confirm_pw": "Confirm Master Password",
            "unlock": "UNLOCK ACCESS",
            "create_vault": "CREATE VAULT",
            "restore_vault": "RESTORE VAULT",
            "generator": "Generator",
            "vault": "Live Vault",
            "trash": "Recycle Bin",
            "settings": "Settings",
            "author": "Author",
            "gen_title": "Crypto-Analytics & Forge",
            "entropy": "Entropy",
            "crack_time": "Time to Crack",
            "length": "Length",
            "params": "Generation Parameters",
            "gen_btn": "FORGE SECURE STRING",
            "copy": "COPY",
            "save": "SAVE",
            "edit": "EDIT",
            "view": "VIEW",
            "delete": "DELETE",
            "restore": "RESTORE",
            "purge": "PURGE",
            "wipe": "FULL SYSTEM WIPE",
            "author_name": "Can Arkadaş Deliktaş",
            "placeholder_title": "Entry Title",
            "placeholder_url": "URL / Domain",
            "placeholder_user": "User Identity",
            "placeholder_desc": "Notes / Metadata",
            "save_btn": "ENCRYPT & PERSIST",
            "created": "Created",
            "strength": "Strength",
            "category": "Category",
            "select_cat": "Select Category",
            "theme": "Theme",
            "very_weak": "Very Weak",
            "weak": "Weak",
            "medium": "Medium",
            "strong": "Strong",
            "ultra": "Ultra Secure",
            "military": "Military Grade",
            "backup_btn": "CREATE INSTANT BACKUP",
            "choose_dir": "Choose Directory",
            "select_vault_folder": "Select folder containing vault files",
            "vault_linked": "Vault linked successfully!",
            "backup_success": "Backup saved successfully!",
            "back": "Go Back",
            "onboarding": "Welcome to PassForge Pro. Select how you want to proceed.",
            "link_existing": "Connect to a vault you've previously created.",
            "auto_lock": "Auto-Lock Timer",
            "clip_clear": "Clipboard Clear Timer",
            "seconds": "Seconds",
            "minutes": "Minutes",
            "hours": "Hours",
            "days": "Days",
            "years": "Years",
            "centuries": "Centuries",
            "instant": "Instant",
            "bits": "bits",
            "no_entries": "NO ENTRIES FOUND",
            "trash_empty": "RECYCLE BIN EMPTY",
            "error": "Error",
            "warning": "Warning",
            "access_denied": "Access Denied",
            "incorrect_pw": "Incorrect Security Credentials.",
            "wipe_confirm": "ERASE ALL LOCAL VAULT DATA?",
            "critical": "CRITICAL",
            "storage_path": "Storage Path",
            "none": "None",
            "vault_label": "VAULT",
            "exit": "EXIT",
            "opt_upper": "Upper (A-Z)",
            "opt_lower": "Lower (a-z)",
            "opt_digits": "Digits (0-9)",
            "opt_special": "Special (!#$)",
            "copied": "COPIED!",
            "err_folder_exists": "Category/Folder already exists here.",
            "err_rename": "Could not rename category.",
            "err_root_restrict": "Root categories cannot be modified or deleted.",
            "msg_title_required": "Identity title is required.",
            "msg_delete_confirm": "Delete folder and all sub-items?",
            "msg_pw_requirement": "Check storage and password (min 8 chars)."
        },
        "tr": {
            "title": "PassForge Pro - Ultra Güvenlik Paketi",
            "setup_title": "Yeni Kasa Oluştur",
            "login_title": "Sistem Kilitli",
            "restore_title": "Mevcut Kasayı Bağla",
            "master_pw": "Ana Şifre",
            "set_master_pw": "Ana Şifre Belirle",
            "confirm_pw": "Ana Şifreyi Onayla",
            "unlock": "ERİŞİMİ AÇ",
            "create_vault": "KASA OLUŞTUR",
            "restore_vault": "KASA GERİ YÜKLE",
            "generator": "Şifre Oluşturucu",
            "vault": "Aktif Kasa",
            "trash": "Geri Dönüşüm",
            "settings": "Ayarlar",
            "author": "Yapımcı",
            "gen_title": "Kripto-Analiz ve Üretim",
            "entropy": "Entropi",
            "crack_time": "Kırma Süresi",
            "length": "Uzunluk",
            "params": "Üretim Parametreleri",
            "gen_btn": "GÜVENLİ ŞİFRE ÜRET",
            "copy": "KOPYALA",
            "save": "KAYDET",
            "edit": "DÜZENLE",
            "view": "GÖRÜNTÜLE",
            "delete": "SİL",
            "restore": "GERİ YÜKLE",
            "purge": "TAMAMEN SİL",
            "wipe": "SİSTEMİ TAMAMEN SIFIRLA",
            "author_name": "Can Arkadaş Deliktaş",
            "placeholder_title": "Kayıt Başlığı",
            "placeholder_url": "URL / Alan Adı",
            "placeholder_user": "Kullanıcı Kimliği",
            "placeholder_desc": "Notlar / Meta Veri",
            "save_btn": "ŞİFRELE VE KAYDET",
            "created": "Oluşturulma",
            "strength": "Güç",
            "category": "Kategori",
            "select_cat": "Kategori Seç",
            "theme": "Tema",
            "very_weak": "Çok Zayıf",
            "weak": "Zayıf",
            "medium": "Orta",
            "strong": "Güçlü",
            "ultra": "Çok Güvenli",
            "military": "Askeri Düzey",
            "backup_btn": "ANLIK YEDEK OLUŞTUR",
            "choose_dir": "Klasör Seç",
            "select_vault_folder": "Kasa dosyalarının bulunduğu klasörü seçin",
            "vault_linked": "Kasa başarıyla bağlandı!",
            "backup_success": "Yedek başarıyla kaydedildi!",
            "back": "Geri Dön",
            "onboarding": "PassForge Pro'ya hoş geldiniz. Nasıl devam etmek istediğinizi seçin.",
            "start_fresh": "Tamamen yeni ve güvenli bir kasa deposu oluşturun.",
            "link_existing": "Daha önce oluşturduğunuz bir kasayı bağlayın.",
            "auto_lock": "Otomatik Kilitleme",
            "clip_clear": "Pano Temizleme",
            "seconds": "Saniye",
            "minutes": "Dakika",
            "hours": "Saat",
            "days": "Gün",
            "years": "Yıl",
            "centuries": "Asır",
            "instant": "Anlık",
            "bits": "bit",
            "no_entries": "KAYIT BULUNAMADI",
            "trash_empty": "GERİ DÖNÜŞÜM KUTUSU BOŞ",
            "error": "Hata",
            "warning": "Uyarı",
            "access_denied": "Erişim Engellendi",
            "incorrect_pw": "Geçersiz Güvenlik Kimlik Bilgileri.",
            "wipe_confirm": "TÜM YEREL KASA VERİLERİ SİLİNSİN Mİ?",
            "critical": "KRİTİK",
            "storage_path": "Depolama Yolu",
            "none": "Yok",
            "vault_label": "KASA",
            "opt_upper": "Büyük Harf (A-Z)",
            "opt_lower": "Küçük Harf (a-z)",
            "opt_digits": "Rakamlar (0-9)",
            "opt_special": "Semboller (!#$)",
            "copied": "KOPYALANDI!",
            "err_folder_exists": "Kategori/Klasör zaten mevcut.",
            "err_rename": "Kategori yeniden adlandırılamadı.",
            "err_root_restrict": "Kök kategoriler değiştirilemez veya silinemez.",
            "msg_title_required": "Kayıt başlığı gereklidir.",
            "msg_delete_confirm": "Klasör ve tüm alt öğeler silinsin mi?",
            "msg_pw_requirement": "Depolama yolunu ve şifreyi kontrol edin (en az 8 karakter)."
        }
    }

# --- CORE LOGIC & PATHS ---

class PathManager:
    POINTER_FILE = "vault_settings.json"

    @staticmethod
    def load_settings():
        if os.path.exists(PathManager.POINTER_FILE):
            with open(PathManager.POINTER_FILE, "r") as f: 
                d = json.load(f)
                if "auto_lock" not in d: d["auto_lock"] = 60 # Default 1 min
                if "clip_clear" not in d: d["clip_clear"] = 25 # Default 25s
                return d
        return {"path": None, "lang": "en", "theme": "Midnight", "auto_lock": 60, "clip_clear": 25}

    @staticmethod
    def save_settings(path=None, lang=None, theme=None, auto_lock=None, clip_clear=None):
        s = PathManager.load_settings()
        if path is not None: s["path"] = path
        if lang: s["lang"] = lang
        if theme: s["theme"] = theme
        if auto_lock is not None: s["auto_lock"] = auto_lock
        if clip_clear is not None: s["clip_clear"] = clip_clear
        with open(PathManager.POINTER_FILE, "w") as f: json.dump(s, f)

class AuthManager:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=150000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    @classmethod
    def setup(cls, password: str, folder_path: str, lang: str, theme: str):
        salt = os.urandom(16)
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        config_data = {"salt": base64.b64encode(salt).decode(), "hash": hashed_pw.decode(), "lang": lang, "theme": theme}
        config_path = os.path.join(folder_path, "config.bin")
        with open(config_path, "w") as f: json.dump(config_data, f)
        PathManager.save_settings(path=folder_path, lang=lang, theme=theme)
        return cls.derive_key(password, salt)

    @classmethod
    def authenticate(cls, password: str, folder_path: str):
        config_path = os.path.join(folder_path, "config.bin")
        if not os.path.exists(config_path): return None, False, {}
        with open(config_path, "r") as f: config = json.load(f)
        if bcrypt.checkpw(password.encode(), config["hash"].encode()):
            return cls.derive_key(password, base64.b64decode(config["salt"])), True, config
        return None, False, config

class EntropyEngine:
    @staticmethod
    def analyze(password: str, lang="en"):
        s = L10N.STRINGS.get(lang, L10N.STRINGS["en"])
        if not password: return 0, "---", "gray", s["instant"]
        chars = sum([26 if re.search(r"[a-z]", password) else 0,
                     26 if re.search(r"[A-Z]", password) else 0,
                     10 if re.search(r"\d", password) else 0,
                     32 if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) else 0])
        chars = max(chars, 1)
        entropy = len(password) * math.log2(chars)
        seconds = (chars ** len(password)) / (2 * 10**11)
        
        s = L10N.STRINGS.get(lang, L10N.STRINGS["en"])
        if entropy < 40: res, col = s["very_weak"], "#FF3B30"
        elif entropy < 60: res, col = s["weak"], "#FF9500"
        elif entropy < 85: res, col = s["medium"], "#FFCC00"
        elif entropy < 110: res, col = s["strong"], "#34C759"
        else: res, col = s["military"], "#007AFF"
        return entropy, res, col, EntropyEngine._format_time(seconds, lang)

    @staticmethod
    def _format_time(s, lang):
        st = L10N.STRINGS.get(lang, L10N.STRINGS["en"])
        if s < 1: return f"< 1 {st['seconds'].lower()}"
        if s > 31536000000: return f"> 100 {st['centuries'].lower()}"
        m = s / 60; h = m / 60; d = h / 24; y = d / 365
        if y >= 1: return f"~{int(y)} {st['years'].lower()}"
        if d >= 1: return f"~{int(d)} {st['days'].lower()}"
        if h >= 1: return f"~{int(h)} {st['hours'].lower()}"
        return f"~{int(m)} {st['minutes'].lower()}"

class VaultDB:
    def __init__(self, key: bytes, folder_path: str):
        self.fernet = Fernet(key)
        self.db_path = os.path.join(folder_path, "vault.db")
        conn = sqlite3.connect(self.db_path)
        conn.execute("""CREATE TABLE IF NOT EXISTS vault (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, url TEXT, username TEXT, 
                        description TEXT, encrypted_pass BLOB, strength_info TEXT, category TEXT, category_id INTEGER DEFAULT 0,
                        is_deleted INTEGER DEFAULT 0, created_at DATETIME DEFAULT (datetime('now', 'localtime')))""")
        try: conn.execute("ALTER TABLE vault ADD COLUMN category_id INTEGER DEFAULT 0")
        except: pass
        conn.execute("CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, parent_id INTEGER DEFAULT 0, UNIQUE(name, parent_id))")
        cursor = conn.execute("SELECT COUNT(*) FROM categories")
        if cursor.fetchone()[0] == 0:
            for c in ["Work", "Social", "Banka", "Personal"]:
                conn.execute("INSERT INTO categories (name, parent_id) VALUES (?, ?)", (c, 0))
        
        # Migration: Sync category_id for orphaned entries
        cats = conn.execute("SELECT id, name FROM categories WHERE parent_id=0").fetchall()
        for cid, cname in cats:
            conn.execute("UPDATE vault SET category_id=? WHERE category=? AND category_id=0", (cid, cname))
        
        conn.commit(); conn.close()

    def run(self, query, params=(), fetch=False):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(query, params)
        res = cursor.fetchall() if fetch else None
        conn.commit(); conn.close()
        return res

class StealthSystem:

    @staticmethod
    def is_windows():
        return os.name == "nt"

    @staticmethod
    def is_admin():
        if StealthSystem.is_windows():
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            return os.geteuid() == 0

    @staticmethod
    def elevate():
        if StealthSystem.is_windows():
            if not StealthSystem.is_admin():
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    sys.executable,
                    " ".join(sys.argv),
                    None,
                    1
                )
                sys.exit()
        else:
            if os.geteuid() != 0:
                print(f"sudo python3 {os.path.basename(sys.argv[0])}")
                sys.exit(1)

    @staticmethod
    def ghost_protocol():
        if not StealthSystem.is_admin():
            return

        if StealthSystem.is_windows():
            paths = [
                os.environ.get("TEMP"),
                os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Prefetch")
            ]
        else:
            paths = [
                "/tmp",
                "/var/tmp",
                os.path.expanduser("~/.cache"),
                os.path.expanduser("~/.local/share")
            ]

        exts = [".dat", ".cache", ".bin", ".tmp", ".sys"]

        for p in paths:
            if not p or not os.path.exists(p):
                continue
            try:
                for _ in range(6):
                    f = os.path.join(
                        p,
                        f"sys_cache_{random.randint(1000,9999)}_{random.choice(string.ascii_lowercase)}{random.choice(exts)}"
                    )
                    with open(f, "wb") as dummy:
                        dummy.write(os.urandom(random.randint(1024, 8192)))
            except:
                pass

    @staticmethod
    def secure_delete(path):
        if not os.path.exists(path):
            return
        try:
            size = os.path.getsize(path)
            with open(path, "wb") as f:
                f.write(os.urandom(size))
            os.remove(path)
        except:
            pass

    @staticmethod
    def restart_app():
        os.execl(sys.executable, sys.executable, *sys.argv)

# --- UI LAYER ---

class PassForgePro(ctk.CTk):
    def __init__(self):
        super().__init__()
        settings = PathManager.load_settings()
        self.lang = settings.get("lang", "en")
        self.theme_name = settings.get("theme", "Midnight")
        self.vault_path = settings.get("path")
        self.auto_lock_time = settings.get("auto_lock", 60)
        self.clip_clear_time = settings.get("clip_clear", 25)
        self.key, self.db = None, None
        self.wins = {}
        self.curr_cat, self.curr_cid = None, 0
        self.last_activity = datetime.now()
        
        self.title(self.tr("title"))
        self.geometry("1180x880")
        ctk.set_appearance_mode("dark")
        
        self.bind_all("<Any-KeyPress>", self._reset_activity)
        self.bind_all("<Any-ButtonPress>", self._reset_activity)
        self.after(5000, self._security_loop)
        
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(expand=True, fill="both")
        
        self.ui_header()
        self.init_startup()

    def ui_header(self):
        self.h_box = ctk.CTkFrame(self, fg_color="transparent", height=45)
        self.h_box.place(relx=0.98, rely=0.02, anchor="ne")
        self.lc = ctk.CTkSegmentedButton(self.h_box, values=["TR", "EN"], command=self.change_lang, width=80, height=32, selected_color=THEMES[self.theme_name]["accent"])
        self.lc.set(self.lang.upper()); self.lc.pack(side="right", padx=5)

    def _open_win(self, name, creator):
        if name in self.wins and self.wins[name].winfo_exists():
            self.wins[name].focus_force(); return
        self.wins[name] = creator()

    def tr(self, key): return L10N.STRINGS.get(self.lang, L10N.STRINGS["en"]).get(key, key)

    def change_lang(self, l):
        self.lang = l.lower(); PathManager.save_settings(lang=self.lang)
        if self.vault_path: PathManager.save_settings(lang=self.lang)
        self.refresh_ui()

    def change_theme(self, t):
        self.theme_name = t; PathManager.save_settings(theme=t)
        self.lc.configure(selected_color=THEMES[t]["accent"])
        self.refresh_ui()

    def refresh_ui(self):
        if self.db: self.show_dashboard()
        else: self.init_startup()

    def _reset_activity(self, e=None):
        self.last_activity = datetime.now()

    def _security_loop(self):
        if self.db and self.auto_lock_time > 0:
            if (datetime.now() - self.last_activity).total_seconds() > self.auto_lock_time:
                self.key, self.db = None, None
                for w in self.winfo_children():
                    if isinstance(w, Toplevel): w.destroy()
                self.refresh_ui()
        self.after(5000, self._security_loop)

    def _copy_with_clear(self, text):
        pyperclip.copy(text)
        if self.clip_clear_time > 0:
            self.after(self.clip_clear_time * 1000, lambda: pyperclip.copy("") if pyperclip.paste() == text else None)

    def _get_cat_paths(self):
        def build(p_id, path=""):
            res = []
            items = self.db.run(f"SELECT id, name FROM categories WHERE parent_id={p_id}", fetch=True)
            for cid, cname in items:
                curr = f"{path}/{cname}" if path else cname
                res.append((curr, cid))
                res.extend(build(cid, curr))
            return res
        return [("None", 0)] + build(0)

    def init_startup(self):
        for w in self.main_frame.winfo_children(): w.destroy()
        if self.vault_path:
            # Integrity Check
            if not os.path.exists(os.path.join(self.vault_path, "vault.db")):
                self.vault_path = None
                PathManager.save_settings(path="")
        
        if not self.vault_path: self.ui_onboarding()
        else: self.ui_login()

    def ui_onboarding(self):
        f = ctk.CTkFrame(self.main_frame, width=540, height=640, corner_radius=30, border_width=2, border_color=THEMES[self.theme_name]["accent"])
        f.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(f, text=f"💎 {APP_NAME}", font=ctk.CTkFont(size=32, weight="bold"), text_color=THEMES[self.theme_name]["accent"]).pack(pady=(60, 20))
        ctk.CTkLabel(f, text=self.tr("onboarding"), text_color="gray", font=ctk.CTkFont(size=14)).pack(pady=10)
        ctk.CTkButton(f, text=self.tr("create_vault"), command=self.show_setup_flow, width=380, height=70, fg_color=THEMES[self.theme_name]["accent"], hover_color=THEMES[self.theme_name]["hover"], font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(40, 10))
        def restore():
            folder = filedialog.askdirectory()
            if folder and os.path.exists(os.path.join(folder, "config.bin")): self.vault_path = folder; PathManager.save_settings(path=folder); self.ui_login()
        ctk.CTkButton(f, text=self.tr("restore_vault"), command=restore, width=380, height=70, fg_color="transparent", border_width=2, border_color=THEMES[self.theme_name]["accent"], font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(30, 10))

    def show_setup_flow(self):
        for w in self.main_frame.winfo_children(): w.destroy()
        f = ctk.CTkFrame(self.main_frame, width=540, height=720, corner_radius=30, border_width=2, border_color=THEMES[self.theme_name]["accent"])
        f.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkButton(f, text=f"← {self.tr('back')}", width=100, fg_color="transparent", command=self.ui_onboarding).pack(anchor="nw", padx=30, pady=30)
        ctk.CTkLabel(f, text=self.tr("setup_title"), font=ctk.CTkFont(size=24, weight="bold")).pack(pady=10)
        pw = ctk.CTkEntry(f, placeholder_text=self.tr("master_pw"), show="*", width=420, height=55, justify="center"); pw.pack(pady=10)
        cf = ctk.CTkEntry(f, placeholder_text=self.tr("confirm_pw"), show="*", width=420, height=55, justify="center"); cf.pack(pady=10)
        lbl = ctk.CTkLabel(f, text=f"{self.tr('storage_path')}: {self.tr('none')}", text_color="gray", font=ctk.CTkFont(size=12)); lbl.pack()
        self.tmp = ""
        def sel(): self.tmp = filedialog.askdirectory(); lbl.configure(text=self.tmp if self.tmp else self.tr("none"), text_color="#34C759" if self.tmp else "gray")
        ctk.CTkButton(f, text=self.tr("choose_dir"), command=sel, width=420, height=45, fg_color="#333").pack(pady=10)
        def finalize():
            if not self.tmp or pw.get() != cf.get() or len(pw.get()) < 8: return messagebox.showerror(self.tr("error"), self.tr("msg_pw_requirement"))
            self.key = AuthManager.setup(pw.get(), self.tmp, self.lang, self.theme_name); self.vault_path = self.tmp; self.db = VaultDB(self.key, self.vault_path); self.refresh_ui()
        ctk.CTkButton(f, text=self.tr("create_vault"), command=finalize, width=420, height=70, fg_color=THEMES[self.theme_name]["accent"]).pack(pady=40)

    def ui_login(self):
        for w in self.main_frame.winfo_children(): w.destroy()
        f = ctk.CTkFrame(self.main_frame, width=520, height=580, corner_radius=30, border_width=2, border_color=THEMES[self.theme_name]["accent"])
        f.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(f, text="🔒 " + self.tr("login_title"), font=ctk.CTkFont(size=30, weight="bold")).pack(pady=(60, 10))
        ctk.CTkLabel(f, text=f"{self.tr('vault_label')}: {os.path.basename(self.vault_path)}", font=ctk.CTkFont(size=12), text_color="gray70").pack(pady=(0, 45))
        e = ctk.CTkEntry(f, placeholder_text=self.tr("master_pw"), show="*", width=400, height=70, font=ctk.CTkFont(size=20), justify="center"); e.pack(pady=10); e.focus_set()
        def log():
            k, ok, cfg = AuthManager.authenticate(e.get(), self.vault_path)
            if ok: self.key, self.lang, self.theme_name = k, cfg["lang"], cfg.get("theme", self.theme_name); self.db = VaultDB(self.key, self.vault_path); self.refresh_ui()
            else: messagebox.showerror(self.tr("access_denied"), self.tr("incorrect_pw"))
        e.bind("<Return>", lambda x: log())
        ctk.CTkButton(f, text=self.tr("unlock"), command=log, width=400, height=75, font=ctk.CTkFont(size=20, weight="bold"), fg_color=THEMES[self.theme_name]["accent"]).pack(pady=25)
        ctk.CTkButton(f, text=f"← {self.tr('back')}", command=lambda: [PathManager.save_settings(path=""), self.init_startup()], fg_color="transparent", text_color="gray").pack()

    def show_dashboard(self):
        for w in self.main_frame.winfo_children(): w.destroy()
        s = ctk.CTkFrame(self.main_frame, width=300, corner_radius=0, fg_color=THEMES[self.theme_name]["bg_dark"])
        s.pack(side="left", fill="y")
        self.work = ctk.CTkFrame(self.main_frame, corner_radius=0, fg_color="transparent")
        self.work.pack(side="right", expand=True, fill="both", padx=35, pady=35)
        
        ctk.CTkLabel(s, text="PASSFORGE PRO", font=ctk.CTkFont(size=24, weight="bold"), text_color=THEMES[self.theme_name]["accent"]).pack(pady=50)
        self.nav = {}
        for k in ["generator", "vault", "trash", "settings"]:
            method_name = f"ui_{k}"
            btn = ctk.CTkButton(s, text=f"  {self.tr(k).upper()}", anchor="w", fg_color="transparent", height=55, font=ctk.CTkFont(size=14, weight="bold"), command=getattr(self, method_name))
            btn.pack(fill="x", padx=20, pady=8); self.nav[k] = btn
        
        ctk.CTkButton(s, text=f"  {self.tr('back').upper()} / {self.tr('exit').upper()}", anchor="w", fg_color="transparent", height=55, font=ctk.CTkFont(size=14, weight="bold"), text_color="#FF3B30", command=self.quit).pack(fill="x", padx=20, pady=8)

        ac = ctk.CTkFrame(s, fg_color=THEMES[self.theme_name]["bg_card"], corner_radius=20)
        ac.pack(side="bottom", fill="x", padx=20, pady=25)
        # Strictly language dependent label
        ctk.CTkLabel(ac, text=self.tr("author").upper(), font=ctk.CTkFont(size=10, weight="bold"), text_color="gray").pack(pady=(12, 0))
        ctk.CTkLabel(ac, text="Can Arkadaş Deliktaş", font=ctk.CTkFont(size=15, slant="italic"), cursor="hand2", text_color=THEMES[self.theme_name]["accent"]).pack(pady=(2, 18))
        ac.bind("<Button-1>", lambda e: webbrowser.open("https://can-deliktas.github.io/"))
        for w in ac.winfo_children(): w.bind("<Button-1>", lambda e: webbrowser.open("https://can-deliktas.github.io/"))
        
        self.ui_generator()

    def _nav(self, k):
        for nk, b in self.nav.items(): b.configure(fg_color=THEMES[self.theme_name]["accent"] if nk == k else "transparent")
        for w in self.work.winfo_children(): w.destroy()

    def ui_generator(self):
        self._nav("generator")
        ctk.CTkLabel(self.work, text=self.tr("gen_title"), font=ctk.CTkFont(size=32, weight="bold")).pack(anchor="w", pady=(0, 25))
        box = ctk.CTkFrame(self.work, corner_radius=30, border_width=1, border_color="#333", fg_color="#111")
        box.pack(fill="x", pady=15)
        self.ge = ctk.CTkEntry(box, font=ctk.CTkFont(family="Consolas", size=38), height=105, justify="center", fg_color="transparent", border_width=0)
        self.ge.pack(fill="x", padx=45, pady=(45, 10))
        
        sx = ctk.CTkFrame(box, fg_color="transparent"); sx.pack(fill="x", padx=60, pady=(0, 25))
        self.e_l = ctk.CTkLabel(sx, text=f"{self.tr('entropy')}: 0 {self.tr('bits')}", font=ctk.CTkFont(size=15)); self.e_l.pack(side="left")
        self.c_l = ctk.CTkLabel(sx, text=f"{self.tr('crack_time')}: ---", font=ctk.CTkFont(size=15, weight="bold")); self.c_l.pack(side="right")
        self.pb = ctk.CTkProgressBar(box, height=15, progress_color=THEMES[self.theme_name]["accent"]); self.pb.pack(fill="x", padx=55, pady=(0, 45)); self.pb.set(0)

        p = ctk.CTkFrame(self.work, corner_radius=30, fg_color=THEMES[self.theme_name]["bg_card"])
        p.pack(fill="both", expand=True, pady=15); p.grid_columnconfigure((0, 1), weight=1)
        
        self.l_l = ctk.CTkLabel(p, text=f"{self.tr('length')}: 16", font=ctk.CTkFont(weight="bold", size=16))
        self.l_l.grid(row=0, column=0, padx=60, pady=(40, 15), sticky="w")
        self.sl = ctk.CTkSlider(p, from_=8, to=128, command=lambda v: self.l_l.configure(text=f"{self.tr('length')}: {int(v)}"), button_color=THEMES[self.theme_name]["accent"])
        self.sl.set(16); self.sl.grid(row=0, column=1, padx=60, pady=(40, 15), sticky="ew")
        
        self.sws = []
        opts = [self.tr("opt_upper"), self.tr("opt_lower"), self.tr("opt_digits"), self.tr("opt_special")]
        for i, t in enumerate(opts):
            s = ctk.CTkSwitch(p, text=t, progress_color=THEMES[self.theme_name]["accent"], font=ctk.CTkFont(size=14))
            s.select(); s.grid(row=1+(i//2), column=i%2, padx=100, pady=25, sticky="w"); self.sws.append(s)

        def forge_string():
            chars = ""
            if self.sws[0].get(): chars += string.ascii_uppercase
            if self.sws[1].get(): chars += string.ascii_lowercase
            if self.sws[2].get(): chars += string.digits
            if self.sws[3].get(): chars += string.punctuation
            if not chars: return
            r = "".join(random.SystemRandom().choice(chars) for _ in range(int(self.sl.get())))
            self.ge.delete(0, "end"); self.ge.insert(0, r)
            e, l, col, t = EntropyEngine.analyze(r, self.lang)
            self.e_l.configure(text=f"{self.tr('entropy')}: {e:.1f} {self.tr('bits')} ({l})", text_color=col)
            self.c_l.configure(text=f"{self.tr('crack_time')}: {t}", text_color=col)
            self.pb.configure(progress_color=col); self.pb.set(min(e/128, 1.0))

        ctk.CTkButton(p, text=self.tr("gen_btn"), height=75, font=ctk.CTkFont(weight="bold", size=20), fg_color=THEMES[self.theme_name]["accent"], command=forge_string).grid(row=3, column=0, columnspan=2, padx=120, pady=45, sticky="ew")
        bx = ctk.CTkFrame(p, fg_color="transparent"); bx.grid(row=4, column=0, columnspan=2, pady=(0, 45))
        ctk.CTkButton(bx, text=self.tr("copy").upper(), width=180, height=55, fg_color="#1DB954", font=ctk.CTkFont(weight="bold"), command=lambda: self._copy_with_clear(self.ge.get())).pack(side="left", padx=15)
        ctk.CTkButton(bx, text=self.tr("save").upper(), width=180, height=55, fg_color="#007AFF", font=ctk.CTkFont(weight="bold"), command=lambda: self.save_modal(pwd=self.ge.get())).pack(side="left", padx=15)

    def ui_vault(self, cat=None, cid=0):
        self._nav("vault")
        self.curr_cat, self.curr_cid = cat, cid
        ctk.CTkLabel(self.work, text=self.tr("vault") + (f" - {cat}" if cat else ""), font=ctk.CTkFont(size=32, weight="bold")).pack(anchor="w", pady=(0, 25))
        
        filter_box = ctk.CTkFrame(self.work, height=45, fg_color="transparent")
        filter_box.pack(fill="x", pady=5)
        
        if cid != 0:
            def go_up():
                p_id = self.db.run(f"SELECT parent_id FROM categories WHERE id={cid}", fetch=True)[0][0]
                p_name = self.db.run(f"SELECT name FROM categories WHERE id={p_id}", fetch=True)[0][0] if p_id != 0 else None
                self.ui_vault(p_name, p_id)
            ctk.CTkButton(filter_box, text="↩", width=40, height=35, command=go_up).pack(side="left", padx=5)

        db_cats = self.db.run(f"SELECT id, name FROM categories WHERE parent_id={cid}", fetch=True)
        for sub_id, sub_name in db_cats:
            ctk.CTkButton(filter_box, text=f"📁 {sub_name.upper()}", width=100, height=35, fg_color="#222", command=lambda n=sub_name, i=sub_id: self.ui_vault(n, i)).pack(side="left", padx=5)

        def add_cat():
            name = simpledialog.askstring(self.tr("vault"), f"{self.tr('create_vault')} ('{cat or self.tr('none')}'):")
            if name: 
                try: 
                    self.db.run("INSERT INTO categories (name, parent_id) VALUES (?, ?)", (name, cid))
                    self.ui_vault(cat, cid)
                except: messagebox.showerror(self.tr("error"), self.tr("err_folder_exists"))
        
        ctk.CTkButton(filter_box, text="+", width=35, height=35, fg_color="#333", command=add_cat).pack(side="left", padx=10)
        
        if cat:
            # Check if this is a Root folder (parent_id=0)
            is_root = self.db.run(f"SELECT parent_id FROM categories WHERE id={cid}", fetch=True)[0][0] == 0
            
            def rename_cat():
                if is_root: return messagebox.showwarning("Restricted", "Root categories cannot be renamed.")
                new_name = simpledialog.askstring(self.tr("edit"), f"{self.tr('edit')} '{cat}':")
                if new_name:
                    try: 
                        self.db.run("UPDATE categories SET name=? WHERE id=?", (new_name, cid))
                        self.ui_vault(new_name, cid)
                    except: messagebox.showerror(self.tr("error"), self.tr("err_rename"))
            
            ctk.CTkButton(filter_box, text="✎", width=35, height=35, fg_color="#555", command=rename_cat).pack(side="left", padx=2)
            
            def del_cat():
                if is_root: return messagebox.showwarning(self.tr("warning"), self.tr("err_root_restrict"))
                if messagebox.askyesno(self.tr("delete"), self.tr("msg_delete_confirm")):
                    self.db.run("DELETE FROM categories WHERE id=?", (cid,))
                    self.ui_vault()
            ctk.CTkButton(filter_box, text="🗑", width=35, height=35, fg_color="#FF3B30", command=del_cat).pack(side="left", padx=2)

        sc = ctk.CTkScrollableFrame(self.work, corner_radius=25, fg_color="#121212", border_width=1, border_color="#222")
        sc.pack(fill="both", expand=True, pady=15)
        q = "SELECT * FROM vault WHERE is_deleted=0 AND category_id=? ORDER BY created_at DESC"
        items = self.db.run(q, (cid,), fetch=True)
        if not items: ctk.CTkLabel(sc, text=self.tr("no_entries"), font=ctk.CTkFont(slant="italic", size=18), text_color="gray").pack(pady=100)
        for r in items:
            c = ctk.CTkFrame(sc, fg_color="#1E1E1E", corner_radius=22, border_width=1, border_color="#333")
            c.pack(fill="x", pady=10, padx=20)
            
            # Pack action box FIRST on the right to ensure it's never pushed off
            bx = ctk.CTkFrame(c, fg_color="transparent"); bx.pack(side="right", padx=25)
            ctk.CTkButton(bx, text=self.tr("view"), width=90, height=40, font=ctk.CTkFont(weight="bold"), command=lambda d=r: self.view_pwd(d)).pack(side="left", padx=8)
            ctk.CTkButton(bx, text=self.tr("edit"), width=90, height=40, fg_color="#F5A623", font=ctk.CTkFont(weight="bold"), command=lambda d=r: self.save_modal(data=d)).pack(side="left", padx=8)
            ctk.CTkButton(bx, text=self.tr("delete"), width=90, height=40, fg_color="#FF3B30", font=ctk.CTkFont(weight="bold"), command=lambda i=r[0]: [self.db.run("UPDATE vault SET is_deleted=1 WHERE id=?", (i,)), self.ui_vault(cat, cid)]).pack(side="left", padx=8)
            
            ix = ctk.CTkFrame(c, fg_color="transparent"); ix.pack(side="left", fill="x", expand=True, padx=30, pady=25)
            ctk.CTkLabel(ix, text=r[1], font=ctk.CTkFont(size=20, weight="bold"), text_color=THEMES[self.theme_name]["accent"]).pack(anchor="w")
            ctk.CTkLabel(ix, text=f"{r[7]} | {r[3]} @ {r[2]}", font=ctk.CTkFont(size=14), text_color="gray70").pack(anchor="w")
            ctk.CTkLabel(ix, text=f"📅 {r[10][:16]}", font=ctk.CTkFont(size=12), text_color="gray50").pack(anchor="w")

    def save_modal(self, pwd=None, data=None):
        if "save" in self.wins and self.wins["save"].winfo_exists():
            return self.wins["save"].focus_force()
        w = Toplevel(self); self.wins["save"] = w
        w.title(self.tr("save")); w.geometry("580x820"); w.configure(bg="#0D0D0D"); w.attributes("-topmost", True)
        f = ctk.CTkFrame(w, corner_radius=35, fg_color="#181818", border_width=1, border_color=THEMES[self.theme_name]["accent"])
        f.pack(expand=True, fill="both", padx=25, pady=25)
        
        ctk.CTkLabel(f, text=self.tr("save" if not data else "edit").upper(), font=ctk.CTkFont(size=26, weight="bold"), text_color=THEMES[self.theme_name]["accent"]).pack(pady=35)
        entries = {}
        for k in ["title", "url", "username", "description"]:
            ctk.CTkLabel(f, text=self.tr(f"placeholder_{k}").upper(), font=ctk.CTkFont(size=11, weight="bold"), text_color="gray").pack(anchor="w", padx=55)
            e = ctk.CTkEntry(f, width=450, height=48, fg_color="#222"); e.pack(pady=(2, 15)); entries[k] = e
            if data: e.insert(0, data[1 if k=="title" else 2 if k=="url" else 3 if k=="username" else 4] or "")
        
        ctk.CTkLabel(f, text=self.tr("category").upper(), font=ctk.CTkFont(size=11, weight="bold"), text_color="gray").pack(anchor="w", padx=55)
        cat_data = self._get_cat_paths()
        cat_vals = [x[0] for x in cat_data]
        cat_opt = ctk.CTkOptionMenu(f, values=cat_vals, width=450, height=48, fg_color="#222", button_color=THEMES[self.theme_name]["accent"])
        cat_opt.pack(pady=(2, 15))
        if data: 
            # Find the path for the stored category_id
            target_id = data[8]
            found_path = "None"
            for p, i in cat_data:
                if i == target_id: found_path = p; break
            cat_opt.set(found_path)
        
        ctk.CTkLabel(f, text=self.tr("master_pw").upper(), font=ctk.CTkFont(size=11, weight="bold"), text_color="gray").pack(anchor="w", padx=55)
        pe = ctk.CTkEntry(f, width=450, height=52, font=ctk.CTkFont(family="Consolas", size=18), justify="center"); pe.pack(pady=(2, 25))
        pe.insert(0, self.db.fernet.decrypt(data[5]).decode() if data else (pwd or ""))
        
        def commit():
            if not entries["title"].get(): return messagebox.showwarning(self.tr("warning"), self.tr("msg_title_required"))
            ent, lvl, _, _ = EntropyEngine.analyze(pe.get(), self.lang)
            sel_path = cat_opt.get()
            sel_id = next((i for p, i in cat_data if p == sel_path), 0)
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            p = (entries["title"].get(), entries["url"].get(), entries["username"].get(), entries["description"].get(), self.db.fernet.encrypt(pe.get().encode()), f"{lvl} ({int(ent)} bits)", sel_path, sel_id, now)
            if not data: self.db.run("INSERT INTO vault (title, url, username, description, encrypted_pass, strength_info, category, category_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)", p)
            else: self.db.run("UPDATE vault SET title=?, url=?, username=?, description=?, encrypted_pass=?, strength_info=?, category=?, category_id=?, created_at=? WHERE id=?", p + (data[0],))
            w.destroy(); self.ui_vault(self.curr_cat, self.curr_cid)
            
        ctk.CTkButton(f, text=self.tr("save_btn"), height=65, font=ctk.CTkFont(weight="bold", size=18), fg_color=THEMES[self.theme_name]["accent"], command=commit).pack(pady=35, padx=65, fill="x")

    def view_pwd(self, r):
        if "view" in self.wins and self.wins["view"].winfo_exists():
            return self.wins["view"].focus_force()
        w = Toplevel(self); self.wins["view"] = w
        w.geometry("480x480"); w.configure(bg="#0F0F0F"); w.attributes("-topmost", True)
        dec = self.db.fernet.decrypt(r[5]).decode()
        ctk.CTkLabel(w, text=r[1], font=ctk.CTkFont(size=24, weight="bold"), text_color=THEMES[self.theme_name]["accent"]).pack(pady=(50, 10))
        ctk.CTkLabel(w, text=f"{self.tr('category')}: {r[7]}", text_color="gray70").pack()
        e = ctk.CTkEntry(w, width=380, height=70, font=ctk.CTkFont(family="Consolas", size=24), justify="center", fg_color="#222"); e.insert(0, dec); e.configure(state="readonly"); e.pack(pady=35)
        ctk.CTkButton(w, text=self.tr("copy"), fg_color="#1DB954", height=60, font=ctk.CTkFont(weight="bold", size=18), command=lambda: [self._copy_with_clear(dec), w.destroy()]).pack(pady=25)

    def ui_trash(self):
        self._nav("trash")
        ctk.CTkLabel(self.work, text=self.tr("trash"), font=ctk.CTkFont(size=32, weight="bold")).pack(anchor="w", pady=(0, 25))
        sc = ctk.CTkScrollableFrame(self.work, corner_radius=25, fg_color="#121212")
        sc.pack(fill="both", expand=True)
        items = self.db.run("SELECT * FROM vault WHERE is_deleted=1", fetch=True)
        if not items: ctk.CTkLabel(sc, text=self.tr("trash_empty"), font=ctk.CTkFont(slant="italic", size=18), text_color="gray").pack(pady=120)
        for r in items:
            c = ctk.CTkFrame(sc, fg_color="#222", corner_radius=18, height=90); c.pack(fill="x", pady=8, padx=20)
            ctk.CTkLabel(c, text=r[1], font=ctk.CTkFont(size=18, weight="bold")).pack(side="left", padx=35, pady=25)
            bx = ctk.CTkFrame(c, fg_color="transparent"); bx.pack(side="right", padx=25)
            ctk.CTkButton(bx, text=self.tr("restore"), width=110, height=45, command=lambda i=r[0]: [self.db.run("UPDATE vault SET is_deleted=0 WHERE id=?", (i,)), self.ui_trash()]).pack(side="left", padx=10)
            ctk.CTkButton(bx, text=self.tr("purge"), width=110, height=45, fg_color="#FF3B30", command=lambda i=r[0]: [self.db.run("DELETE FROM vault WHERE id=?", (i,)), self.ui_trash()]).pack(side="left", padx=10)

    def ui_settings(self):
        self._nav("settings")
        ctk.CTkLabel(self.work, text=self.tr("settings"), font=ctk.CTkFont(size=32, weight="bold")).pack(anchor="w", pady=(0, 25))
        box = ctk.CTkFrame(self.work, corner_radius=30, fg_color=THEMES[self.theme_name]["bg_card"], border_width=1, border_color="#333")
        box.pack(fill="x", pady=15)
        
        ctk.CTkLabel(box, text=self.tr("theme").upper(), font=ctk.CTkFont(weight="bold", size=14), text_color=THEMES[self.theme_name]["accent"]).pack(pady=(30, 10))
        tm = ctk.CTkSegmentedButton(box, values=list(THEMES.keys()), command=self.change_theme, selected_color=THEMES[self.theme_name]["accent"], height=38)
        tm.set(self.theme_name); tm.pack(pady=(0, 30), padx=80, fill="x")
        
        ctk.CTkButton(box, text=self.tr("backup_btn"), height=65, font=ctk.CTkFont(weight="bold"), command=lambda: messagebox.showinfo(self.tr("vault"), f"{self.tr('vault_label')}: {self.vault_path}")).pack(pady=15, padx=80, fill="x")

        # Security Timers
        sec_box = ctk.CTkFrame(self.work, corner_radius=30, fg_color=THEMES[self.theme_name]["bg_card"], border_width=1, border_color="#333")
        sec_box.pack(fill="x", pady=15)
        
        # Auto Lock Slider
        ctk.CTkLabel(sec_box, text=self.tr("auto_lock").upper(), font=ctk.CTkFont(weight="bold", size=14), text_color=THEMES[self.theme_name]["accent"]).pack(pady=(20, 5))
        def update_lock(v):
            self.auto_lock_time = int(v); lock_lbl.configure(text=f"{int(v//60)} {self.tr('minutes')} {int(v%60)} {self.tr('seconds')}"); PathManager.save_settings(auto_lock=self.auto_lock_time)
        ls = ctk.CTkSlider(sec_box, from_=30, to=1800, command=update_lock, button_color=THEMES[self.theme_name]["accent"])
        ls.set(self.auto_lock_time); ls.pack(fill="x", padx=100, pady=5)
        lock_lbl = ctk.CTkLabel(sec_box, text=f"{int(self.auto_lock_time//60)} {self.tr('minutes')} {int(self.auto_lock_time%60)} {self.tr('seconds')}", font=ctk.CTkFont(size=12)); lock_lbl.pack(pady=(0, 20))

        # Clipboard Clear Slider
        ctk.CTkLabel(sec_box, text=self.tr("clip_clear").upper(), font=ctk.CTkFont(weight="bold", size=14), text_color=THEMES[self.theme_name]["accent"]).pack(pady=(10, 5))
        def update_clip(v):
            self.clip_clear_time = int(v); clip_lbl.configure(text=f"{int(v)} {self.tr('seconds')}"); PathManager.save_settings(clip_clear=self.clip_clear_time)
        cs = ctk.CTkSlider(sec_box, from_=10, to=60, command=update_clip, button_color=THEMES[self.theme_name]["accent"])
        cs.set(self.clip_clear_time); cs.pack(fill="x", padx=100, pady=5)
        clip_lbl = ctk.CTkLabel(sec_box, text=f"{int(self.clip_clear_time)} {self.tr('seconds')}", font=ctk.CTkFont(size=12)); clip_lbl.pack(pady=(0, 25))

        def wipe():
            if messagebox.askyesno(self.tr("critical"), self.tr("wipe_confirm")):
                StealthSystem.secure_delete(os.path.join(self.vault_path, "config.bin"))
                StealthSystem.secure_delete(os.path.join(self.vault_path, "vault.db"))
                StealthSystem.secure_delete(PathManager.POINTER_FILE)
                StealthSystem.restart_app()
        ctk.CTkButton(box, text=self.tr("wipe"), fg_color="#FF3B30", height=65, font=ctk.CTkFont(weight="bold"), command=wipe).pack(pady=(15, 45), padx=80, fill="x")

if __name__ == "__main__":
    StealthSystem.elevate()
    StealthSystem.ghost_protocol()
    PassForgePro().mainloop()
