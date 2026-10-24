# -*- coding: utf-8 -*-
"""
SentinelONE - Dosya Şifreleme Aracı
AES-256-GCM + Scrypt, header HMAC (parola bağlı), keyfile desteği.
"""

import os
import sys
import struct
import secrets
import hashlib
import time
import threading
import platform
import atexit
import gc
import json
import hmac
import math
import string
import subprocess
from typing import Optional, Tuple, List, Dict, Any, Callable
from enum import IntEnum
from datetime import datetime
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False


# ==============================
# GÜVENLİK TARAMA
# ==============================
def is_root() -> bool:
    system = platform.system()
    if system in ("Linux", "Darwin"):
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False
    if system == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return False


def is_debugged() -> bool:
    """Linux/macOS'ta TracerPid, Windows'ta IsDebuggerPresent üzerinden tespit."""
    system = platform.system()
    if system in ("Linux", "Darwin"):
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        return int(line.split(":")[1].strip()) != 0
        except Exception:
            pass
        return False
    # [FIX #8] Windows debugger tespiti eklendi
    if system == "Windows":
        try:
            import ctypes
            return ctypes.windll.kernel32.IsDebuggerPresent() != 0
        except Exception:
            return False
    return False


def get_security_status() -> Dict[str, Any]:
    score = 100
    critical = []

    if is_root():
        score -= 50
        critical.append("Root/admin yetkileriyle çalışıyor")

    if is_debugged():
        score -= 40
        critical.append("Debugger tespit edildi")

    if sys.dont_write_bytecode:
        score += 10

    score = max(0, score)
    if score >= 90:
        level = "ÇOK GÜVENLİ"
    elif score >= 70:
        level = "GÜVENLİ"
    elif score >= 50:
        level = "ORTA RİSK"
    elif score >= 30:
        level = "YÜKSEK RİSK"
    else:
        level = "KRİTİK RİSK"

    return {
        "score": score,
        "level": level,
        "critical": critical,
        "is_secure": score >= 70,
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "python_version": sys.version.split()[0],
    }


class RestrictedSecurityMode:
    ACTIVE = False

    @classmethod
    def evaluate_and_activate(cls, status: Dict[str, Any]) -> bool:
        if status["score"] >= 70:
            return False
        # [FIX #8b] Tk oluşturmadan önce mainloop yoksa CLI'de sor; GUI'de GUI sorar
        # Bu fonksiyon artık sadece CLI için fallback; GUI tarafında ayrıca sorulur.
        if not GUI_AVAILABLE:
            print(f"Uyarı: Düşük güvenlik skoru ({status['score']}/100). Kısıtlı mod aktif.")
            cls.ACTIVE = True
            return True
        # GUI varsa sessizce kısıtlı modu aktive et; kullanıcıya GUI'de bilgi verilir.
        cls.ACTIVE = True
        return True


# ==============================
# HATA SINIFLARI
# ==============================
class SecurityError(Exception): pass
class EncryptionError(Exception): pass
class PasswordError(Exception): pass
class FileSizeError(Exception): pass
class HeaderIntegrityError(SecurityError): pass
class KeyfileRequiredError(SecurityError): pass


# ==============================
# GÜVENLİK SEVİYELERİ
# ==============================
class SecurityLevel(IntEnum):
    BASIC = 1
    COMMERCIAL = 2
    GOVERNMENT = 3
    FORTRESS = 4


@dataclass
class SecurityPreset:
    name: str
    description: str
    key_size: int
    kdf_iterations: int
    chunk_size: int
    max_file_size: int
    password_min_length: int
    password_entropy_min: int
    require_keyfile: bool = False
    min_character_sets: int = 3  # [FIX #7] preset'te tanımlı


SECURITY_PRESETS = {
    SecurityLevel.BASIC: SecurityPreset(
        name="Temel", description="Kişisel dosyalar için",
        key_size=32, kdf_iterations=2**14, chunk_size=1 * 1024 * 1024,
        max_file_size=1 * 1024**3, password_min_length=8,
        password_entropy_min=40, min_character_sets=2,
    ),
    SecurityLevel.COMMERCIAL: SecurityPreset(
        name="Profesyonel", description="İş belgeleri için",
        key_size=32, kdf_iterations=2**16, chunk_size=2 * 1024 * 1024,
        max_file_size=10 * 1024**3, password_min_length=12,
        password_entropy_min=60, min_character_sets=3,
    ),
    SecurityLevel.GOVERNMENT: SecurityPreset(
        name="Askeri Seviye", description="Gizli belgeler için",
        key_size=32, kdf_iterations=2**18, chunk_size=4 * 1024 * 1024,
        max_file_size=100 * 1024**3, password_min_length=16,
        password_entropy_min=80, require_keyfile=True, min_character_sets=4,
    ),
    SecurityLevel.FORTRESS: SecurityPreset(
        name="Kale Modu", description="Maksimum güvenlik",
        key_size=32, kdf_iterations=2**20, chunk_size=8 * 1024 * 1024,
        max_file_size=1 * 1024**4, password_min_length=24,
        password_entropy_min=120, require_keyfile=True, min_character_sets=5,
    ),
}
# [FIX #3] key_size 32'ye sabitlendi (AES-256). Ek güç için KDF iterasyonları zaten yüksek.
# Ayrıca master_key her zaman 32 byte AES anahtarıdır; 48/64/96 kullanılmıyordu.


# ==============================
# GÜVENLİ ŞİFRE ÜRETİCİ
# ==============================
class SecurePasswordGenerator:
    CHARSETS = {
        "lower": string.ascii_lowercase,
        "upper": string.ascii_uppercase,
        "digits": string.digits,
        "symbols": "!@#$%^&*()_+-=[]{}|;:,.<>?/",
        "extended": "~`\"'\\",
    }
    _rng = secrets.SystemRandom()

    # [FIX #7b] Kelime havuzu genişletildi (hatırlanabilir parola entropisi için)
    WORDLIST = [
        "kale", "güneş", "ayna", "deniz", "orman", "kitap", "kalem", "masa",
        "bilgisayar", "şifre", "güvenlik", "kod", "program", "veri", "bulut",
        "nehir", "dağ", "yıldız", "gece", "sabah", "rüzgar", "ateş", "toprak",
        "su", "hava", "altın", "gümüş", "demir", "bakır", "taş", "yol",
        "köprü", "kapı", "pencere", "çatı", "bahçe", "çiçek", "ağaç", "yaprak",
        "kuş", "balık", "aslan", "kaplan", "kartal", "şahin", "baykuş", "yunus",
        "mavi", "yeşil", "kırmızı", "sarı", "beyaz", "siyah", "mor", "turuncu",
        "bir", "iki", "üç", "dört", "beş", "altı", "yedi", "sekiz", "dokuz",
        "on", "yüz", "bin", "milyon", "sıfır", "sayı", "harf", "kelime",
        "dost", "arkadaş", "aile", "kardeş", "anne", "baba", "çocuk", "insan",
        "şehir", "köy", "ülke", "dünya", "evren", "güneş", "ay", "gezegen",
        "müzik", "şarkı", "dans", "resim", "heykel", "şiir", "roman", "hikaye",
    ]

    @staticmethod
    def generate_password(security_level: SecurityLevel, include_words: bool = False
                          ) -> Tuple[str, Dict[str, Any]]:
        preset = SECURITY_PRESETS[security_level]

        if security_level == SecurityLevel.BASIC:
            length = SecurePasswordGenerator._rng.randint(12, 16)
            keys = ["lower", "upper", "digits"]
        elif security_level == SecurityLevel.COMMERCIAL:
            length = SecurePasswordGenerator._rng.randint(16, 20)
            keys = ["lower", "upper", "digits", "symbols"]
        elif security_level == SecurityLevel.GOVERNMENT:
            length = SecurePasswordGenerator._rng.randint(20, 24)
            keys = ["lower", "upper", "digits", "symbols", "extended"]
        else:
            length = SecurePasswordGenerator._rng.randint(24, 32)
            keys = ["lower", "upper", "digits", "symbols", "extended"]

        if include_words and security_level in (SecurityLevel.BASIC, SecurityLevel.COMMERCIAL):
            password = SecurePasswordGenerator._generate_memorable_password(length)
        else:
            password = SecurePasswordGenerator._generate_random_password(length, keys)

        analysis = SecurePasswordGenerator.analyze_password(password)
        # [FIX #7c] Hatırlanabilir parolada gerçek kelime-havuzu entropisi de hesaba katılır
        if include_words:
            real_entropy = SecurePasswordGenerator._memorable_real_entropy(password)
            analysis["entropy_bits"] = min(analysis["entropy_bits"], real_entropy)
            analysis["real_entropy_bits"] = real_entropy
        if analysis["entropy_bits"] < preset.password_entropy_min:
            return SecurePasswordGenerator.generate_password(security_level, False)
        return password, analysis

    @staticmethod
    def _generate_random_password(length: int, charset_keys: List[str]) -> str:
        all_chars = "".join(SecurePasswordGenerator.CHARSETS[k] for k in charset_keys)
        rng = SecurePasswordGenerator._rng
        chars = [secrets.choice(SecurePasswordGenerator.CHARSETS[k]) for k in charset_keys]
        remaining = length - len(chars)
        chars.extend(rng.choice(all_chars) for _ in range(remaining))
        rng.shuffle(chars)
        return "".join(chars)

    @staticmethod
    def _generate_memorable_password(length: int) -> str:
        rng = SecurePasswordGenerator._rng
        parts, total = [], 0
        attempts = 0
        while total < length and attempts < 50:
            attempts += 1
            word = rng.choice(SecurePasswordGenerator.WORDLIST)
            r = rng.random()
            if r > 0.5:
                word = word.upper()
            elif r > 0.3:
                word = word.capitalize()
            parts.append(word)
            total += len(word)
            if rng.random() > 0.7 and total < length - 2:
                parts.append(rng.choice(SecurePasswordGenerator.CHARSETS["symbols"]))
                total += 1
        password = "".join(parts)
        return password[:length] if len(password) > length else password

    @staticmethod
    def _memorable_real_entropy(password: str) -> float:
        """Hatırlanabilir parola için kelime havuzu tabanlı gerçek entropi tahmini."""
        pool = len(SecurePasswordGenerator.WORDLIST)
        # Yaklaşık kelime sayısı: uzunluk / ortalama kelime uzunluğu (~5)
        approx_words = max(1, len(password) // 5)
        return approx_words * math.log2(pool)

    @staticmethod
    def analyze_password(password: str) -> Dict[str, Any]:
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in SecurePasswordGenerator.CHARSETS["symbols"] for c in password)
        has_extended = any(c in SecurePasswordGenerator.CHARSETS["extended"] for c in password)

        sets = sum([has_lower, has_upper, has_digit, has_symbol, has_extended])
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_symbol: charset_size += 32
        if has_extended: charset_size += 7

        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0.0
        if entropy >= 128:
            strength = "mükemmel"
        elif entropy >= 100:
            strength = "çok_güçlü"
        elif entropy >= 80:
            strength = "güçlü"
        elif entropy >= 60:
            strength = "orta"
        elif entropy >= 40:
            strength = "zayıf"
        else:
            strength = "çok_zayıf"

        return {
            "length": len(password),
            "has_lower": has_lower,
            "has_upper": has_upper,
            "has_digit": has_digit,
            "has_symbol": has_symbol,
            "has_extended": has_extended,
            "character_sets": sets,
            "entropy_bits": entropy,
            "strength": strength,
        }

    @staticmethod
    def save_password_to_desktop(password: str, filename: Optional[str] = None,
                                 metadata: Optional[Dict[str, Any]] = None) -> str:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        if not os.path.isdir(desktop):
            desktop = os.path.expanduser("~")
        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"SentinelONE_Password_{ts}.txt"
        filepath = os.path.join(desktop, filename)

        # [FIX #18] Çakışma varsa sonuna sayaç ekle
        if os.path.exists(filepath):
            base, ext = os.path.splitext(filepath)
            c = 1
            while os.path.exists(f"{base}_{c}{ext}"):
                c += 1
            filepath = f"{base}_{c}{ext}"

        analysis = SecurePasswordGenerator.analyze_password(password)
        content = (
            f"SentinelONE - Parola Kaydı\n{'=' * 50}\n\n"
            f"Oluşturulma: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Parola: {password}\n\n{'=' * 50}\n\n"
            f"Uzunluk: {len(password)} karakter\n"
            f"Entropi: {analysis['entropy_bits']:.1f} bit\n"
            f"Güç: {analysis['strength']}\n\n{'=' * 50}\n\n"
            f"UYARI: Bu dosya düz metindir. Güvenli bir yerde saklayın,\n"
            f"paylaşmayın, işiniz bitince güvenli şekilde silin.\n"
        )
        if metadata:
            content += "\nEk Bilgiler:\n"
            for k, v in metadata.items():
                content += f"  {k}: {v}\n"

        fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath


# ==============================
# GÜVENLİ BELLEK YÖNETİCİSİ
# ==============================
class SecureMemoryManager:
    def __init__(self):
        self._allocations: List[bytearray] = []
        # [FIX #10] id() bazlı set — O(1) lookup, içerik karşılaştırması yok
        self._allocation_ids: set = set()
        atexit.register(self.cleanup_all)

    def allocate(self, size: int) -> bytearray:
        data = bytearray(size)
        self._allocations.append(data)
        self._allocation_ids.add(id(data))
        return data

    def wipe(self, data: bytearray, method: str = "DOD3"):
        if not data:
            return
        rng = secrets.SystemRandom()
        n = len(data)
        if method == "ZERO":
            for i in range(n):
                data[i] = 0
        elif method == "DOD3":
            for i in range(n):
                data[i] = 0
            for i in range(n):
                data[i] = 0xFF
            for i in range(n):
                data[i] = rng.randrange(256)
            for i in range(n):
                data[i] = 0
        elif method == "RANDOM":
            for i in range(n):
                data[i] = rng.randrange(256)
        buf_id = id(data)
        if buf_id in self._allocation_ids:
            self._allocation_ids.discard(buf_id)
            try:
                self._allocations.remove(data)
            except ValueError:
                pass

    def cleanup_all(self):
        for buf in list(self._allocations):
            try:
                self.wipe(buf, "DOD3")
            except Exception:
                pass
        self._allocations.clear()
        self._allocation_ids.clear()
        gc.collect()


# ==============================
# ANA ŞİFRELEME MOTORU
# ==============================
class SentinelEngine:
    """
    Format:
      Header (1024 byte):
        [0:4]   magic "SNE1"
        [4]     version
        [5]     security_level
        [6:14]  timestamp (u64)
        [14:22] original_size (u64)
        [22:26] chunk_size (u32)
        [26:30] key_size (u32)
        [30:32] reserved
        [32:64] salt (32)
        [64:68] encrypted_master_key_len (u32)
        [68:68+len] encrypted_master_key (nonce+ct+tag)
        [..+32] header_hmac (parola türevli anahtar ile)
        [..+4]  metadata_len (u32)
        geri kalan: rastgele padding (HMAC kapsamaz, bilgi taşımaz)
    """
    VERSION = 1
    MAGIC = b"SNE1"
    HEADER_SIZE = 1024
    MAX_METADATA_LEN = 1024 * 1024  # [FIX #4] 1 MB üst sınır

    def __init__(self, security_level: SecurityLevel = SecurityLevel.COMMERCIAL):
        self.security_level = security_level
        self.preset = self._effective_preset(security_level)
        self.memory = SecureMemoryManager()

    def _effective_preset(self, level: SecurityLevel) -> SecurityPreset:
        p = SECURITY_PRESETS[level]
        if RestrictedSecurityMode.ACTIVE:
            return SecurityPreset(
                name=f"{p.name} (Kısıtlı)",
                description=f"{p.description} [Kısıtlı Mod]",
                key_size=p.key_size,
                kdf_iterations=p.kdf_iterations,
                chunk_size=min(p.chunk_size, 512 * 1024),
                max_file_size=min(p.max_file_size, 100 * 1024 * 1024),
                password_min_length=p.password_min_length,
                password_entropy_min=p.password_entropy_min,
                require_keyfile=p.require_keyfile,
                min_character_sets=p.min_character_sets,
            )
        return p

    def check_password_policy(self, password: str) -> Tuple[bool, Dict[str, Any]]:
        if not password:
            return False, {"error": "Parola boş olamaz", "checks_passed": [], "checks_failed": ["boş"]}
        analysis = SecurePasswordGenerator.analyze_password(password)
        passed, failed = [], []
        if len(password) >= self.preset.password_min_length:
            passed.append(f"uzunluk>={self.preset.password_min_length}")
        else:
            failed.append(f"uzunluk<{self.preset.password_min_length}")
        if analysis["entropy_bits"] >= self.preset.password_entropy_min:
            passed.append(f"entropi>={self.preset.password_entropy_min}")
        else:
            failed.append(f"entropi<{self.preset.password_entropy_min}")
        # [FIX #7d] Karakter seti eşiği preset'ten okunuyor
        if analysis["character_sets"] >= self.preset.min_character_sets:
            passed.append(f"karakter_seti>={self.preset.min_character_sets}")
        else:
            failed.append(f"karakter_seti<{self.preset.min_character_sets}")
        return len(failed) == 0, {
            "is_valid": len(failed) == 0,
            "checks_passed": passed,
            "checks_failed": failed,
            "analysis": analysis,
        }

    # ---------- KDF & HMAC ----------
    def _derive_material(self, password: str, keyfile_path: Optional[str], salt: bytes
                         ) -> Tuple[bytearray, bytearray, bytearray]:
        """
        Döner: (aes_key, hmac_key, key_material_bytes)
        aes_key = Scrypt(password+keyfile, salt)
        hmac_key = Scrypt(password+keyfile, salt + b"HMAC")
        """
        # [FIX #6] material bytearray olarak tutuluyor, sızıntı azaltıldı
        material = bytearray(password.encode("utf-8"))
        if keyfile_path:
            with open(keyfile_path, "rb") as f:
                kf = f.read()
            material += hashlib.sha256(kf).digest()
            ba = bytearray(kf)
            self.memory.wipe(ba, "ZERO")
            del kf, ba

        kdf = Scrypt(salt=salt, length=32, n=self.preset.kdf_iterations, r=8, p=1,
                     backend=default_backend())
        aes_raw = kdf.derive(bytes(material))

        kdf2 = Scrypt(salt=salt + b"HMAC", length=32, n=self.preset.kdf_iterations, r=8, p=1,
                      backend=default_backend())
        hmac_raw = kdf2.derive(bytes(material))

        aes_key = self.memory.allocate(32)
        aes_key[:] = aes_raw
        hmac_key = self.memory.allocate(32)
        hmac_key[:] = hmac_raw

        # geçici kopyaları temizle
        tmp = bytearray(aes_raw)
        self.memory.wipe(tmp, "ZERO")
        del aes_raw, tmp
        tmp = bytearray(hmac_raw)
        self.memory.wipe(tmp, "ZERO")
        del hmac_raw, tmp
        self.memory.wipe(material, "ZERO")
        # material zaten yönetici tarafından silindi; geri dönüş için boş bytearray
        return aes_key, hmac_key, bytearray()

    def _compute_header_hmac(self, hmac_key: bytearray, body: bytes) -> bytes:
        return hmac.new(bytes(hmac_key), body, hashlib.sha256).digest()

    # ---------- Header ----------
    def _create_header(self, salt: bytes, encrypted_master_key: bytes,
                       hmac_key: bytearray, file_size: int,
                       metadata_len: int) -> bytes:
        header = bytearray(self.HEADER_SIZE)
        header[0:4] = self.MAGIC
        header[4] = self.VERSION
        header[5] = self.security_level.value
        header[6:14] = struct.pack("<Q", int(time.time()))
        header[14:22] = struct.pack("<Q", file_size)
        header[22:26] = struct.pack("<I", self.preset.chunk_size)
        header[26:30] = struct.pack("<I", self.preset.key_size)
        header[32:64] = salt
        key_len = len(encrypted_master_key)
        header[64:68] = struct.pack("<I", key_len)
        header[68:68 + key_len] = encrypted_master_key
        offset = 68 + key_len

        header[offset:offset + 4] = struct.pack("<I", metadata_len)
        offset += 4

        body = bytes(header[:offset])
        digest = self._compute_header_hmac(hmac_key, body)
        header[offset:offset + 32] = digest
        offset += 32

        if offset < self.HEADER_SIZE:
            header[offset:self.HEADER_SIZE] = secrets.token_bytes(self.HEADER_SIZE - offset)
        return bytes(header)

    def _verify_header(self, header_data: bytes, hmac_key: bytearray) -> Dict[str, Any]:
        if len(header_data) < self.HEADER_SIZE:
            raise HeaderIntegrityError("Header eksik")
        if header_data[0:4] != self.MAGIC:
            raise HeaderIntegrityError("Geçersiz magic")
        version = header_data[4]
        if version != self.VERSION:
            raise HeaderIntegrityError(f"Desteklenmeyen sürüm: {version}")

        level_val = header_data[5]
        try:
            level = SecurityLevel(level_val)
        except ValueError:
            raise HeaderIntegrityError(f"Geçersiz güvenlik seviyesi: {level_val}")

        salt = header_data[32:64]
        key_len = struct.unpack("<I", header_data[64:68])[0]
        if key_len <= 0 or 68 + key_len + 36 > self.HEADER_SIZE:
            raise HeaderIntegrityError("Header boyutları bozuk")
        encrypted_master_key = header_data[68:68 + key_len]
        offset = 68 + key_len

        metadata_len = struct.unpack("<I", header_data[offset:offset + 4])[0]
        # [FIX #4] metadata_len üst sınırı
        if metadata_len > self.MAX_METADATA_LEN:
            raise HeaderIntegrityError(f"metadata_len çok büyük: {metadata_len}")
        offset += 4
        stored_hmac = header_data[offset:offset + 32]
        body = header_data[:offset]
        computed = self._compute_header_hmac(hmac_key, body)
        if not hmac.compare_digest(stored_hmac, computed):
            raise HeaderIntegrityError("Header HMAC doğrulanamadı")

        chunk_size = struct.unpack("<I", header_data[22:26])[0]
        file_size = struct.unpack("<Q", header_data[14:22])[0]

        return {
            "salt": salt,
            "level": level,
            "encrypted_master_key": encrypted_master_key,
            "metadata_len": metadata_len,
            "chunk_size": chunk_size,
            "original_size": file_size,
        }

    # ---------- AES-GCM yardımcıları ----------
    @staticmethod
    def _aesgcm(key: bytearray) -> AESGCM:
        return AESGCM(bytes(key[:32]))

    def _encrypt_metadata(self, metadata: Dict[str, Any], master_key: bytearray) -> bytes:
        plaintext = json.dumps(metadata, ensure_ascii=False).encode("utf-8")
        nonce = secrets.token_bytes(12)
        ct = self._aesgcm(master_key).encrypt(nonce, plaintext, b"METADATA")
        tmp = bytearray(plaintext)
        self.memory.wipe(tmp, "ZERO")
        del plaintext, tmp
        return nonce + ct

    def _decrypt_metadata(self, blob: bytes, master_key: bytearray) -> Dict[str, Any]:
        if len(blob) < 12 + 16:
            raise SecurityError("Metadata blob çok kısa")
        nonce, ct = blob[:12], blob[12:]
        try:
            plaintext = self._aesgcm(master_key).decrypt(nonce, ct, b"METADATA")
        except InvalidTag:
            raise SecurityError("Metadata doğrulanamadı")
        try:
            result = json.loads(plaintext.decode("utf-8"))
        finally:
            tmp = bytearray(plaintext)
            self.memory.wipe(tmp, "ZERO")
            del plaintext, tmp
        return result

    def _encrypt_master_key(self, master_key: bytes, aes_key: bytearray) -> bytes:
        nonce = secrets.token_bytes(12)
        ct = self._aesgcm(aes_key).encrypt(nonce, master_key, b"MASTER_KEY")
        return nonce + ct

    def _decrypt_master_key(self, blob: bytes, aes_key: bytearray) -> bytearray:
        if len(blob) < 12 + 16:
            raise SecurityError("Şifreli anahtar blob çok kısa")
        nonce, ct = blob[:12], blob[12:]
        try:
            plaintext = self._aesgcm(aes_key).decrypt(nonce, ct, b"MASTER_KEY")
        except InvalidTag:
            raise SecurityError("Master key doğrulanamadı (parola/keyfile hatalı)")
        buf = self.memory.allocate(len(plaintext))
        buf[:] = plaintext
        tmp = bytearray(plaintext)
        self.memory.wipe(tmp, "ZERO")
        del plaintext, tmp
        return buf

    def _encrypt_chunk(self, chunk: bytes, master_key: bytearray, index: int) -> bytes:
        nonce = struct.pack(">Q", index) + secrets.token_bytes(4)
        return nonce + self._aesgcm(master_key).encrypt(nonce, chunk, b"CHUNK")

    def _decrypt_chunk(self, blob: bytes, master_key: bytearray, index: int,
                       chunk_size: int) -> bytes:
        if len(blob) < 12 + 16:
            raise SecurityError(f"Chunk {index} çok kısa")
        nonce, ct = blob[:12], blob[12:]
        if nonce[:8] != struct.pack(">Q", index):
            raise SecurityError(f"Chunk {index} nonce sırası bozuk")
        if len(ct) > chunk_size + 16:
            raise SecurityError(f"Chunk {index} boyutu anormal")
        try:
            return self._aesgcm(master_key).decrypt(nonce, ct, b"CHUNK")
        except InvalidTag:
            raise SecurityError(f"Chunk {index} doğrulanamadı")

    def _cleanup(self, *items):
        for item in items:
            if isinstance(item, bytearray):
                self.memory.wipe(item, "DOD3")

    # ---------- Encrypt ----------
    def encrypt_file(self, input_path: str, output_path: str, password: str,
                     keyfile_path: Optional[str] = None,
                     progress_callback: Optional[Callable[[int, int, str], None]] = None
                     ) -> Dict[str, Any]:
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Dosya bulunamadı: {input_path}")
        file_size = os.path.getsize(input_path)
        if file_size == 0:
            raise ValueError("Boş dosya şifrelenemez")
        if RestrictedSecurityMode.ACTIVE and file_size > 100 * 1024 * 1024:
            raise FileSizeError("Kısıtlı modda maksimum 100MB")
        if file_size > self.preset.max_file_size:
            raise FileSizeError(f"Dosya çok büyük: {file_size} > {self.preset.max_file_size}")
        if self.preset.require_keyfile and (not keyfile_path or not os.path.exists(keyfile_path)):
            raise KeyfileRequiredError(
                f"{self.preset.name} seviyesi için geçerli bir keyfile zorunludur."
            )
        # [FIX #19] Çıktı dosyası zaten varsa üzerine yazma
        if os.path.exists(output_path):
            raise EncryptionError(f"Çıktı dosyası zaten var: {output_path}")

        valid, policy = self.check_password_policy(password)
        if not valid:
            raise PasswordError(f"Parola yetersiz: {policy['checks_failed']}")

        if progress_callback:
            progress_callback(0, 100, "Başlatılıyor...")

        # [FIX #1] finally'de NameError olmaması için baştan tanımla
        aes_key: Optional[bytearray] = None
        hmac_key: Optional[bytearray] = None
        master_key: Optional[bytearray] = None

        salt = secrets.token_bytes(32)
        if progress_callback:
            progress_callback(3, 100, "Anahtar türetiliyor...")

        try:
            aes_key, hmac_key, _ = self._derive_material(password, keyfile_path, salt)

            master_key = self.memory.allocate(32)  # [FIX #3] AES-256 anahtarı
            master_key[:] = secrets.token_bytes(32)
            encrypted_master_key = self._encrypt_master_key(bytes(master_key), aes_key)

            metadata = {
                "original_name": os.path.basename(input_path),
                "original_size": file_size,
                "created": datetime.now().isoformat(),
                "security_level": self.preset.name,
            }
            meta_blob = self._encrypt_metadata(metadata, master_key)

            header = self._create_header(salt, encrypted_master_key, hmac_key,
                                         file_size, len(meta_blob))

            with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
                fout.write(header)
                fout.write(meta_blob)

                index = 0
                total_read = 0
                while True:
                    if progress_callback:
                        pct = int((total_read / file_size) * 92) + 5
                        progress_callback(pct, 100, f"Şifreleniyor... parça {index}")
                    chunk = fin.read(self.preset.chunk_size)
                    if not chunk:
                        break
                    blob = self._encrypt_chunk(chunk, master_key, index)
                    fout.write(struct.pack("<I", len(blob)))
                    fout.write(blob)
                    total_read += len(chunk)
                    index += 1

            # [FIX #2] Yazılan toplam boyut orijinalle eşleşmeli
            if total_read != file_size:
                raise EncryptionError(
                    f"Şifreleme tutarsız: okunan {total_read} != orijinal {file_size}"
                )

            result = {
                "original_file": input_path,
                "encrypted_file": output_path,
                "original_size": file_size,
                "encrypted_size": os.path.getsize(output_path),
                "chunks": index,
                "security_level": self.preset.name,
                "timestamp": datetime.now().isoformat(),
                "password_strength": policy["analysis"]["strength"],
            }
            if progress_callback:
                progress_callback(100, 100, "Şifreleme tamamlandı")
            return result
        except Exception as e:
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except Exception:
                    pass
            if isinstance(e, (EncryptionError, FileSizeError, PasswordError,
                              KeyfileRequiredError, FileNotFoundError, ValueError)):
                raise
            raise EncryptionError(f"Şifreleme başarısız: {e}")
        finally:
            self._cleanup(master_key, aes_key, hmac_key)

    # ---------- Decrypt ----------
    def decrypt_file(self, input_path: str, output_path: str, password: str,
                     keyfile_path: Optional[str] = None,
                     progress_callback: Optional[Callable[[int, int, str], None]] = None
                     ) -> Dict[str, Any]:
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Dosya bulunamadı: {input_path}")
        file_size = os.path.getsize(input_path)
        if file_size < self.HEADER_SIZE:
            raise ValueError("Geçersiz dosya boyutu")
        # [FIX #19b] Çıktı çakışma kontrolü
        if os.path.exists(output_path):
            raise EncryptionError(f"Çıktı dosyası zaten var: {output_path}")

        if progress_callback:
            progress_callback(0, 100, "Başlatılıyor...")

        aes_key = hmac_key = master_key = None
        try:
            with open(input_path, "rb") as fin:
                header_data = fin.read(self.HEADER_SIZE)

                level_val = header_data[5]
                try:
                    file_level = SecurityLevel(level_val)
                except ValueError:
                    raise HeaderIntegrityError(f"Geçersiz güvenlik seviyesi: {level_val}")
                self.security_level = file_level
                self.preset = self._effective_preset(file_level)

                if self.preset.require_keyfile and (not keyfile_path or not os.path.exists(keyfile_path)):
                    raise KeyfileRequiredError(
                        f"Bu dosya {self.preset.name} ile şifrelenmiş; keyfile zorunlu."
                    )

                salt = header_data[32:64]
                if progress_callback:
                    progress_callback(5, 100, "Anahtar türetiliyor...")

                aes_key, hmac_key, _ = self._derive_material(password, keyfile_path, salt)

                info = self._verify_header(header_data, hmac_key)
                chunk_size = info["chunk_size"]
                if chunk_size <= 0 or chunk_size > 64 * 1024 * 1024:
                    raise HeaderIntegrityError("Geçersiz chunk_size")

                master_key = self._decrypt_master_key(info["encrypted_master_key"], aes_key)

                meta_blob = fin.read(info["metadata_len"])
                if len(meta_blob) != info["metadata_len"]:
                    raise SecurityError("Metadata eksik")
                metadata = self._decrypt_metadata(meta_blob, master_key)

                orig_size = metadata.get("original_size", 0)
                # [FIX #5] Header'daki file_size ile metadata'daki original_size tutarlı olmalı
                if info["original_size"] != orig_size:
                    raise HeaderIntegrityError(
                        f"Boyut tutarsızlığı: header={info['original_size']} meta={orig_size}"
                    )
                if RestrictedSecurityMode.ACTIVE and orig_size > 100 * 1024 * 1024:
                    raise FileSizeError("Kısıtlı modda maksimum 100MB")

                with open(output_path, "wb") as fout:
                    index = 0
                    total_written = 0
                    while True:
                        len_bytes = fin.read(4)
                        if len(len_bytes) < 4:
                            break
                        blob_len = struct.unpack("<I", len_bytes)[0]
                        if blob_len <= 0 or blob_len > chunk_size + 64:
                            raise SecurityError(f"Chunk {index} boyutu anormal")
                        blob = fin.read(blob_len)
                        if len(blob) != blob_len:
                            raise SecurityError(f"Chunk {index} eksik")
                        plaintext = self._decrypt_chunk(blob, master_key, index, chunk_size)
                        fout.write(plaintext)
                        total_written += len(plaintext)
                        tmp = bytearray(plaintext)
                        self.memory.wipe(tmp, "ZERO")
                        del plaintext, tmp

                        if progress_callback:
                            pct = 10 + int((fin.tell() / file_size) * 85)
                            progress_callback(min(pct, 99), 100,
                                              f"Deşifre ediliyor... parça {index}")
                        index += 1

                # [FIX #2b] Truncation tespiti: yazılan bayt sayısı metadata ile eşleşmeli
                if total_written != orig_size:
                    raise SecurityError(
                        f"Truncation tespit edildi: yazılan {total_written} != beklenen {orig_size}"
                    )

            result = {
                "decrypted_file": output_path,
                "bytes_written": total_written,
                "chunks_processed": index,
                "metadata": metadata,
                "timestamp": datetime.now().isoformat(),
            }
            if progress_callback:
                progress_callback(100, 100, "Deşifreleme tamamlandı")
            return result
        except Exception as e:
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except Exception:
                    pass
            if isinstance(e, (SecurityError, FileSizeError, KeyfileRequiredError,
                              FileNotFoundError, ValueError)):
                raise
            raise EncryptionError(f"Deşifreleme başarısız: {e}")
        finally:
            self._cleanup(master_key, aes_key, hmac_key)


# ==============================
# GUI
# ==============================
class SentinelGUI:
    def __init__(self, root, security_status: Dict[str, Any]):
        self.root = root
        self.security_status = security_status
        self.root.title("SentinelONE")
        self.root.geometry("980x740")
        self.root.minsize(900, 640)

        self.security_level = SecurityLevel.COMMERCIAL
        self.engine = SentinelEngine(self.security_level)

        self.current_file: Optional[str] = None
        self.file_type = "none"
        self.keyfile_path: Optional[str] = None
        self.is_processing = False

        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        atexit.register(self.cleanup)

    def setup_ui(self):
        main = ttk.Frame(self.root, padding="10")
        main.pack(fill=tk.BOTH, expand=True)
        self._build_status(main)
        self._build_header(main)
        self._build_body(main)
        self._build_footer(main)

    def _build_status(self, parent):
        score = self.security_status["score"]
        level = self.security_status["level"]
        color = "#27AE60" if score >= 70 else "#F39C12" if score >= 50 else "#E74C3C"

        frame = ttk.LabelFrame(parent, text="Güvenlik Durumu", padding="8")
        frame.pack(fill=tk.X, pady=(0, 8))

        canvas = tk.Canvas(frame, height=26, bg="white", highlightthickness=0)
        canvas.pack(fill=tk.X, pady=4)
        bw = 300
        fw = (score / 100) * bw
        canvas.create_rectangle(10, 8, 10 + bw, 22, outline="#BDC3C7", width=2)
        canvas.create_rectangle(10, 8, 10 + fw, 22, fill=color, outline="")
        canvas.create_text(10 + bw + 15, 15, text=f"{score}/100 - {level}",
                           font=("Arial", 10, "bold"), fill=color, anchor="w")

        info = ttk.Frame(frame)
        info.pack(fill=tk.X, pady=3)
        ttk.Label(info, text=f"Root: {'VAR' if is_root() else 'YOK'}", width=14).pack(side=tk.LEFT, padx=4)
        ttk.Label(info, text=f"Debugger: {'VAR' if is_debugged() else 'YOK'}", width=18).pack(side=tk.LEFT, padx=4)

        if RestrictedSecurityMode.ACTIVE:
            tk.Label(frame, text="KISITLI MOD AKTİF - Maksimum 100MB",
                     font=("Arial", 10, "bold"), fg="#E74C3C",
                     bg="#FDEDEC", padx=10, pady=4).pack(fill=tk.X, pady=3)

    def _build_header(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, pady=(0, 8))
        tk.Label(top, text="SentinelONE", font=("Arial", 18, "bold"),
                 fg="#2C3E50").pack(side=tk.LEFT)

        right = ttk.Frame(top)
        right.pack(side=tk.RIGHT)
        ttk.Label(right, text="Güvenlik:").pack(side=tk.LEFT, padx=(0, 4))
        self.level_var = tk.StringVar(value=SECURITY_PRESETS[self.security_level].name)
        combo = ttk.Combobox(right, textvariable=self.level_var,
                             values=[p.name for p in SECURITY_PRESETS.values()],
                             state="readonly", width=16)
        combo.pack(side=tk.LEFT)
        combo.bind("<<ComboboxSelected>>", self.on_level_changed)

    def _build_body(self, parent):
        mid = ttk.Frame(parent)
        mid.pack(fill=tk.BOTH, expand=True, pady=6)

        left = ttk.LabelFrame(mid, text="Dosya İşlemleri", padding="12")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        self.file_button = tk.Button(left, text="Dosya Seç", command=self.select_file,
                                     font=("Arial", 11), bg="#3498DB", fg="white", height=2)
        self.file_button.pack(fill=tk.X)

        self.file_label = tk.Label(left, text="Henüz dosya seçilmedi",
                                   font=("Arial", 9), fg="#2C3E50",
                                   wraplength=300, justify=tk.LEFT)
        self.file_label.pack(fill=tk.X, pady=6)

        kf = ttk.Frame(left)
        kf.pack(fill=tk.X, pady=4)
        ttk.Button(kf, text="Keyfile Seç", command=self.select_keyfile, width=12).pack(side=tk.LEFT)
        self.keyfile_label = tk.Label(kf, text="Keyfile yok", font=("Arial", 8))
        self.keyfile_label.pack(side=tk.LEFT, padx=6)

        actions = ttk.Frame(left)
        actions.pack(fill=tk.X, pady=10)
        self.encrypt_btn = tk.Button(actions, text="DOSYAYI ŞİFRELE",
                                     command=self.encrypt_action,
                                     font=("Arial", 11, "bold"),
                                     bg="#27AE60", fg="white", height=2, state="disabled")
        self.encrypt_btn.pack(fill=tk.X, pady=(0, 4))
        self.decrypt_btn = tk.Button(actions, text="ŞİFREYİ ÇÖZ",
                                     command=self.decrypt_action,
                                     font=("Arial", 11, "bold"),
                                     bg="#F39C12", fg="white", height=2, state="disabled")
        self.decrypt_btn.pack(fill=tk.X)

        right = ttk.LabelFrame(mid, text="Şifre Üretici", padding="12")
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        ttk.Label(right, text="Güvenlik Seviyesi:").pack(anchor=tk.W)
        self.pass_level_var = tk.IntVar(value=self.security_level.value)
        for lvl in SecurityLevel:
            ttk.Radiobutton(right, text=SECURITY_PRESETS[lvl].name,
                            value=lvl.value, variable=self.pass_level_var
                            ).pack(anchor=tk.W, pady=1)

        self.memorable_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text="Hatırlanabilir şifre",
                        variable=self.memorable_var).pack(anchor=tk.W, pady=8)
        ttk.Button(right, text="Şifre Üret", command=self.generate_password
                   ).pack(fill=tk.X, pady=4)
        self.generated_pass_var = tk.StringVar()
        ttk.Entry(right, textvariable=self.generated_pass_var,
                  font=("Consolas", 10), state="readonly").pack(fill=tk.X, pady=4)
        self.pass_info_label = tk.Label(right, text="", font=("Arial", 9),
                                        justify=tk.LEFT, wraplength=250)
        self.pass_info_label.pack(fill=tk.X, pady=4)
        ttk.Button(right, text="Masaüstüne Kaydet",
                   command=self.save_password_to_desktop).pack(fill=tk.X, pady=4)

    def _build_footer(self, parent):
        bot = ttk.Frame(parent)
        bot.pack(fill=tk.BOTH, expand=False, pady=(8, 0))

        pf = ttk.Frame(bot)
        pf.pack(fill=tk.X, pady=(0, 8))
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(pf, variable=self.progress_var, maximum=100
                        ).pack(fill=tk.X, side=tk.LEFT, expand=True)
        self.progress_label = tk.Label(pf, text="%0", width=5)
        self.progress_label.pack(side=tk.RIGHT, padx=(5, 0))

        self.status_var = tk.StringVar(value="Hazır")
        tk.Label(bot, textvariable=self.status_var, font=("Arial", 10),
                 fg="#2C3E50").pack(fill=tk.X, pady=(0, 8))

        lf = ttk.LabelFrame(bot, text="İşlem Logu", padding="8")
        lf.pack(fill=tk.BOTH, expand=True)
        self.log_text = scrolledtext.ScrolledText(lf, height=8, font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        ttk.Button(lf, text="Temizle", command=self.clear_log, width=12
                   ).pack(anchor=tk.SE, pady=(4, 0))

    # ---------- Events ----------
    def on_level_changed(self, event=None):
        name = self.level_var.get()
        for lvl, p in SECURITY_PRESETS.items():
            if p.name == name:
                self.security_level = lvl
                old = self.engine
                self.engine = SentinelEngine(lvl)
                old.memory.cleanup_all()
                self.log(f"Güvenlik seviyesi: {p.name}")
                if p.require_keyfile:
                    self.log("Bu seviye keyfile zorunlu kılar")
                break

    def select_file(self):
        path = filedialog.askopenfilename(title="Dosya seçin")
        if not path:
            return
        size = os.path.getsize(path)
        if RestrictedSecurityMode.ACTIVE and size > 100 * 1024 * 1024:
            messagebox.showerror("Hata", "Kısıtlı modda maksimum 100MB")
            return
        self.current_file = path
        base = os.path.basename(path)
        mb = size / (1024 * 1024)

        # [FIX #9] Magic byte kontrolü ile tip belirleme (uzantıya güvenme)
        is_encrypted = False
        try:
            with open(path, "rb") as f:
                head = f.read(4)
            is_encrypted = (head == SentinelEngine.MAGIC)
        except Exception:
            is_encrypted = path.lower().endswith(".sne1")

        if is_encrypted:
            self.file_type = "encrypted"
            self.file_label.config(text=f"Şifreli dosya: {base}\nBoyut: {mb:.2f} MB",
                                   fg="#F39C12")
            self.encrypt_btn.config(state="disabled")
            self.decrypt_btn.config(state="normal")
        else:
            self.file_type = "normal"
            self.file_label.config(text=f"Normal dosya: {base}\nBoyut: {mb:.2f} MB",
                                   fg="#3498DB")
            self.encrypt_btn.config(state="normal")
            self.decrypt_btn.config(state="disabled")
        self.log(f"Dosya seçildi: {base} ({mb:.2f} MB)")

    def select_keyfile(self):
        path = filedialog.askopenfilename(title="Keyfile seçin")
        if path:
            self.keyfile_path = path
            self.keyfile_label.config(text=os.path.basename(path))
            self.log(f"Keyfile: {os.path.basename(path)}")

    def encrypt_action(self):
        if not self.current_file or self.file_type != "normal":
            messagebox.showerror("Hata", "Önce şifrelenecek bir dosya seçin")
            return
        if self.is_processing:
            messagebox.showwarning("Uyarı", "İşlem devam ediyor")
            return
        if self.engine.preset.require_keyfile and not self.keyfile_path:
            messagebox.showerror("Keyfile Gerekli",
                                 f"{self.engine.preset.name} için keyfile zorunludur.")
            return

        if messagebox.askyesno("Parola", "Otomatik güçlü parola üretilsin mi?"):
            password, analysis = SecurePasswordGenerator.generate_password(
                self.security_level, False)
            win = tk.Toplevel(self.root)
            win.title("Üretilen Parola")
            win.geometry("440x300")
            win.transient(self.root)
            win.grab_set()
            tk.Label(win, text="ÜRETİLEN PAROLA", font=("Arial", 13, "bold")).pack(pady=10)
            tk.Label(win, text=password, font=("Consolas", 15, "bold"),
                     bg="black", fg="white", padx=16, pady=8).pack(pady=8)
            tk.Label(win, text=f"Uzunluk: {analysis['length']} | Güç: {analysis['strength']} "
                               f"| Entropi: {analysis['entropy_bits']:.1f} bit",
                     font=("Arial", 9)).pack(pady=4)

            def save_and_go():
                try:
                    fp = SecurePasswordGenerator.save_password_to_desktop(
                        password, metadata={"dosya": os.path.basename(self.current_file),
                                            "güvenlik": self.engine.preset.name})
                    self.log(f"Parola kaydedildi: {os.path.basename(fp)}")
                    messagebox.showinfo("Başarılı", f"Parola kaydedildi:\n{fp}")
                except Exception as e:
                    messagebox.showerror("Hata", f"Kayıt başarısız: {e}")
                win.destroy()
                self.start_encryption(password)

            tk.Button(win, text="Kaydet ve Devam Et", command=save_and_go,
                      bg="#27AE60", fg="white", font=("Arial", 11)).pack(pady=16)
            tk.Button(win, text="İptal", command=win.destroy).pack()
        else:
            password = simpledialog.askstring("Parola", "Parola:", show="*")
            if password:
                self.start_encryption(password)

    def start_encryption(self, password: str):
        if not password:
            return
        out = self.current_file + ".sne1"
        c = 1
        base, _ = os.path.splitext(self.current_file)
        while os.path.exists(out):
            out = f"{base}_{c}.sne1"
            c += 1
        engine = self.engine
        self.is_processing = True
        self.disable_buttons()
        threading.Thread(target=self._encrypt_thread,
                         args=(engine, self.current_file, out, password),
                         daemon=True).start()

    def _encrypt_thread(self, engine, inp, out, password):
        try:
            self.update_status("Şifreleme başlatılıyor...", 0)
            self.log(f"Şifreleme: {os.path.basename(inp)}")

            def cb(cur, tot, msg):
                self.update_status(msg, int(cur / tot * 100) if tot else 0)

            md = engine.encrypt_file(inp, out, password, self.keyfile_path, cb)
            self.update_status("Şifreleme tamamlandı", 100)
            self.root.after(0, lambda: messagebox.showinfo(
                "Başarılı",
                f"Şifreleme tamamlandı.\n\nDosya: {os.path.basename(out)}\n"
                f"Boyut: {md['encrypted_size']:,} bayt\nParçalar: {md['chunks']}\n"
                f"Güvenlik: {md['security_level']}"))
            self.log(f"Tamam: {os.path.basename(out)}")
        except Exception as e:
            msg = str(e)
            self.log(f"Şifreleme hatası: {msg}")
            self.update_status("Hata", 0)
            self.root.after(0, lambda: messagebox.showerror("Hata", msg))
        finally:
            self.is_processing = False
            self.root.after(0, self.enable_buttons)

    def decrypt_action(self):
        if not self.current_file or self.file_type != "encrypted":
            messagebox.showerror("Hata", "Önce .sne1 dosyası seçin")
            return
        if self.is_processing:
            messagebox.showwarning("Uyarı", "İşlem devam ediyor")
            return
        password = simpledialog.askstring("Parola", "Deşifreleme parolası:", show="*")
        if not password:
            return

        base = os.path.basename(self.current_file)
        out_name = base[:-5] if base.endswith(".sne1") else f"decrypted_{base}"
        out_dir = os.path.dirname(self.current_file) or "."
        out = os.path.join(out_dir, out_name)
        c = 1
        while os.path.exists(out):
            n, e = os.path.splitext(out_name)
            out = os.path.join(out_dir, f"{n}_{c}{e}")
            c += 1

        engine = self.engine
        self.is_processing = True
        self.disable_buttons()
        threading.Thread(target=self._decrypt_thread,
                         args=(engine, self.current_file, out, password),
                         daemon=True).start()

    def _decrypt_thread(self, engine, inp, out, password):
        try:
            self.update_status("Deşifreleme başlatılıyor...", 0)
            self.log(f"Deşifreleme: {os.path.basename(inp)}")

            def cb(cur, tot, msg):
                self.update_status(msg, int(cur / tot * 100) if tot else 0)

            md = engine.decrypt_file(inp, out, password, self.keyfile_path, cb)
            self.update_status("Deşifreleme tamamlandı", 100)
            self.root.after(0, lambda: messagebox.showinfo(
                "Başarılı",
                f"Deşifreleme tamamlandı.\n\nDosya: {os.path.basename(out)}\n"
                f"Boyut: {md['bytes_written']:,} bayt\nParçalar: {md['chunks_processed']}"))
            self.log(f"Tamam: {os.path.basename(out)}")
        except Exception as e:
            msg = str(e)
            self.log(f"Deşifreleme hatası: {msg}")
            self.update_status("Hata", 0)
            self.root.after(0, lambda: messagebox.showerror("Hata", msg))
        finally:
            self.is_processing = False
            self.root.after(0, self.enable_buttons)

    def generate_password(self):
        try:
            lvl = SecurityLevel(self.pass_level_var.get())
            pw, an = SecurePasswordGenerator.generate_password(lvl, self.memorable_var.get())
            self.generated_pass_var.set(pw)
            self.pass_info_label.config(
                text=f"Uzunluk: {an['length']} | Güç: {an['strength']} | "
                     f"Entropi: {an['entropy_bits']:.1f} bit")
            self.log(f"Parola üretildi ({an['strength']})")
        except Exception as e:
            messagebox.showerror("Hata", f"Parola üretilemedi: {e}")

    def save_password_to_desktop(self):
        pw = self.generated_pass_var.get()
        if not pw:
            messagebox.showwarning("Uyarı", "Önce parola üretin")
            return
        try:
            lvl = SecurityLevel(self.pass_level_var.get())
            fp = SecurePasswordGenerator.save_password_to_desktop(
                pw, metadata={"güvenlik": SECURITY_PRESETS[lvl].name})
            messagebox.showinfo("Başarılı", f"Kaydedildi:\n{fp}")
            self.log(f"Parola kaydedildi: {os.path.basename(fp)}")
        except Exception as e:
            messagebox.showerror("Hata", f"Kayıt başarısız: {e}")

    def update_status(self, msg: str, percent: int):
        def _u():
            self.status_var.set(msg)
            self.progress_var.set(percent)
            self.progress_label.config(text=f"%{percent}")
        self.root.after(0, _u)

    def log(self, msg: str):
        def _l():
            ts = datetime.now().strftime("%H:%M:%S")
            self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
            self.log_text.see(tk.END)
        self.root.after(0, _l)

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)
        self.log("Log temizlendi")

    def disable_buttons(self):
        self.encrypt_btn.config(state="disabled")
        self.decrypt_btn.config(state="disabled")
        self.file_button.config(state="disabled")

    def enable_buttons(self):
        self.file_button.config(state="normal")
        if self.file_type == "normal":
            self.encrypt_btn.config(state="normal")
            self.decrypt_btn.config(state="disabled")
        elif self.file_type == "encrypted":
            self.encrypt_btn.config(state="disabled")
            self.decrypt_btn.config(state="normal")
        else:
            self.encrypt_btn.config(state="disabled")
            self.decrypt_btn.config(state="disabled")

    def on_closing(self):
        if self.is_processing:
            if not messagebox.askyesno("Çıkış", "İşlem devam ediyor. Çıkılsın mı?"):
                return
        self.cleanup()
        self.root.destroy()

    def cleanup(self):
        if hasattr(self, "engine"):
            self.engine.memory.cleanup_all()


# ==============================
# CLI
# ==============================
def run_cli(status: Dict[str, Any]):
    print("SentinelONE - CLI")
    print(f"Güvenlik skoru: {status['score']}/100 ({status['level']})")
    if RestrictedSecurityMode.ACTIVE:
        print("Kısıtlı mod aktif (maksimum 100MB)")

    while True:
        print("\n1. Şifrele\n2. Deşifrele\n3. Parola Üret\n4. Çıkış")
        try:
            choice = input("Seçim: ").strip()
            if choice == "1":
                inp = input("Dosya: ").strip()
                if not os.path.exists(inp):
                    print("Bulunamadı")
                    continue
                print("Seviye:")
                for lvl, p in SECURITY_PRESETS.items():
                    print(f"  {lvl.value}. {p.name}")
                try:
                    lvl = SecurityLevel(int(input("Seviye: ").strip()))
                except (ValueError, KeyError):
                    print("Geçersiz")
                    continue
                engine = SentinelEngine(lvl)
                if engine.preset.require_keyfile:
                    kf = input("Keyfile (zorunlu): ").strip()
                    if not kf or not os.path.exists(kf):
                        print("Keyfile gerekli")
                        continue
                else:
                    kf = input("Keyfile (boş=atla): ").strip() or None

                auto = input("Otomatik parola? (e/h): ").lower() == "e"
                if auto:
                    pw, an = SecurePasswordGenerator.generate_password(lvl, False)
                    print(f"Parola: {pw}")
                    print(f"Güç: {an['strength']} | Entropi: {an['entropy_bits']:.1f} bit")
                else:
                    pw = input("Parola: ").strip()
                    if not pw:
                        continue
                out = inp + ".sne1"
                # [FIX #19c] Çakışma kontrolü CLI'de de
                if os.path.exists(out):
                    c = 1
                    base, _ = os.path.splitext(inp)
                    while os.path.exists(f"{base}_{c}.sne1"):
                        c += 1
                    out = f"{base}_{c}.sne1"
                try:
                    md = engine.encrypt_file(inp, out, pw, kf)
                    print(f"Tamam: {out} ({md['encrypted_size']:,} bayt, {md['chunks']} parça)")
                except Exception as e:
                    print(f"Hata: {e}")

            elif choice == "2":
                inp = input(".sne1 dosya: ").strip()
                if not os.path.exists(inp):
                    print("Bulunamadı")
                    continue
                pw = input("Parola: ").strip()
                if not pw:
                    continue
                kf = input("Keyfile (boş=atla): ").strip() or None
                out = input("Çıktı (boş=otomatik): ").strip()
                if not out:
                    b = os.path.basename(inp)
                    out = b[:-5] if b.endswith(".sne1") else f"dec_{b}"
                # [FIX #19d] Çakışma kontrolü
                if os.path.exists(out):
                    c = 1
                    base, ext = os.path.splitext(out)
                    while os.path.exists(f"{base}_{c}{ext}"):
                        c += 1
                    out = f"{base}_{c}{ext}"
                try:
                    md = SentinelEngine().decrypt_file(inp, out, pw, kf)
                    print(f"Tamam: {out} ({md['bytes_written']:,} bayt)")
                except Exception as e:
                    print(f"Hata: {e}")

            elif choice == "3":
                for lvl, p in SECURITY_PRESETS.items():
                    print(f"  {lvl.value}. {p.name}")
                try:
                    lvl = SecurityLevel(int(input("Seviye: ").strip()))
                except (ValueError, KeyError):
                    print("Geçersiz")
                    continue
                mem = input("Hatırlanabilir? (e/h): ").lower() == "e"
                pw, an = SecurePasswordGenerator.generate_password(lvl, mem)
                print(f"Parola: {pw}")
                print(f"Uzunluk: {an['length']} | Güç: {an['strength']} | "
                      f"Entropi: {an['entropy_bits']:.1f} bit")
                if input("Masaüstüne kaydet? (e/h): ").lower() == "e":
                    try:
                        print(f"Kaydedildi: {SecurePasswordGenerator.save_password_to_desktop(pw)}")
                    except Exception as e:
                        print(f"Hata: {e}")

            elif choice == "4":
                break
        except KeyboardInterrupt:
            print("\nİptal")
            break
        except Exception as e:
            print(f"Hata: {e}")


# ==============================
# ANA PROGRAM
# ==============================
def main():
    sys.dont_write_bytecode = True
    status = get_security_status()

    # [FIX #8b] GUI varsa Tk'yı bir kez oluştur; kısıtlı mod sorusu GUI'de sorulur
    if not GUI_AVAILABLE:
        RestrictedSecurityMode.evaluate_and_activate(status)
        if status["score"] < 30:
            print(f"Kritik güvenlik riski (skor: {status['score']}/100).")
            if input("Devam? (e/h): ").lower() != "e":
                return
        run_cli(status)
        return

    try:
        root = tk.Tk()
        if platform.system() == "Darwin":
            try:
                root.tk.call("tk", "scaling", 1.5)
            except Exception:
                pass
        # Kısıtlı mod sorusu (GUI'de, Tk zaten oluşturulmuşken)
        if status["score"] < 70:
            root.withdraw()
            resp = messagebox.askyesno(
                "Güvenlik Uyarısı",
                f"Güvenlik Skoru: {status['score']}/100\n\n"
                "Kısıtlı modda devam etmek ister misiniz?\n"
                "(Dosya boyutu 100MB ile sınırlı)",
                icon="warning",
            )
            if resp:
                RestrictedSecurityMode.ACTIVE = True
            else:
                root.destroy()
                return
            root.deiconify()

        SentinelGUI(root, status)
        root.update_idletasks()
        w, h = 980, 740
        x = (root.winfo_screenwidth() - w) // 2
        y = (root.winfo_screenheight() - h) // 2
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.mainloop()
    except Exception as e:
        print(f"GUI hatası: {e}. CLI'ye geçiliyor.")
        run_cli(status)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nDurduruldu")
    except Exception as e:
        print(f"Beklenmeyen hata: {e}")
        import traceback
        traceback.print_exc()