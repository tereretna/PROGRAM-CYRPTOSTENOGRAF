"""
crypto.py - Modul Kriptografi AES-256 menggunakan pycryptodome
Implementasi: AES-256 mode GCM (Galois/Counter Mode) untuk keamanan maksimal
"""
import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes


# Konstanta
SALT_SIZE   = 16   # bytes
NONCE_SIZE  = 16   # bytes (GCM nonce)
TAG_SIZE    = 16   # bytes (GCM authentication tag)
KEY_SIZE    = 32   # bytes -> 256 bit
ITER_COUNT  = 200_000  # iterasi PBKDF2


def _derive_key(password: str, salt: bytes) -> bytes:
    """Menurunkan kunci AES-256 dari password menggunakan PBKDF2-HMAC-SHA256."""
    return PBKDF2(
        password.encode('utf-8'),
        salt,
        dkLen=KEY_SIZE,
        count=ITER_COUNT,
        prf=lambda p, s: HMAC.new(p, s, SHA256).digest()
    )


def encrypt(plaintext: str, password: str) -> str:
    """
    Mengenkripsi plaintext menggunakan AES-256-GCM.

    Format output (base64):
        SALT (16 B) | NONCE (16 B) | TAG (16 B) | CIPHERTEXT (N B)

    Returns:
        String base64 yang aman untuk ditampilkan dan disimpan.
    """
    salt  = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)
    key   = _derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

    payload = salt + nonce + tag + ciphertext
    return base64.b64encode(payload).decode('utf-8')


def decrypt(encoded: str, password: str) -> str:
    """
    Mendekripsi ciphertext (format base64) menggunakan AES-256-GCM.

    Returns:
        Plaintext asli sebagai string.

    Raises:
        ValueError: Jika password salah atau data rusak/dimanipulasi.
    """
    try:
        payload    = base64.b64decode(encoded.encode('utf-8'))
        salt       = payload[:SALT_SIZE]
        nonce      = payload[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        tag        = payload[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + TAG_SIZE]
        ciphertext = payload[SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

        key    = _derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError, Exception):
        raise ValueError("Dekripsi gagal: password salah atau data telah dimanipulasi.")


# ─── Utilitas ─────────────────────────────────────────────────────────────────

def get_password_strength(password: str) -> dict:
    """
    Mengevaluasi kekuatan password dan mengembalikan skor + saran.
    """
    score = 0
    tips  = []

    if len(password) >= 8:
        score += 1
    else:
        tips.append("Gunakan minimal 8 karakter.")

    if len(password) >= 12:
        score += 1

    if any(c.isupper() for c in password):
        score += 1
    else:
        tips.append("Tambahkan huruf kapital (A-Z).")

    if any(c.islower() for c in password):
        score += 1
    else:
        tips.append("Tambahkan huruf kecil (a-z).")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        tips.append("Tambahkan angka (0-9).")

    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        score += 1
    else:
        tips.append("Tambahkan karakter spesial (!@#$%^&*).")

    labels = {0: 'Sangat Lemah', 1: 'Lemah', 2: 'Lemah',
              3: 'Sedang', 4: 'Kuat', 5: 'Sangat Kuat', 6: 'Sangat Kuat'}
    colors = {0: 'danger', 1: 'danger', 2: 'warning',
              3: 'warning', 4: 'info', 5: 'success', 6: 'success'}

    return {
        'score' : score,
        'label' : labels.get(score, 'Sedang'),
        'color' : colors.get(score, 'info'),
        'tips'  : tips,
        'persen': min(int(score / 6 * 100), 100)
    }