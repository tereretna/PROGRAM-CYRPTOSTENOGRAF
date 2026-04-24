"""
stego_image.py - Modul Steganografi Citra (Hybrid LSB + AES-256)
Mendukung format PNG dan JPG. Output selalu PNG (lossless).

Hybrid LSB: bit-bit pesan disisipkan pada LSB channel RGB
secara bergiliran (R->G->B->R->...) untuk meningkatkan ketahanan.
"""
import io
import struct
import numpy as np
from PIL import Image
from skimage.metrics import peak_signal_noise_ratio as psnr_func
from skimage.metrics import structural_similarity as ssim_func

from modules.crypto import encrypt, decrypt

# Penanda akhir pesan (8 byte unik)
DELIMITER = b'\x00\xFF\xAA\x55\xDE\xAD\xBE\xEF'


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _text_to_bits(data: bytes) -> list:
    """Mengubah bytes menjadi list bit (0/1)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list) -> bytes:
    """Mengubah list bit kembali menjadi bytes."""
    result = []
    for i in range(0, len(bits), 8):
        chunk = bits[i:i+8]
        if len(chunk) < 8:
            break
        byte = 0
        for b in chunk:
            byte = (byte << 1) | b
        result.append(byte)
    return bytes(result)


def _compute_metrics(original: np.ndarray, stego: np.ndarray) -> dict:
    """Menghitung PSNR dan SSIM antara gambar asli dan stego."""
    psnr_val = psnr_func(original, stego, data_range=255)
    ssim_val = ssim_func(
        original, stego,
        multichannel=True,
        channel_axis=-1,
        data_range=255
    )
    return {
        'psnr': round(float(psnr_val), 4),
        'ssim': round(float(ssim_val), 6)
    }


# ─── Encode ───────────────────────────────────────────────────────────────────

def encode_image(image_bytes: bytes, message: str, password: str) -> tuple:
    """
    Menyisipkan pesan terenkripsi ke dalam gambar menggunakan Hybrid LSB.

    Args:
        image_bytes : Konten file gambar (bytes).
        message     : Pesan plaintext yang akan disisipkan.
        password    : Password untuk enkripsi AES-256.

    Returns:
        Tuple (stego_png_bytes: bytes, metrics: dict)

    Raises:
        ValueError: Jika kapasitas gambar tidak cukup.
    """
    # 1. Enkripsi pesan
    ciphertext_b64 = encrypt(message, password)
    payload        = ciphertext_b64.encode('utf-8') + DELIMITER
    bits           = _text_to_bits(payload)

    # 2. Buka gambar
    img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    arr_original = np.array(img, dtype=np.uint8)
    arr          = arr_original.copy()

    h, w, c = arr.shape
    max_bits = h * w * 3  # 3 channel: R, G, B

    if len(bits) > max_bits:
        raise ValueError(
            f"Pesan terlalu panjang! Kapasitas gambar: {max_bits // 8} byte, "
            f"dibutuhkan: {len(bits) // 8} byte."
        )

    # 3. Sisipkan bit secara Hybrid (R, G, B bergiliran)
    bit_idx = 0
    for i in range(h):
        for j in range(w):
            for ch in range(3):  # Hybrid: R, G, B
                if bit_idx >= len(bits):
                    break
                # Ganti LSB pixel
                arr[i, j, ch] = (int(arr[i, j, ch]) & 0xFE) | bits[bit_idx]
                bit_idx += 1
            if bit_idx >= len(bits):
                break
        if bit_idx >= len(bits):
            break

    # 4. Hitung metrik kualitas
    metrics = _compute_metrics(arr_original, arr)

    # 5. Simpan sebagai PNG (lossless)
    stego_img = Image.fromarray(arr, 'RGB')
    buf = io.BytesIO()
    stego_img.save(buf, format='PNG', optimize=False, compress_level=1)
    return buf.getvalue(), metrics


# ─── Decode ───────────────────────────────────────────────────────────────────

def decode_image(stego_bytes: bytes, password: str) -> str:
    """
    Mengekstrak dan mendekripsi pesan dari gambar stego.

    Args:
        stego_bytes : Konten file gambar stego (bytes).
        password    : Password untuk dekripsi AES-256.

    Returns:
        Pesan plaintext yang berhasil diekstrak.

    Raises:
        ValueError: Jika delimiter tidak ditemukan atau password salah.
    """
    img = Image.open(io.BytesIO(stego_bytes)).convert('RGB')
    arr = np.array(img, dtype=np.uint8)
    h, w, _ = arr.shape

    # 1. Ekstrak semua LSB
    bits = []
    for i in range(h):
        for j in range(w):
            for ch in range(3):
                bits.append(int(arr[i, j, ch] & 1))

    # 2. Konversi ke bytes dan cari delimiter
    raw_bytes = _bits_to_bytes(bits)
    delim_pos = raw_bytes.find(DELIMITER)

    if delim_pos == -1:
        raise ValueError("Tidak ditemukan pesan tersembunyi dalam gambar ini.")

    ciphertext_b64 = raw_bytes[:delim_pos].decode('utf-8')

    # 3. Dekripsi
    return decrypt(ciphertext_b64, password)


# ─── Kapasitas ────────────────────────────────────────────────────────────────

def get_capacity(image_bytes: bytes) -> dict:
    """Mengembalikan kapasitas penyimpanan gambar dalam byte dan karakter."""
    img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    arr = np.array(img)
    h, w, _ = arr.shape
    max_bytes = (h * w * 3) // 8
    overhead  = len(DELIMITER) + 200  # estimasi overhead enkripsi
    usable    = max(0, max_bytes - overhead)
    return {
        'resolusi'   : f"{w}x{h}",
        'max_byte'   : max_bytes,
        'usable_byte': usable,
        'usable_char': usable // 4  # estimasi karakter UTF-8
    }