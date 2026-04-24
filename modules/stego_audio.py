"""
stego_audio.py - Modul Steganografi Audio (Hybrid LSB + AES-256)
Mendukung format WAV. Menggunakan modul `wave` bawaan Python.

Hybrid LSB Audio: bit pesan disisipkan pada LSB setiap sample audio
(16-bit PCM, little-endian). Hybrid berarti bit disisipkan bergantian
pada byte rendah dan byte tinggi setiap sample.
"""
import io
import wave
import struct
import numpy as np
from modules.crypto import encrypt, decrypt

# Penanda akhir pesan
DELIMITER = b'\x00\xFF\xAA\x55\xDE\xAD\xBE\xEF'


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _text_to_bits(data: bytes) -> list:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list) -> bytes:
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


def _compute_audio_snr(original: np.ndarray, stego: np.ndarray) -> dict:
    """Menghitung SNR (Signal-to-Noise Ratio) untuk audio."""
    noise     = original.astype(np.float64) - stego.astype(np.float64)
    signal_pwr = np.mean(original.astype(np.float64) ** 2)
    noise_pwr  = np.mean(noise ** 2)
    if noise_pwr == 0:
        snr = float('inf')
    else:
        snr = 10 * np.log10(signal_pwr / noise_pwr)

    # PSNR untuk audio (max value = 32767 untuk 16-bit)
    if noise_pwr == 0:
        psnr = float('inf')
    else:
        psnr = 10 * np.log10((32767.0 ** 2) / noise_pwr)

    return {
        'snr' : round(float(snr),  4),
        'psnr': round(float(psnr), 4),
        'ssim': None  # SSIM tidak berlaku untuk audio
    }


# ─── Encode ───────────────────────────────────────────────────────────────────

def encode_audio(audio_bytes: bytes, message: str, password: str) -> tuple:
    """
    Menyisipkan pesan terenkripsi ke dalam file WAV menggunakan Hybrid LSB.

    Args:
        audio_bytes : Konten file WAV (bytes).
        message     : Pesan plaintext.
        password    : Password untuk enkripsi AES-256.

    Returns:
        Tuple (stego_wav_bytes: bytes, metrics: dict)

    Raises:
        ValueError: Kapasitas tidak cukup atau format tidak didukung.
    """
    # 1. Enkripsi pesan
    ciphertext_b64 = encrypt(message, password)
    payload        = ciphertext_b64.encode('utf-8') + DELIMITER
    bits           = _text_to_bits(payload)

    # 2. Baca file WAV
    buf_in = io.BytesIO(audio_bytes)
    with wave.open(buf_in, 'rb') as wf:
        params      = wf.getparams()
        n_channels  = wf.getnchannels()
        sampwidth   = wf.getsampwidth()
        framerate   = wf.getframerate()
        n_frames    = wf.getnframes()
        raw_frames  = wf.readframes(n_frames)

    if sampwidth != 2:
        raise ValueError(
            f"Format audio tidak didukung: sample width {sampwidth * 8}-bit. "
            "Gunakan file WAV 16-bit PCM."
        )

    # 3. Konversi ke array numpy (16-bit signed integer)
    samples_orig = np.frombuffer(raw_frames, dtype=np.int16).copy()

    # Hybrid: sisipkan pada LSB byte rendah, bergantian dengan byte tinggi
    max_bits = len(samples_orig)  # 1 bit per sample (LSB)
    if len(bits) > max_bits:
        raise ValueError(
            f"Pesan terlalu panjang! Kapasitas audio: {max_bits // 8} byte, "
            f"dibutuhkan: {len(bits) // 8} byte."
        )

    samples_stego = samples_orig.copy()
    for i, bit in enumerate(bits):
        # Hybrid LSB: bit genap -> LSB, bit ganjil -> second LSB
        if i % 2 == 0:
            samples_stego[i] = (samples_stego[i] & ~1) | bit
        else:
            samples_stego[i] = (samples_stego[i] & ~2) | (bit << 1)

    # 4. Hitung metrik
    metrics = _compute_audio_snr(samples_orig, samples_stego)

    # 5. Simpan kembali ke WAV
    buf_out = io.BytesIO()
    with wave.open(buf_out, 'wb') as wf_out:
        wf_out.setparams(params)
        wf_out.writeframes(samples_stego.tobytes())

    return buf_out.getvalue(), metrics


# ─── Decode ───────────────────────────────────────────────────────────────────

def decode_audio(stego_bytes: bytes, password: str) -> str:
    """
    Mengekstrak dan mendekripsi pesan dari file WAV stego.

    Args:
        stego_bytes : Konten file WAV stego (bytes).
        password    : Password untuk dekripsi AES-256.

    Returns:
        Pesan plaintext.

    Raises:
        ValueError: Delimiter tidak ditemukan atau password salah.
    """
    buf_in = io.BytesIO(stego_bytes)
    with wave.open(buf_in, 'rb') as wf:
        n_frames   = wf.getnframes()
        raw_frames = wf.readframes(n_frames)

    samples = np.frombuffer(raw_frames, dtype=np.int16)

    # Ekstrak bit (Hybrid LSB)
    bits = []
    for i, sample in enumerate(samples):
        if i % 2 == 0:
            bits.append(int(sample & 1))
        else:
            bits.append(int((sample >> 1) & 1))

    # Konversi ke bytes dan cari delimiter
    raw_bytes = _bits_to_bytes(bits)
    delim_pos = raw_bytes.find(DELIMITER)

    if delim_pos == -1:
        raise ValueError("Tidak ditemukan pesan tersembunyi dalam file audio ini.")

    ciphertext_b64 = raw_bytes[:delim_pos].decode('utf-8')
    return decrypt(ciphertext_b64, password)


# ─── Kapasitas ────────────────────────────────────────────────────────────────

def get_audio_capacity(audio_bytes: bytes) -> dict:
    """Mengembalikan kapasitas penyimpanan audio dalam byte."""
    buf = io.BytesIO(audio_bytes)
    with wave.open(buf, 'rb') as wf:
        n_frames   = wf.getnframes()
        framerate  = wf.getframerate()
        n_channels = wf.getnchannels()
        duration   = n_frames / framerate

    max_bits  = n_frames * n_channels
    max_bytes = max_bits // 8
    overhead  = len(DELIMITER) + 200
    usable    = max(0, max_bytes - overhead)
    return {
        'durasi'     : round(duration, 2),
        'framerate'  : framerate,
        'max_byte'   : max_bytes,
        'usable_byte': usable,
        'usable_char': usable // 4
    }