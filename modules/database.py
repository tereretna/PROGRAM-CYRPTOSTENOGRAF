"""
database.py - Modul koneksi dan manajemen database SQLite
"""
import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'cryptostego.db')


def get_connection():
    """Mengembalikan koneksi ke database SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Membuat tabel-tabel yang diperlukan jika belum ada."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS riwayat (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            jenis       TEXT    NOT NULL,
            operasi     TEXT    NOT NULL,
            nama_file   TEXT,
            pesan_info  TEXT,
            waktu       TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'Sukses',
            psnr_value  REAL,
            ssim_value  REAL
        );
    """)

    conn.commit()
    conn.close()
    print("[DB] Database diinisialisasi.")


def tambah_riwayat(jenis, operasi, nama_file=None, pesan_info=None,
                   status='Sukses', psnr_value=None, ssim_value=None):
    """Menyimpan satu record riwayat operasi ke database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO riwayat (jenis, operasi, nama_file, pesan_info, waktu, status, psnr_value, ssim_value)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (jenis, operasi, nama_file, pesan_info,
         datetime.now().strftime('%Y-%m-%d %H:%M:%S'), status, psnr_value, ssim_value)
    )
    conn.commit()
    conn.close()


def ambil_semua_riwayat():
    """Mengambil seluruh riwayat operasi dari database (terbaru dulu)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM riwayat ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def hapus_riwayat(record_id):
    """Menghapus satu record riwayat berdasarkan ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM riwayat WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()


def hapus_semua_riwayat():
    """Menghapus seluruh isi tabel riwayat."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM riwayat")
    conn.commit()
    conn.close()