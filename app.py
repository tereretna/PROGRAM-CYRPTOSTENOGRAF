"""
app.py - Aplikasi Web Utama (Flask)
CryptoStego Dashboard - Hybrid Cryptography & Steganography
"""
import os
import io
import uuid
from datetime import datetime
from flask import (Flask, render_template, request, redirect,
                   url_for, flash, send_file, jsonify, session)

from modules.database import init_db, tambah_riwayat, ambil_semua_riwayat, hapus_riwayat, hapus_semua_riwayat
from modules.crypto    import encrypt, decrypt, get_password_strength
from modules.stego_image import encode_image, decode_image, get_capacity
from modules.stego_audio import encode_audio, decode_audio, get_audio_capacity

# ─── Konfigurasi ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(32)

UPLOAD_FOLDER  = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
ALLOWED_IMAGE  = {'png', 'jpg', 'jpeg'}
ALLOWED_AUDIO  = {'wav'}
MAX_FILE_MB    = 50

app.config['UPLOAD_FOLDER']    = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_MB * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─── Inisialisasi DB ──────────────────────────────────────────────────────────
with app.app_context():
    init_db()


# ─── Helpers ──────────────────────────────────────────────────────────────────
def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set


def unique_name(prefix, ext):
    return f"{prefix}_{uuid.uuid4().hex[:8]}.{ext}"


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    """Halaman dashboard utama."""
    stats = {
        'total'   : len(ambil_semua_riwayat()),
    }
    return render_template('dashboard.html', stats=stats)


# ══════════════════════════════════════════════════════════════════════════════
# MODUL KRIPTOGRAFI
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/crypto/enkripsi', methods=['GET', 'POST'])
def crypto_enkripsi():
    result = None
    if request.method == 'POST':
        plaintext = request.form.get('plaintext', '').strip()
        password  = request.form.get('password', '').strip()
        if not plaintext or not password:
            flash('Teks dan password tidak boleh kosong.', 'danger')
        else:
            try:
                ciphertext = encrypt(plaintext, password)
                result = {'ciphertext': ciphertext, 'panjang': len(ciphertext)}
                tambah_riwayat('Kriptografi', 'Enkripsi AES-256',
                               pesan_info=f"Panjang teks: {len(plaintext)} karakter")
                flash('Enkripsi berhasil!', 'success')
            except Exception as e:
                flash(f'Error: {str(e)}', 'danger')
    return render_template('crypto_enkripsi.html', result=result)


@app.route('/crypto/dekripsi', methods=['GET', 'POST'])
def crypto_dekripsi():
    result = None
    if request.method == 'POST':
        ciphertext = request.form.get('ciphertext', '').strip()
        password   = request.form.get('password', '').strip()
        if not ciphertext or not password:
            flash('Ciphertext dan password tidak boleh kosong.', 'danger')
        else:
            try:
                plaintext = decrypt(ciphertext, password)
                result = {'plaintext': plaintext}
                tambah_riwayat('Kriptografi', 'Dekripsi AES-256',
                               pesan_info=f"Dekripsi berhasil")
                flash('Dekripsi berhasil!', 'success')
            except ValueError as e:
                flash(str(e), 'danger')
    return render_template('crypto_dekripsi.html', result=result)


# ══════════════════════════════════════════════════════════════════════════════
# MODUL STEGANOGRAFI CITRA
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/stego/image/encode', methods=['GET', 'POST'])
def stego_image_encode():
    capacity = None
    if request.method == 'POST':
        file     = request.files.get('image')
        message  = request.form.get('message', '').strip()
        password = request.form.get('password', '').strip()

        if not file or not allowed_file(file.filename, ALLOWED_IMAGE):
            flash('Harap upload file gambar (PNG/JPG).', 'danger')
            return render_template('stego_image_encode.html', capacity=capacity)
        if not message or not password:
            flash('Pesan dan password tidak boleh kosong.', 'danger')
            return render_template('stego_image_encode.html', capacity=capacity)

        try:
            image_bytes = file.read()
            stego_bytes, metrics = encode_image(image_bytes, message, password)
            out_name = unique_name('stego_img', 'png')
            out_path = os.path.join(UPLOAD_FOLDER, out_name)
            with open(out_path, 'wb') as f:
                f.write(stego_bytes)

            tambah_riwayat(
                'Stego Citra', 'Encode Image',
                nama_file=out_name,
                pesan_info=f"Pesan: {len(message)} karakter",
                psnr_value=metrics['psnr'],
                ssim_value=metrics['ssim']
            )
            flash(
                f"Encode berhasil! PSNR: {metrics['psnr']} dB | SSIM: {metrics['ssim']}",
                'success'
            )
            return send_file(
                io.BytesIO(stego_bytes),
                mimetype='image/png',
                as_attachment=True,
                download_name=out_name
            )
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception as e:
            flash(f'Error tidak terduga: {str(e)}', 'danger')

    return render_template('stego_image_encode.html', capacity=capacity)


@app.route('/stego/image/decode', methods=['GET', 'POST'])
def stego_image_decode():
    result = None
    if request.method == 'POST':
        file     = request.files.get('image')
        password = request.form.get('password', '').strip()

        if not file or not allowed_file(file.filename, ALLOWED_IMAGE):
            flash('Harap upload file gambar stego (PNG/JPG).', 'danger')
            return render_template('stego_image_decode.html', result=result)
        if not password:
            flash('Password tidak boleh kosong.', 'danger')
            return render_template('stego_image_decode.html', result=result)

        try:
            image_bytes = file.read()
            plaintext   = decode_image(image_bytes, password)
            result = {'plaintext': plaintext, 'nama_file': file.filename}
            tambah_riwayat('Stego Citra', 'Decode Image',
                           nama_file=file.filename,
                           pesan_info='Ekstraksi berhasil')
            flash('Pesan berhasil diekstrak!', 'success')
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

    return render_template('stego_image_decode.html', result=result)


# ══════════════════════════════════════════════════════════════════════════════
# MODUL STEGANOGRAFI AUDIO
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/stego/audio/encode', methods=['GET', 'POST'])
def stego_audio_encode():
    if request.method == 'POST':
        file     = request.files.get('audio')
        message  = request.form.get('message', '').strip()
        password = request.form.get('password', '').strip()

        if not file or not allowed_file(file.filename, ALLOWED_AUDIO):
            flash('Harap upload file audio WAV.', 'danger')
            return render_template('stego_audio_encode.html')
        if not message or not password:
            flash('Pesan dan password tidak boleh kosong.', 'danger')
            return render_template('stego_audio_encode.html')

        try:
            audio_bytes = file.read()
            stego_bytes, metrics = encode_audio(audio_bytes, message, password)
            out_name = unique_name('stego_audio', 'wav')
            out_path = os.path.join(UPLOAD_FOLDER, out_name)
            with open(out_path, 'wb') as f:
                f.write(stego_bytes)

            tambah_riwayat(
                'Stego Audio', 'Encode Audio',
                nama_file=out_name,
                pesan_info=f"Pesan: {len(message)} karakter",
                psnr_value=metrics['psnr'],
                ssim_value=metrics.get('ssim')
            )
            flash(
                f"Encode audio berhasil! PSNR: {metrics['psnr']} dB | SNR: {metrics['snr']} dB",
                'success'
            )
            return send_file(
                io.BytesIO(stego_bytes),
                mimetype='audio/wav',
                as_attachment=True,
                download_name=out_name
            )
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

    return render_template('stego_audio_encode.html')


@app.route('/stego/audio/decode', methods=['GET', 'POST'])
def stego_audio_decode():
    result = None
    if request.method == 'POST':
        file     = request.files.get('audio')
        password = request.form.get('password', '').strip()

        if not file or not allowed_file(file.filename, ALLOWED_AUDIO):
            flash('Harap upload file audio WAV stego.', 'danger')
            return render_template('stego_audio_decode.html', result=result)
        if not password:
            flash('Password tidak boleh kosong.', 'danger')
            return render_template('stego_audio_decode.html', result=result)

        try:
            audio_bytes = file.read()
            plaintext   = decode_audio(audio_bytes, password)
            result = {'plaintext': plaintext, 'nama_file': file.filename}
            tambah_riwayat('Stego Audio', 'Decode Audio',
                           nama_file=file.filename,
                           pesan_info='Ekstraksi berhasil')
            flash('Pesan berhasil diekstrak dari audio!', 'success')
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

    return render_template('stego_audio_decode.html', result=result)


# ══════════════════════════════════════════════════════════════════════════════
# RIWAYAT (CRUD)
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/riwayat')
def riwayat():
    data = ambil_semua_riwayat()
    return render_template('riwayat.html', data=data)


@app.route('/riwayat/hapus/<int:record_id>', methods=['POST'])
def hapus_satu(record_id):
    hapus_riwayat(record_id)
    flash('Record berhasil dihapus.', 'info')
    return redirect(url_for('riwayat'))


@app.route('/riwayat/hapus-semua', methods=['POST'])
def hapus_semua():
    hapus_semua_riwayat()
    flash('Seluruh riwayat berhasil dihapus.', 'info')
    return redirect(url_for('riwayat'))


# ══════════════════════════════════════════════════════════════════════════════
# API UTILITAS (AJAX)
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/password-strength', methods=['POST'])
def api_password_strength():
    data     = request.get_json()
    password = data.get('password', '')
    result   = get_password_strength(password)
    return jsonify(result)


@app.route('/api/image-capacity', methods=['POST'])
def api_image_capacity():
    file = request.files.get('image')
    if not file:
        return jsonify({'error': 'No file'}), 400
    try:
        info = get_capacity(file.read())
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/audio-capacity', methods=['POST'])
def api_audio_capacity():
    file = request.files.get('audio')
    if not file:
        return jsonify({'error': 'No file'}), 400
    try:
        info = get_audio_capacity(file.read())
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Error handlers ───────────────────────────────────────────────────────────
@app.errorhandler(413)
def too_large(e):
    flash(f'File terlalu besar. Maksimum {MAX_FILE_MB} MB.', 'danger')
    return redirect(request.referrer or url_for('dashboard'))


# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)