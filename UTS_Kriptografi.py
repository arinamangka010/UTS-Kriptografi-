"""
=============================================================================
  UTS KRIPTOGRAFI – Soal No. 16 (Genap)
  Perbandingan Kriptografi Simetris (AES/Fernet) vs Asimetris (RSA)
  
  Materi  : Symmetric cryptography dan Asymmetric cryptography
  Deskripsi: Membandingkan metode kriptografi simetris dan asimetris
  Ketentuan:
    1. Implementasi AES/Fernet (simetris) dan RSA (asimetris)
    2. Pengujian: kecepatan proses, ukuran ciphertext, keamanan dasar
    3. Tabel perbandingan
=============================================================================
"""

import time
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────────────────────────────────────
#  KONSTANTA
# ─────────────────────────────────────────────────────────────────────────────
ULANG = 100          # jumlah pengulangan untuk rata-rata waktu
LEBAR = 70           # lebar border tabel


# ─────────────────────────────────────────────────────────────────────────────
#  HELPER TAMPILAN
# ─────────────────────────────────────────────────────────────────────────────
def garis(char="═", lebar=LEBAR):
    print(char * lebar)

def header(judul: str):
    garis()
    print(f"  {judul}")
    garis()

def sub_header(judul: str):
    print(f"\n  ── {judul} ──")

def cetak_tabel_border(headers, rows, widths, row_sep=True):
    """Mencetak tabel dengan garis border menggunakan karakter kotak."""
    top = "┌" + "┬".join("─" * (w + 2) for w in widths) + "┐"
    sep = "├" + "┼".join("─" * (w + 2) for w in widths) + "┤"
    bot = "└" + "┴".join("─" * (w + 2) for w in widths) + "┘"

    def baris(cols):
        cells = " │ ".join(str(c).ljust(w) for c, w in zip(cols, widths))
        return "│ " + cells + " │"

    print("  " + top)
    print("  " + baris(headers))
    print("  " + sep)
    for i, row in enumerate(rows):
        print("  " + baris(row))
        if row_sep and i < len(rows) - 1:
            print("  " + sep)
    print("  " + bot)


# ─────────────────────────────────────────────────────────────────────────────
#  1.  FERNET  (AES-128-CBC + HMAC-SHA256)
# ─────────────────────────────────────────────────────────────────────────────
class FernetSimetris:
    """Enkripsi simetris menggunakan Fernet (wrapper AES-128 CBC + HMAC)."""

    def __init__(self):
        self.kunci = Fernet.generate_key()
        self.fernet = Fernet(self.kunci)

    # Enkripsi
    def enkripsi(self, plaintext: bytes) -> bytes:
        return self.fernet.encrypt(plaintext)

    # Dekripsi
    def dekripsi(self, ciphertext: bytes) -> bytes:
        return self.fernet.decrypt(ciphertext)

    # Info kunci
    def info_kunci(self) -> dict:
        return {
            "algoritma"  : "Fernet (AES-128-CBC + HMAC-SHA256)",
            "ukuran_kunci": "256 bit (Fernet key)",
            "kunci_hex"  : self.kunci[:24].decode() + "...",
        }


# ─────────────────────────────────────────────────────────────────────────────
#  2.  RSA  (2048-bit)
# ─────────────────────────────────────────────────────────────────────────────
class RSAAsimetris:
    """Enkripsi asimetris menggunakan RSA-2048 dengan OAEP padding."""

    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.kunci_privat = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.kunci_publik = self.kunci_privat.public_key()

    # Enkripsi menggunakan kunci publik
    def enkripsi(self, plaintext: bytes) -> bytes:
        return self.kunci_publik.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # Dekripsi menggunakan kunci privat
    def dekripsi(self, ciphertext: bytes) -> bytes:
        return self.kunci_privat.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # Ukuran kunci publik (PEM)
    def ukuran_kunci_publik_bytes(self) -> int:
        pem = self.kunci_publik.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return len(pem)

    # Info kunci
    def info_kunci(self) -> dict:
        return {
            "algoritma"   : f"RSA-{self.key_size} (OAEP + SHA-256)",
            "ukuran_kunci": f"{self.key_size} bit",
            "exp_publik"  : "65537 (e)",
        }


# ─────────────────────────────────────────────────────────────────────────────
#  3.  PENGUJIAN
# ─────────────────────────────────────────────────────────────────────────────
def uji_kecepatan(obj, plaintext: bytes, ulang: int = ULANG):
    """Menghitung rata-rata waktu enkripsi & dekripsi (detik)."""
    # Enkripsi
    t0 = time.perf_counter()
    for _ in range(ulang):
        ct = obj.enkripsi(plaintext)
    t_enkripsi = (time.perf_counter() - t0) / ulang

    # Dekripsi
    t0 = time.perf_counter()
    for _ in range(ulang):
        obj.dekripsi(ct)
    t_dekripsi = (time.perf_counter() - t0) / ulang

    return t_enkripsi, t_dekripsi, ct


def uji_ukuran(plaintext: bytes, ciphertext: bytes):
    """Perbandingan ukuran plaintext vs ciphertext (bytes)."""
    return len(plaintext), len(ciphertext)


def keamanan_dasar(nama: str) -> dict:
    """Deskripsi tingkat keamanan dasar berdasarkan algoritma."""
    if "Fernet" in nama:
        return {
            "kunci"        : "1 kunci (shared secret)",
            "confidentiality": "AES-128-CBC",
            "integrity"    : "HMAC-SHA256 (built-in)",
            "keamanan_bit" : "128-bit symmetric",
            "max_plaintext": "Tidak terbatas",
            "distribusi"   : "Harus dibagi secara aman",
        }
    else:
        return {
            "kunci"        : "Kunci publik + privat",
            "confidentiality": "RSA-2048 OAEP",
            "integrity"    : "Tidak built-in",
            "keamanan_bit" : "≈112-bit asymmetric",
            "max_plaintext": "Maks ≤190 byte",
            "distribusi"   : "Kunci publik bebas dibagi",
        }


# ─────────────────────────────────────────────────────────────────────────────
#  4.  MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    header("PERBANDINGAN KRIPTOGRAFI SIMETRIS vs ASIMETRIS")

    # ── Plaintext uji ──────────────────────────────────────────────────────
    PLAINTEXT = b"Ini adalah pesan rahasia untuk pengujian kriptografi!"
    print(f"\n  Plaintext : \"{PLAINTEXT.decode()}\"")
    print(f"  Ukuran    : {len(PLAINTEXT)} byte")
    print(f"  Pengulangan: {ULANG}x (untuk rata-rata waktu)")

    # ── Inisialisasi ────────────────────────────────────────────────────────
    sub_header("Inisialisasi & Generate Kunci")

    t0 = time.perf_counter()
    fernet_obj = FernetSimetris()
    t_gen_fernet = time.perf_counter() - t0

    t0 = time.perf_counter()
    rsa_obj = RSAAsimetris(key_size=2048)
    t_gen_rsa = time.perf_counter() - t0

    print(f"  Fernet – generate kunci : {t_gen_fernet*1000:.4f} ms")
    print(f"  RSA    – generate kunci : {t_gen_rsa*1000:.4f} ms")

    # ── Info Kunci ──────────────────────────────────────────────────────────
    sub_header("Informasi Kunci")
    fi = fernet_obj.info_kunci()
    ri = rsa_obj.info_kunci()
    print(f"  [Fernet] Algoritma   : {fi['algoritma']}")
    print(f"  [Fernet] Ukuran Kunci: {fi['ukuran_kunci']}")
    print(f"  [Fernet] Kunci (cut) : {fi['kunci_hex']}")
    print()
    print(f"  [RSA]    Algoritma   : {ri['algoritma']}")
    print(f"  [RSA]    Ukuran Kunci: {ri['ukuran_kunci']}")
    print(f"  [RSA]    Eksponen    : {ri['exp_publik']}")

    # ── Uji Kecepatan ───────────────────────────────────────────────────────
    sub_header(f"Pengujian Kecepatan (rata-rata {ULANG}x)")
    t_enc_f, t_dec_f, ct_f = uji_kecepatan(fernet_obj, PLAINTEXT)
    t_enc_r, t_dec_r, ct_r = uji_kecepatan(rsa_obj, PLAINTEXT)

    print(f"  Fernet – Enkripsi avg : {t_enc_f*1000:.4f} ms")
    print(f"  Fernet – Dekripsi avg : {t_dec_f*1000:.4f} ms")
    print(f"  RSA    – Enkripsi avg : {t_enc_r*1000:.4f} ms")
    print(f"  RSA    – Dekripsi avg : {t_dec_r*1000:.4f} ms")

    # ── Uji Ukuran Ciphertext ───────────────────────────────────────────────
    sub_header("Pengujian Ukuran Ciphertext")
    pt_sz, ct_sz_f = uji_ukuran(PLAINTEXT, ct_f)
    _,     ct_sz_r = uji_ukuran(PLAINTEXT, ct_r)

    print(f"  Plaintext ukuran    : {pt_sz} byte")
    print(f"  Fernet ciphertext   : {ct_sz_f} byte  (overhead: +{ct_sz_f - pt_sz} byte)")
    print(f"  RSA ciphertext      : {ct_sz_r} byte  (overhead: +{ct_sz_r - pt_sz} byte)")

    # ── Verifikasi Kebenaran ────────────────────────────────────────────────
    sub_header("Verifikasi Dekripsi")
    ok_f = fernet_obj.dekripsi(ct_f) == PLAINTEXT
    ok_r = rsa_obj.dekripsi(ct_r) == PLAINTEXT
    print(f"  Fernet – hasil dekripsi benar : {'✔ YA' if ok_f else '✘ TIDAK'}")
    print(f"  RSA    – hasil dekripsi benar : {'✔ YA' if ok_r else '✘ TIDAK'}")

    # ── Tingkat Keamanan Dasar ──────────────────────────────────────────────
    sub_header("Tingkat Keamanan Dasar")
    k_f = keamanan_dasar("Fernet")
    k_r = keamanan_dasar("RSA")

    label_map = {
        "kunci"          : "Jenis Kunci",
        "confidentiality": "Confidentiality",
        "integrity"      : "Integritas",
        "keamanan_bit"   : "Keamanan (bit)",
        "max_plaintext"  : "Maks. Plaintext",
        "distribusi"     : "Distribusi Kunci",
    }
    keamanan_rows = [(label_map[k], k_f[k], k_r[k]) for k in k_f]
    cetak_tabel_border(
        headers=["Parameter", "Fernet (Simetris)", "RSA (Asimetris)"],
        rows=keamanan_rows,
        widths=[16, 24, 25],
        row_sep=True
    )

    # ══════════════════════════════════════════════════════════════════════════
    #  TABEL PERBANDINGAN
    # ══════════════════════════════════════════════════════════════════════════
    print()
    garis("═")
    print("  TABEL PERBANDINGAN KRIPTOGRAFI SIMETRIS vs ASIMETRIS")
    garis("═")

    rows = [
        ("Jenis Algoritma",
         "Simetris",
         "Asimetris"),
        ("Nama Algoritma",
         "AES-128-CBC + HMAC",
         "RSA-2048 OAEP"),
        ("Ukuran Kunci",
         fi["ukuran_kunci"],
         ri["ukuran_kunci"]),
        ("Gen. Kunci (ms)",
         f"{t_gen_fernet*1000:.3f} ms",
         f"{t_gen_rsa*1000:.3f} ms"),
        ("Waktu Enkripsi (avg)",
         f"{t_enc_f*1000:.4f} ms",
         f"{t_enc_r*1000:.4f} ms"),
        ("Waktu Dekripsi (avg)",
         f"{t_dec_f*1000:.4f} ms",
         f"{t_dec_r*1000:.4f} ms"),
        ("Ukuran Plaintext",
         f"{pt_sz} byte",
         f"{pt_sz} byte"),
        ("Ukuran Ciphertext",
         f"{ct_sz_f} byte",
         f"{ct_sz_r} byte"),
        ("Overhead Ciphertext",
         f"+{ct_sz_f - pt_sz} byte",
         f"+{ct_sz_r - pt_sz} byte"),
        ("Integritas Data",
         "HMAC-SHA256 (built-in)",
         "Tidak built-in"),
        ("Keamanan (bit)",
         "128-bit",
         "≈112-bit"),
        ("Maks Ukuran Plaintext",
         "Tidak terbatas",
         "≤190 byte"),
        ("Distribusi Kunci",
         "Kunci harus dibagi aman",
         "Kunci publik bebas bagi"),
        ("Jumlah Kunci",
         "1 kunci (shared)",
         "2 kunci (pub+priv)"),
        ("Kecepatan Relatif",
         "SANGAT CEPAT",
         "LEBIH LAMBAT"),
        ("Penggunaan Umum",
         "Enkripsi data besar",
         "Key exchange & signing"),
    ]

    cetak_tabel_border(
        headers=["Parameter", "Fernet (Simetris)", "RSA (Asimetris)"],
        rows=rows,
        widths=[22, 23, 23],
        row_sep=False
    )

    garis("═")
    print()

    # ── Kesimpulan ──────────────────────────────────────────────────────────
    print("  KESIMPULAN:")
    print(f"  {'─'*66}")
    print("  • Fernet (Simetris) jauh lebih cepat untuk enkripsi/dekripsi.")
    print("  • RSA (Asimetris) tidak memerlukan pertukaran kunci rahasia,")
    print("    sehingga lebih aman untuk komunikasi awal (key exchange).")
    print("  • RSA memiliki batasan ukuran plaintext (≤190 byte untuk 2048-bit).")
    print("  • Praktik terbaik (Hybrid Encryption): RSA untuk menukar kunci")
    print("    simetris, lalu Fernet/AES untuk enkripsi data sesungguhnya.")
    garis("═")


if __name__ == "__main__":
    main()
