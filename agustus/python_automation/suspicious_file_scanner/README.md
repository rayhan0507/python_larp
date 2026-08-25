## Struktur folder

```
simple_file_scanner/
├── scan.py          <- semua logikanya ada di sini, dibaca dari atas ke bawah
├── sample_data/      <- contoh file buat dites (sudah ada file "aman" & "mencurigakan")
└── README.md
```

## Cara pakai

```bash
python scan.py
```

Script ini otomatis akan:
1. Scan folder `sample_data/`
2. Tampilkan daftar file yang mencurigakan beserta alasannya
3. Tanya apakah mau dipindahkan ke folder `karantina/` (jawab `y` atau `n`)
4. Kalau `y`, folder karantina otomatis di-zip

## Isi `scan.py`, bagian per bagian


## kategori yang dideteksi

1. **Tanpa ekstensi** -> `path.suffix == ""`
2. **Nama mencurigakan**
   - Ekstensi ganda: `invoice.pdf.exe`
   - Nama kayak hash acak: `a8f5f167f44f...exe`
   - Kata berbahaya di nama: `crack`, `keygen`, `payload`, dll
3. **Ukuran aneh**
   - File 0 byte
   - File `.exe` yang kekecilan (< 10 KB)
