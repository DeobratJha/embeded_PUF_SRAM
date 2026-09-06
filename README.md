# ESP32 SRAM PUF

Small ESP32 project demonstrating SRAM-based PUF (Physically Unclonable Function).

Quick start
- Install and activate the ESP-IDF toolchain.
- From the project root run:

```powershell
idf.py build
idf.py -p <PORT> flash
```

Notes
- Generated build artifacts are excluded via `.gitignore` — do not commit `build/`.
- This repository contains ESP-IDF components and application source under `esp32_sram_puf/`.

If you want, I can commit and push this file for you.
