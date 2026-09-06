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
- This repo contains a full ESP-IDF application in `esp32_sram_puf/` including the `main/` component and local `components/`.

Overview
- Implements SRAM PUF extraction, a challenge-response authentication protocol, and optional Kyber-based post-quantum key agreement.

Project layout (important files)
- `esp32_sram_puf/main/` — contains `main_uav.c`, `main_gcc.c`, `authentication.c`, `puf_lib.*`, and related headers.
- `esp32_sram_puf/components/objective_2/` — Kyber key-agreement helpers and headers (`kyber_key_agreement.h`).

Build & flash (full)
```powershell
cd "D:\NITK\Major_Project\esp32_sram_puf_V6_Complete - novelty\esp32_sram_puf"
idf.py build
idf.py -p <PORT> flash
idf.py monitor
```

Recommended ESP-IDF
- The project references ESP-IDF v5.4.1 components in the build files; using ESP-IDF v5.4.x is recommended.

If you want a full, detailed README (architecture, API, enrollment steps, security notes), tell me and I will expand this file further.

---

## Detailed Project README

### Project summary

This project demonstrates a hardware-rooted identity built from SRAM-based PUF (Physically Unclonable Function) on ESP32 devices. It provides:

- PUF extraction and enrollment (helper data stored in NVS if enabled)
- Zero-stored-key mode: derive cryptographic seed from PUF on every boot without storing secrets in flash
- Challenge-response authentication (GCC ↔ UAV) using PUF-derived responses
- Optional post-quantum key-agreement (Kyber) to derive session keys after authentication
- ESP-NOW based messaging for low-latency wireless exchanges

### Table of contents

 - Quick start
 - Directory layout
 - Architecture overview
 - Public API reference
 - Enrollment and provisioning
 - Build, flash and monitor
 - Testing and debugging
 - Security considerations
 - Suggested .gitignore
 - Troubleshooting
 - Contributing

### Quick start (prerequisites)

1. Install ESP-IDF (recommended v5.4.x to match project artifacts) and set up the environment: follow official docs at https://docs.espressif.com/
2. Windows users: use the ESP-IDF PowerShell environment provided by the installer.

### Directory layout (important paths)

- `esp32_sram_puf/` — root ESP-IDF project folder
  - `main/` — application component source files and headers
	 - `main_uav.c` — UAV device role (PUF boot sequence, deterministic Kyber keygen, respond to challenges)
	 - `main_gcc.c` — GCC (ground control center) role (distance detection, challenge sending, verification, initiate Kyber)
	 - `authentication.c`, `authentication.h` — challenge/response logic and in-memory enrollment DB
	 - `puf_lib.c`, `puf_lib.h` — core PUF sampling, enrollment, helper data, read functions and utilities
	 - `esp_now_comm.c`, `esp_now_comm.h` — ESP-NOW messaging wrapper used across roles
  - `components/objective_2/` — Kyber (post-quantum) key-agreement helpers; includes `kyber_key_agreement.h`
  - `partitions.csv`, `sdkconfig*`, `CMakeLists.txt` — project config

### Architecture overview

1. PUF subsystem (`puf_lib`)
	- Supports multiple extraction regions: RTC SRAM and SRAM2.
	- Two operating modes: raw extraction (no enrollment) producing deterministic seed on each boot, or enrollment mode which records stable bit indices and helper data to reconstruct PUF responses reliably.
	- Functions: sampling with majority voting, freeze detection (detects capacitive retention/freeze events), helper-data generation and storage to NVS.

2. Authentication flow (`authentication.c`)
	- GCC sends a random challenge (nonce) to the UAV over ESP-NOW.
	- UAV reconstructs PUF response (or derives seed), computes `response = SHA256(challenge || PUF_RESPONSE)`, and sends back the response.
	- GCC verifies entropy and (optionally) reconstructs expected response using stored helper data for a match; current implementation verifies entropy and looks up device by MAC.

3. Post-quantum key agreement (Objective 2 / Kyber)
	- After authentication succeeds, GCC and UAV run Kyber encaps/decaps to derive a shared secret.
	- On UAV the Kyber keypair can be derived deterministically from the PUF-derived seed so the private key does not need to be stored in flash.

4. Communication layer (ESP-NOW)
	- `esp_now_comm` uses `espnow_message_t` (type, length, data) supporting payloads up to ~1600 bytes to carry Kyber public keys and ciphertexts or auth messages.

### Public API reference (high level)

PUF library (see `puf_lib.h`):
- `esp_err_t puflib_init(void);` — initialize PUF subsystem and NVS access.
- `esp_err_t enroll_puf(void);` — run enrollment routine to collect stable bits and helper data.
- `bool get_puf_response(void);` — reconstruct PUF response using helper data; populates `PUF_RESPONSE`.
- `esp_err_t derive_device_seed_simple(uint8_t seed_out[32]);` — derive 32-byte deterministic seed directly from SRAM PUF without enrollment.
- `esp_err_t store_enrollment_data(puf_enrollment_data_t* data);` / `esp_err_t load_enrollment_data(puf_enrollment_data_t* data);` — NVS helpers.

Authentication (`authentication.h`):
- `esp_err_t auth_init(void);` — initialize authentication subsystem.
- `auth_result_t authenticate_device(auth_message_t* auth_msg);` — run device-side authenticate routine (returns computed response in `auth_msg`).
- `bool verify_response(auth_message_t* auth_msg);` — verify a received response on GCC side.

Kyber helpers (`kyber_key_agreement.h`):
- `esp_err_t kyber_init(void);`
- `esp_err_t kyber_keygen(uint8_t *pk_out, uint8_t *sk_out);` — non-deterministic on GCC
- `esp_err_t kyber_keygen_deterministic(const uint8_t seed[32], uint8_t *pk_out, uint8_t *sk_out);` — deterministic keygen using PUF seed (UAV)
- `esp_err_t kyber_encaps(const uint8_t *pk, uint8_t *ct_out, uint8_t *ss_out);` (UAV encaps)
- `esp_err_t kyber_decaps(const uint8_t *sk, const uint8_t *ct, uint8_t *ss_out);` (GCC decaps)

ESP-NOW comms (`esp_now_comm.h`):
- `esp_err_t espnow_init(bool is_gcc);`
- `esp_err_t espnow_send_message(const uint8_t *peer_addr, espnow_message_t *msg);`
- `void espnow_set_recv_callback(void (*callback)(const uint8_t *mac, const uint8_t *data, int len));`

### Enrollment and provisioning

Two provisioning models are supported:

1. Zero-stored-key (no enrollment):
	- UAV derives a device seed on each boot using `derive_device_seed_simple()` and uses that seed for deterministic key generation. No helper data is stored.

2. Enrollment with helper data:
	- Run `enroll_puf()` on the UAV (this collects `NUM_ENROLLMENT_SAMPLES` and computes stable-bit indices and helper data).
	- Use `print_helper_data()` to print the helper data and stable indices to the console.
	- On GCC, call `enroll_new_uav(mac, helper_data)` (or extend to store to NVS) to add the UAV's helper data and MAC to the trusted database.

Practical steps to enroll a UAV (manual flow):

 - On UAV:
	1. Build and flash UAV firmware.
	2. Open monitor and run enrollment mode (project logs show enrollment steps) or create a small CLI that triggers `enroll_puf()`.
	3. Use `print_helper_data()` to copy the printed helper bytes.
 - On GCC:
	1. Add the UAV MAC and helper bytes into `enroll_new_uav()` call in `main_gcc.c` or call the function at runtime if you expose a command interface.
	2. Optionally modify the GCC code to persist enrolled entries to NVS for durability.

### Build, flash and monitor

From the project root (where `esp32_sram_puf` lives):

```powershell
cd "D:\NITK\Major_Project\esp32_sram_puf_V6_Complete - novelty\esp32_sram_puf"
idf.py set-target esp32
idf.py build
idf.py -p COM3 flash monitor
```

Replace `COM3` with your serial port. Use `idf.py monitor` to view runtime logs.

### Testing and debugging

- To run built-in PUF tests, compile with `-DENABLE_PUF_TESTS` enabled in `CMakeLists.txt` or add to your `sdkconfig` as needed.
- Logs: both `main_uav.c` and `main_gcc.c` include verbose logging (`ESP_LOGI/ESP_LOGE`) to help trace enrollment, challenge generation, response verification and Kyber flows.

### Security considerations

- Secrets: the design aims for a zero-stored-key model where keys derive from PUF at boot. Ensure `secure_zeroize()` is used for sensitive buffers and that the compiler does not optimize it away.
- Helper data: treat enrollment helper data as sensitive. If an attacker obtains helper data and can measure PUF outputs, they may reconstruct keys. Consider encrypting helper data at rest or using tamper-resistant storage.
- Replay protection: ensure challenges are random and large enough (current challenge size is defined in `authentication.h`), and consider adding timestamps and nonces to messages.
- Side-channel & fault attacks: hardware PUFs and deterministic key derivation can be subject to fault injection; consider adding tamper-detection or requiring physical access controls for enrollment.
- Firmware updates: be careful when updating firmware — if enrollment format changes, older helper data may become invalid.
