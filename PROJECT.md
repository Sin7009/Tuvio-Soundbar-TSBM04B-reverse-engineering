# Project: Tuvio TSBM04B Firmware RE & Patching

## Mission
Reverse engineer, unpack, patch, and repack the Tuvio TSBM04B soundbar OTA firmware (Actions ATS2853 / Zephyr RTOS) to fix auto-standby threshold timeout and rear satellite speaker disconnects.

## Architecture & Binary Formats
- **SoC**: Actions ATS2853 (ARM Cortex-M4 / Thumb-2, Zephyr RTOS base)
- **Container**: Actions OTA Container (`AOTA` magic, 32-byte header, file table at 0x200, 7 CRC32 checksums)
- **Layer 1 Obfuscation**: 32-byte static XOR whitening mask across partitions (`sdfs.bin`, `zephyr.bin`, `mbrec.bin`, `param.bin`).
- **Layer 2 Vendor Format**: `zephyr.bin` and `mbrec.bin` use vendor container header (`ACTH` magic + `4ad14d5d` / compression / encryption payload).
- **DSP & Config**: `sdfs.bin` contains 9 SDFS resource entries and DSP parameter tables (0x300 byte step profiles).

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | Firmware Decryption & Unpacking Tooling | Analyze `mbrec.bin` & `zephyr.bin` vendor `ACTH` header/payload, develop Python unpacker (`unpack_zephyr.py`) producing valid Thumb-2 code | None | IN_PROGRESS |
| 2 | Reverse Engineering & Binary Patching | Analyze ARM Thumb-2 binary & `sdfs.bin` tables, locate auto-standby audio energy threshold and rear speaker keep-alive logic, develop `patch_firmware.py` | M1 | PLANNED |
| 3 | OTA Repacking & Verification | Repack modified partitions into `ota.bin` via `aota_tool.py`, recalculate all CRC32 checksums, verify bit-exact structure | M2 | PLANNED |

## Interface Contracts
- **`unpack_zephyr.py`**:
  Input: `dec/zephyr.bin` (or `raw/zephyr.bin`) & `dec/mbrec.bin`
  Output: `unpacked/zephyr_code.bin` / `unpacked/zephyr.elf` (valid Thumb-2 instructions)
- **`patch_firmware.py`**:
  Input: Unpacked firmware and/or `dec/sdfs.bin`
  Output: Patched binary and repacked `dec/zephyr.bin`
- **`aota_tool.py`**:
  Input: `dec/` directory
  Output: `new_ota.bin` (valid Actions OTA image passing all CRC32 checks)

## Code Layout
- `raw/`: Raw extracted OTA partitions
- `dec/`: XOR-decrypted OTA partitions
- `unpack_zephyr.py`: Python script for `ACTH` / Actions ATS2853 payload extraction
- `patch_firmware.py`: Patching script for auto-standby threshold and rear satellite keep-alive
- `aota_tool.py`: OTA container unpack/repack utility
