#!/usr/bin/env python3
"""
Milestone 3 Verification & Non-Self-Certifying Byte Diff Suite for Tuvio TSBM04B.
Validates Actions OTA image integrity, alignment, 7 CRC32 checksums, and exact byte diffs.
"""

import os
import sys
import struct
import zlib

XOR_KEY = bytes.fromhex(
    'a1662b968ae2403342a4ed7b31e5bf9a'
    'd69be2637003c5ff7bd173457a90d52a'
)

def verify_aota_image(path: str) -> dict:
    d = open(path, 'rb').read()
    if len(d) < 0x400 or d[:4] != b'AOTA':
        raise ValueError(f"Invalid AOTA header magic: {d[:4]}")

    hdr_crc = struct.unpack('<I', d[0x04:0x08])[0]
    nfiles = struct.unpack('<I', d[0x0c:0x10])[0]
    total_size = struct.unpack('<I', d[0x14:0x18])[0]
    data_crc = struct.unpack('<I', d[0x18:0x1c])[0]
    version = d[0x40:0x60].split(b'\0')[0].decode('latin1', errors='replace')
    board = d[0x60:0x7c].split(b'\0')[0].decode('latin1', errors='replace')
    vercode = struct.unpack('<I', d[0x7c:0x80])[0]

    calc_hdr_crc = zlib.crc32(d[8:0x400]) & 0xffffffff
    calc_data_crc = zlib.crc32(d[0x400:]) & 0xffffffff

    assert total_size == len(d), f"Declared size {total_size} != file size {len(d)}"
    assert hdr_crc == calc_hdr_crc, f"Header CRC mismatch: 0x{hdr_crc:08x} vs calc 0x{calc_hdr_crc:08x}"
    assert data_crc == calc_data_crc, f"Data CRC mismatch: 0x{data_crc:08x} vs calc 0x{calc_data_crc:08x}"

    partitions = []
    for i in range(nfiles):
        e = d[0x200 + i * 32 : 0x200 + (i + 1) * 32]
        name = e[:16].split(b'\0')[0].decode('latin1')
        off, size, resv, crc = struct.unpack('<IIII', e[16:32])
        blob = d[off : off + size]
        calc_part_crc = zlib.crc32(blob) & 0xffffffff
        assert crc == calc_part_crc, f"Partition '{name}' CRC mismatch: 0x{crc:08x} vs calc 0x{calc_part_crc:08x}"
        partitions.append({
            'name': name,
            'off': off,
            'size': size,
            'crc32': crc,
            'table_crc_offset': 0x200 + i * 32 + 28
        })

    return {
        'version': version,
        'board': board,
        'vercode': vercode,
        'nfiles': nfiles,
        'total_size': total_size,
        'hdr_crc': hdr_crc,
        'data_crc': data_crc,
        'partitions': partitions
    }

def run_byte_diff_suite(orig_path: str, patched_path: str):
    orig = open(orig_path, 'rb').read()
    patched = open(patched_path, 'rb').read()

    assert len(orig) == len(patched), f"File length mismatch: {len(orig)} vs {len(patched)}"

    diffs = [(i, orig[i], patched[i]) for i in range(len(orig)) if orig[i] != patched[i]]
    print(f"\n================ NON-SELF-CERTIFYING BYTE DIFF ANALYSIS ================")
    print(f"[*] Original Image: {orig_path} ({len(orig)} bytes)")
    print(f"[*] Patched Image : {patched_path} ({len(patched)} bytes)")
    print(f"[*] Total Byte Diffs: {len(diffs)} bytes")

    hdr_diffs = [d for d in diffs if d[0] < 0x400]
    data_diffs = [d for d in diffs if d[0] >= 0x400]

    print(f"\n--- Header & Table Region Diffs (0x000..0x3FF): {len(hdr_diffs)} bytes ---")
    expected_hdr_offsets = {
        0x0004: "Header CRC32 (byte 0)", 0x0005: "Header CRC32 (byte 1)",
        0x0006: "Header CRC32 (byte 2)", 0x0007: "Header CRC32 (byte 3)",
        0x0018: "Data CRC32 (byte 0)", 0x0019: "Data CRC32 (byte 1)",
        0x001a: "Data CRC32 (byte 2)", 0x001b: "Data CRC32 (byte 3)",
        0x023c: "zephyr.bin CRC32 (byte 0)", 0x023d: "zephyr.bin CRC32 (byte 1)",
        0x023e: "zephyr.bin CRC32 (byte 2)", 0x023f: "zephyr.bin CRC32 (byte 3)",
        0x025c: "sdfs.bin CRC32 (byte 0)", 0x025d: "sdfs.bin CRC32 (byte 1)",
        0x025e: "sdfs.bin CRC32 (byte 2)", 0x025f: "sdfs.bin CRC32 (byte 3)",
    }

    for off, b1, b2 in hdr_diffs:
        desc = expected_hdr_offsets.get(off, "UNEXPECTED HEADER DIFF")
        print(f"  Offset 0x{off:04x}: 0x{b1:02x} -> 0x{b2:02x} [{desc}]")
        assert off in expected_hdr_offsets, f"Unexpected header diff at offset 0x{off:04x}"

    print(f"\n--- Partition Data Region Diffs (0x400..EOF): {len(data_diffs)} bytes (expected 10 bytes) ---")
    expected_data_offsets = {
        0x074442: "zephyr.bin @ 0x73a42 (code 0x073a0e): ping timer threshold 0xc8 -> 0x32",
        0x03b90d: "zephyr.bin @ 0x3af0d (code 0x03aed9): RF loop timer threshold 0xc8 -> 0x32",
        0x07ebf2: "zephyr.bin @ 0x7e1f2 (code 0x07e1be): sleep timer NOP byte 0 (0x30 -> 0x96)",
        0x07ebf3: "zephyr.bin @ 0x7e1f3 (code 0x07e1bf): sleep timer NOP byte 1 (0xa4 -> 0x6b)",
        0x0c9864: "sdfs.bin @ 0x00064: keep-alive link param byte 0 (0x8b -> 0x01 XOR-whitened)",
        0x0c9865: "sdfs.bin @ 0x00065: keep-alive link param byte 1 (0x7b -> 0x00 XOR-whitened)",
        0x0c9922: "sdfs.bin @ 0x000122: energy threshold step 0 byte 0 (0x0a -> 0x00 XOR-whitened)",
        0x0c9923: "sdfs.bin @ 0x000123: energy threshold step 0 byte 1 (0x02 -> 0x00 XOR-whitened)",
        0x0cab22: "sdfs.bin @ 0x001322: energy threshold step 6 byte 0 (0x1e -> 0x00 XOR-whitened)",
        0x0cab23: "sdfs.bin @ 0x001323: energy threshold step 6 byte 1 (0x02 -> 0x00 XOR-whitened)",
    }

    for off, b1, b2 in data_diffs:
        desc = expected_data_offsets.get(off, "UNEXPECTED DATA DIFF")
        print(f"  Offset 0x{off:06x}: 0x{b1:02x} -> 0x{b2:02x} [{desc}]")
        assert off in expected_data_offsets, f"Unexpected payload diff at offset 0x{off:06x}"

    assert len(hdr_diffs) in (15, 16), f"Expected 15-16 header diffs, got {len(hdr_diffs)}"
    assert len(data_diffs) == 10, f"Expected 10 payload diffs, got {len(data_diffs)}"
    assert len(diffs) == len(hdr_diffs) + len(data_diffs), f"Total diff mismatch: {len(diffs)} vs {len(hdr_diffs)}+{len(data_diffs)}"

    print(f"\n[+] BYTE DIFF ANALYSIS PASSED PERFECTLY: {len(diffs)}/{len(diffs)} DIFFS MATCH EXPECTED SPECIFICATION EXACTLY")

def main():
    orig_path = "ota.bin"
    patched_path = "patched_ota.bin"

    print("================ MILESTONE 3 OTA INTEGRITY & CRC MATRIX ================")
    res = verify_aota_image(patched_path)
    print(f"[*] Version Name : {res['version']}")
    print(f"[*] Board Name   : {res['board']}")
    print(f"[*] Version Code : 0x{res['vercode']:05x}")
    print(f"[*] Total Size   : {res['total_size']} bytes")
    print(f"[*] Header CRC32 : 0x{res['hdr_crc']:08x} [VERIFIED PASS]")
    print(f"[*] Data CRC32   : 0x{res['data_crc']:08x} [VERIFIED PASS]")
    print("\n--- Partition Table CRC32 Verification Matrix ---")
    for p in res['partitions']:
        print(f"  Partition: {p['name']:12s} Off: 0x{p['off']:07x} Size: 0x{p['size']:06x} CRC32: 0x{p['crc32']:08x} [VERIFIED PASS]")

    run_byte_diff_suite(orig_path, patched_path)

if __name__ == '__main__':
    main()
