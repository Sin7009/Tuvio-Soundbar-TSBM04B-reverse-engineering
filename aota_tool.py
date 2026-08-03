#!/usr/bin/env python3
"""
Распаковщик/дешифратор OTA-прошивок Actions Technology ATS285x (магия 'AOTA').
Проверено на: Tuvio TSBM04B (soundbar 5.1.2), fw 2.00_2605191448, board ats2853_dvb.

Контейнер:
  0x000  'AOTA'
  0x004  u32  crc32(0x008..0x400) — заголовок + каталог
  0x00c  u32  число файлов
  0x014  u32  полный размер образа
  0x018  u32  crc32(0x400..EOF) — вся область данных
  0x040  char[32]  version_name
  0x060  char[28]  board_name
  0x07c  u32  version_code
  0x200  таблица файлов, запись 32 байта:
           char[16] имя, u32 offset, u32 size, u32 reserved, u32 crc32

Полезная нагрузка (кроме ota.xml) обфусцирована статичной 32-байтной XOR-маской.
Маска восстановлена двумя независимыми способами (повторяющиеся padding-блоки
и частотный анализ по классам остатков mod 32) и совпала побайтово.

Целостность образа — ТОЛЬКО CRC32 (7 полей). Подписи в контейнере нет:
0x01c..0x040 и 0x2a0..0x400 — нули. Пересборка проверена: unpack -> repack
даёт бит-в-бит исходный файл.

Использование:
  python3 aota_tool.py unpack ota.bin outdir/
  python3 aota_tool.py repack outdir/ new_ota.bin

ВНИМАНИЕ: repack пересчитывает CRC, но НЕ решает главных проблем —
код в zephyr.bin упакован вендорским способом и не редактируется, а
загрузчик может проверять образ собственными средствами. Прошивка
модифицированного образа может привести к неработоспособности устройства.
"""
import os, struct, sys, zlib

XOR_KEY = bytes.fromhex(
    'a1662b968ae2403342a4ed7b31e5bf9a'
    'd69be2637003c5ff7bd173457a90d52a'
)

def unxor(data: bytes) -> bytes:
    k = XOR_KEY
    return bytes(b ^ k[i % 32] for i, b in enumerate(data))

def unpack(path, outdir):
    d = open(path, 'rb').read()
    if d[:4] != b'AOTA':
        sys.exit('не AOTA-образ: magic=%r' % d[:4])

    nfiles   = struct.unpack('<I', d[0x0c:0x10])[0]
    total    = struct.unpack('<I', d[0x14:0x18])[0]
    version  = d[0x40:0x60].split(b'\0')[0].decode()
    board    = d[0x60:0x7c].split(b'\0')[0].decode()
    vercode  = struct.unpack('<I', d[0x7c:0x80])[0]

    print('version_name : %s' % version)
    print('board_name   : %s' % board)
    print('version_code : 0x%05x' % vercode)
    print('files        : %d' % nfiles)
    print('size         : %d (заявлено) / %d (фактически) %s'
          % (total, len(d), 'OK' if total == len(d) else 'MISMATCH'))
    print()

    os.makedirs(os.path.join(outdir, 'raw'), exist_ok=True)
    os.makedirs(os.path.join(outdir, 'dec'), exist_ok=True)

    open(os.path.join(outdir, 'raw', '_container.bin'), 'wb').write(d)

    for i in range(nfiles):
        e = d[0x200 + i * 32: 0x200 + (i + 1) * 32]
        name = e[:16].split(b'\0')[0].decode()
        off, size, resv, crc = struct.unpack('<IIII', e[16:32])
        blob = d[off:off + size]
        ok = (zlib.crc32(blob) & 0xffffffff) == crc
        print('%-12s off=0x%07x size=0x%06x crc32=0x%08x %s'
              % (name, off, size, crc, 'OK' if ok else 'BAD'))
        open(os.path.join(outdir, 'raw', name), 'wb').write(blob)
        # ota.xml лежит в открытом виде, остальное — под XOR-маской
        dec = blob if name == 'ota.xml' else unxor(blob)
        open(os.path.join(outdir, 'dec', name), 'wb').write(dec)

def repack(indir, outpath):
    """Собирает образ из <indir>/dec/, пересчитывая все 7 CRC32."""
    src = os.path.join(indir, 'raw', '_container.bin')
    if not os.path.exists(src):
        sys.exit('нет %s — распакуйте образ этой же версией инструмента' % src)
    out = bytearray(open(src, 'rb').read())

    nfiles = struct.unpack('<I', out[0x0c:0x10])[0]
    for i in range(nfiles):
        e = 0x200 + i * 32
        name = bytes(out[e:e + 16]).split(b'\0')[0].decode()
        off, size = struct.unpack('<II', out[e + 16:e + 24])
        new = open(os.path.join(indir, 'dec', name), 'rb').read()
        # ota.xml хранится открытым, остальное — под XOR-маской
        if name != 'ota.xml':
            new = unxor(new)
        if len(new) != size:
            sys.exit('%s: размер изменился (%d -> %d); таблицу смещений '
                     'придётся перестраивать вручную' % (name, size, len(new)))
        out[off:off + size] = new
        struct.pack_into('<I', out, e + 28, zlib.crc32(new) & 0xffffffff)
        print('%-12s size=0x%06x crc32=0x%08x' % (name, size, zlib.crc32(new) & 0xffffffff))

    struct.pack_into('<I', out, 0x14, len(out))
    struct.pack_into('<I', out, 0x18, zlib.crc32(out[0x400:]) & 0xffffffff)
    struct.pack_into('<I', out, 0x04, zlib.crc32(out[8:0x400]) & 0xffffffff)
    open(outpath, 'wb').write(out)
    print('\nзаписано %s (%d байт)' % (outpath, len(out)))

if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'unpack':
        unpack(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == 'repack':
        repack(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
