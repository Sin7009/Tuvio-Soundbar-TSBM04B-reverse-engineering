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
  python3 aota_tool.py unpack ota.bin [outdir]
  python3 aota_tool.py repack outdir/ new_ota.bin
  python3 aota_tool.py verify ota.bin
"""
import os, struct, sys, zlib

XOR_KEY = bytes.fromhex(
    'a1662b968ae2403342a4ed7b31e5bf9a'
    'd69be2637003c5ff7bd173457a90d52a'
)

def unxor(data: bytes) -> bytes:
    k = XOR_KEY
    return bytes(b ^ k[i % 32] for i, b in enumerate(data))

def unpack(path, outdir=None):
    d = open(path, 'rb').read()
    if d[:4] != b'AOTA':
        sys.exit('не AOTA-образ: magic=%r' % d[:4])

    hdr_crc  = struct.unpack('<I', d[0x04:0x08])[0]
    nfiles   = struct.unpack('<I', d[0x0c:0x10])[0]
    total    = struct.unpack('<I', d[0x14:0x18])[0]
    data_crc = struct.unpack('<I', d[0x18:0x1c])[0]
    version  = d[0x40:0x60].split(b'\0')[0].decode()
    board    = d[0x60:0x7c].split(b'\0')[0].decode()
    vercode  = struct.unpack('<I', d[0x7c:0x80])[0]

    calc_hdr_crc  = zlib.crc32(d[8:0x400]) & 0xffffffff
    calc_data_crc = zlib.crc32(d[0x400:]) & 0xffffffff

    print('version_name : %s' % version)
    print('board_name   : %s' % board)
    print('version_code : 0x%05x' % vercode)
    print('files        : %d' % nfiles)
    print('size         : %d (заявлено) / %d (фактически) %s'
          % (total, len(d), 'OK' if total == len(d) else 'MISMATCH'))
    print('header_crc32 : 0x%08x %s' % (hdr_crc, 'OK' if hdr_crc == calc_hdr_crc else 'BAD (expected 0x%08x)' % calc_hdr_crc))
    print('data_crc32   : 0x%08x %s' % (data_crc, 'OK' if data_crc == calc_data_crc else 'BAD (expected 0x%08x)' % calc_data_crc))
    print()

    if outdir:
        os.makedirs(os.path.join(outdir, 'raw'), exist_ok=True)
        os.makedirs(os.path.join(outdir, 'dec'), exist_ok=True)
        open(os.path.join(outdir, 'raw', '_container.bin'), 'wb').write(d)

    all_ok = (hdr_crc == calc_hdr_crc) and (data_crc == calc_data_crc) and (total == len(d))

    for i in range(nfiles):
        e = d[0x200 + i * 32: 0x200 + (i + 1) * 32]
        name = e[:16].split(b'\0')[0].decode()
        off, size, resv, crc = struct.unpack('<IIII', e[16:32])
        blob = d[off:off + size]
        ok = (zlib.crc32(blob) & 0xffffffff) == crc
        if not ok:
            all_ok = False
        print('%-12s off=0x%07x size=0x%06x crc32=0x%08x %s'
              % (name, off, size, crc, 'OK' if ok else 'BAD'))
        if outdir:
            open(os.path.join(outdir, 'raw', name), 'wb').write(blob)
            # ota.xml лежит в открытом виде, остальное — под XOR-маской
            dec = blob if name == 'ota.xml' else unxor(blob)
            open(os.path.join(outdir, 'dec', name), 'wb').write(dec)

    if not all_ok:
        sys.exit('ОШИБКА: Проверка CRC32 или структуры не пройдена!')
    elif not outdir:
        print('\n=== ВСЕ 7 КОНТРОЛЬНЫХ СУММ CRC32 И СТРУКТУРА КОНТЕЙНЕРА УСПЕШНО ПРОВЕРЕНЫ ===')

def repack(indir, outpath):
    """Собирает образ из <indir>/dec/ или patched/, пересчитывая все 7 CRC32."""
    src_candidates = [
        os.path.join(indir, 'raw', '_container.bin'),
        os.path.join(indir, '_container.bin'),
        'raw/_container.bin',
        'ota_work/raw/_container.bin',
        'ota.bin'
    ]
    src = None
    for cand in src_candidates:
        if os.path.exists(cand):
            src = cand
            break
    if not src:
        sys.exit('нет контейнера — распакуйте исходный образ ota.bin')

    out = bytearray(open(src, 'rb').read())
    nfiles = struct.unpack('<I', out[0x0c:0x10])[0]

    for i in range(nfiles):
        e = 0x200 + i * 32
        name = bytes(out[e:e + 16]).split(b'\0')[0].decode()
        off, size = struct.unpack('<II', out[e + 16:e + 24])

        # Ищем файл в порядке приоритета
        file_candidates = [
            os.path.join(indir, 'dec', name),
            os.path.join(indir, 'dec_' + name),
            os.path.join(indir, 'raw_' + name),
            os.path.join(indir, name),
            os.path.join('patched', 'dec_' + name),
            os.path.join('patched', 'raw_' + name),
            os.path.join('dec', name),
            os.path.join('raw', name)
        ]
        part_data = None
        chosen_path = None
        for cand in file_candidates:
            if os.path.exists(cand):
                part_data = open(cand, 'rb').read()
                chosen_path = cand
                break

        if part_data is None:
            sys.exit('Файл раздела %s не найден ни по одному из путей!' % name)

        # Определяем, расшифрован ли файл (Layer 1 XOR)
        if name != 'ota.xml' and (part_data.startswith(b'ACTH') or part_data.startswith(b'sdfs') or 'dec' in os.path.basename(chosen_path) or 'dec' in chosen_path.split(os.sep)):
            raw_blob = unxor(part_data)
        else:
            raw_blob = part_data

        if len(raw_blob) != size:
            sys.exit('%s: размер изменился (%d -> %d); таблицу смещений придётся перестраивать' % (name, size, len(raw_blob)))

        out[off:off + size] = raw_blob
        crc32_val = zlib.crc32(raw_blob) & 0xffffffff
        struct.pack_into('<I', out, e + 28, crc32_val)
        print('%-12s size=0x%06x crc32=0x%08x [из %s]' % (name, size, crc32_val, chosen_path))

    struct.pack_into('<I', out, 0x14, len(out))
    struct.pack_into('<I', out, 0x18, zlib.crc32(out[0x400:]) & 0xffffffff)
    struct.pack_into('<I', out, 0x04, zlib.crc32(out[8:0x400]) & 0xffffffff)
    open(outpath, 'wb').write(out)
    print('\nзаписано %s (%d байт)' % (outpath, len(out)))

def parse_args():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)

    cmd = args[0]
    if cmd in ('verify',):
        if len(args) < 2:
            sys.exit('Укажите путь к OTA-файлу для verify')
        return 'verify', args[1], None
    elif cmd in ('unpack',):
        outdir = 'unpacked'
        path = None
        i = 1
        while i < len(args):
            if args[i] == '--outdir' and i + 1 < len(args):
                outdir = args[i + 1]
                i += 2
            elif not path:
                path = args[i]
                i += 1
            else:
                outdir = args[i]
                i += 1
        if not path:
            sys.exit('Укажите путь к OTA-файлу для unpack')
        return 'unpack', path, outdir
    elif cmd in ('repack', 'pack'):
        if len(args) < 3:
            sys.exit('Использование: python3 aota_tool.py pack <indir> <outpath>')
        return 'repack', args[1], args[2]
    else:
        sys.exit(__doc__)

if __name__ == '__main__':
    mode, arg1, arg2 = parse_args()
    if mode in ('unpack', 'verify'):
        unpack(arg1, arg2)
    elif mode == 'repack':
        repack(arg1, arg2)


