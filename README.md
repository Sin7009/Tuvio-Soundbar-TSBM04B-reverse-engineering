# Tuvio TSBM04B (Soundbar 5.1.2 Dolby Atmos) — Reverse Engineering & Firmware Analysis

[![SoC](https://img.shields.io/badge/SoC-Actions%20ATS2853-blue.svg)](https://www.actionstech.com/)
[![OS](https://img.shields.io/badge/RTOS-Zephyr-green.svg)](https://www.zephyrproject.org/)
[![Container](https://img.shields.io/badge/Format-Actions%20AOTA-orange.svg)]()
[![GitHub Pages](https://img.shields.io/badge/Live%20Studio-GitHub%20Pages-cyan.svg)](https://sin7009.github.io/Tuvio-Soundbar-TSBM04B-reverse-engineering/)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE)

🌐 **Live Configurator Studio:** [https://sin7009.github.io/Tuvio-Soundbar-TSBM04B-reverse-engineering/](https://sin7009.github.io/Tuvio-Soundbar-TSBM04B-reverse-engineering/)  
Источник прошивки: `TSBM04B-firmware.zip` (860 672 байта).

Репозиторий посвящён исследованию, разбору и модификации OTA-прошивки саундбара **Tuvio TSBM04B** (5.1.2 Dolby Atmos).

---

## 📌 Цели исследования

1. **Решение проблемы быстрого автоотключения (Auto-Standby):** Изменение таймаутов энергосбережения ErP и уровня чувствительности входящего аудиосигнала.
2. **Решение проблемы периодического отключения тыловых колонок:** Настройка таймаутов сопряжения и повторных попыток переподключения сателлитов (5.8GHz / 2.4GHz RF).
3. **Полный реверс-инжиниринг контейнера AOTA и исполняемого кода Zephyr RTOS.**

---

## 🛠️ Спецификация устройства и образа

| Параметр | Значение |
|---|---|
| **Устройство** | Tuvio Soundbar 5.1.2 Dolby Atmos (TSBM04B) |
| **SoC** | Actions Technology ATS2853 (Bluetooth/Audio SoC) |
| **ОС** | Zephyr RTOS (Actions ZS285A SDK) |
| **Имя платы** | `ats2853_dvb` (референсная плата Actions) |
| **Версия прошивки** | `2.00_2605191448` (Version Code: `0x20007`) |
| **Магия контейнера** | `AOTA` (Actions Over-The-Air) |

---

## 📦 Структура контейнера AOTA

Устройство использует формат контейнера Actions Technology. Целостность образа контролируется **только по контрольным суммам CRC32** (7 полей CRC32). Внешние подписи RSA/ECDSA в заголовке контейнера отсутствуют.

```
0x000  'AOTA' (Magic Header)
0x004  u32   crc32(0x008..0x400) — заголовок + каталог
0x00c  u32   число файлов (5)
0x014  u32   полный размер образа
0x018  u32   crc32(0x400..EOF) — область данных
0x040  char[32]  version_name (2.00_2605191448)
0x060  char[28]  board_name (ats2853_dvb)
0x07c  u32   version_code (0x20007)
0x200  таблица файлов (запись 32 байта: name[16], offset, size, resv, crc32)
```

### Разделы прошивки

| Раздел | Offset | Размер | Описание |
|---|---|---|---|
| `ota.xml` | `0x000400` | 1 088 B | Манифест прошивки (открытый текст XML) |
| `zephyr.bin` | `0x000a00` | 822 304 B | `fw0_sys` — Код приложения Zephyr RTOS |
| `sdfs.bin` | `0x0c9800` | 30 720 B | `fw0_sdfs` — Специфичный файловый архив SDFS (профили DSP) |
| `mbrec.bin` | `0x0d1000` | 4 096 B | `fw0_boot` — Двухэтапный первичное ядро загрузчика |
| `param.bin` | `0x0d2000` | 512 B | `sys_param0` | Таблица системных параметров флеш-памяти |

---

## 🔐 Шифрование и обфускация

Исследование выявило 2 уровня защиты прошивки:

### 1. Уровень 1: XOR-whitening (Маска 32 байта)
Все разделы прошивки (кроме `ota.xml`) скрыты под статичной 32-байтовой XOR-маской:
```hex
a1662b968ae2403342a4ed7b31e5bf9ad69be2637003c5ff7bd173457a90d52a
```
Снятие маски восстанавливает заголовки `sdfs`, `ACTH` и `ACPV`.

### 2. Уровень 2: Двухэтапная структура загрузчика `ACTH`
Файл `mbrec.bin` содержит два суб-образа `ACTH`:
* **Stage 1 (`0x0000`):** Boot ROM Loader.
* **Stage 2 (`0x06c4`):** Основной загрузчик саундбара, содержащий алгоритм дескрэмблирования и декомпрессии кода приложения `zephyr.bin` (двухполублочная 32-байтная архитектура).

---

## 🚀 Использование инструментов

### 1. Распаковка и пересборка контейнера AOTA (`aota_tool.py`)
Утилита распаковывает `ota.bin` со снятием XOR-маски и позволяет пересобрать его с автоматическим пересчётом всех 7 контрольных сумм CRC32:

```bash
# Распаковка прошивки
python3 aota_tool.py unpack ota.bin outdir/

# Пересборка прошивки
python3 aota_tool.py repack outdir/ new_ota.bin
```

### 2. Извлечение исполняемого кода `zephyr.bin` (`unpack_zephyr.py`)
Утилита декомпрессии и анализа векторов ARM Thumb-2 из загруженника `zephyr.bin`:

```bash
python3 unpack_zephyr.py dec/zephyr.bin unpacked/
```

---

## 💾 Инструкция по обновлению на саундбаре

1. Отформатируйте USB-флешку (до 32 ГБ) в файловую систему **FAT32**.
2. Положите файл `ota.bin` в корень флешки (других файлов быть не должно).
3. Полностью выключите саундбар из розетки (220V).
4. Вставьте флешку в USB-порт саундбара.
5. Включите саундбар в розетку. На экране появится надпись **`UP`** (Updating).
6. Дождитесь надписи **`OK`** (~30–60 секунд).
7. Извлеките флешку и перезагрузите устройство.

---

## 📜 Лицензия

Этот проект распространяется под лицензией MIT. Разработано в исследовательских и образовательных целях.
