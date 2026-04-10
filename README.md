# NetStego — стеганографическое сокрытие данных в сетевых пакетах

Система для передачи данных через скрытые каналы в протоколах TCP/IP с шифрованием AES-256-GCM и многоуровневым модулем обнаружения.

## Возможности

- Передача файлов и текстовых сообщений через 5 стеганографических каналов
- Шифрование AES-256-GCM с протоколом фрагментации NST (CRC32, SHA-256)
- Обнаружение скрытых каналов: статистика + ML (Isolation Forest, Random Forest) + сигнатуры
- Анализ payload на вредоносные вложения (20 сигнатур в 7 категориях)
- Поддержка избыточности для устойчивости к потере пакетов
- Работа в двух режимах: реальная отправка по сети и dry-run (только PCAP)
- Автоматизированные бенчмарки и генерация графиков

## Стеганографические каналы

| Канал | Поле-носитель | Бит/пакет | Скрытность |
|-------|--------------|-----------|------------|
| ICMP Payload | Payload ICMP Echo Request | 11776 | Низкая |
| DNS QNAME | Поддомен DNS-запроса (base32) | 240 | Средняя |
| TCP ISN | TCP Sequence Number (SYN) | 32 | Высокая |
| TCP Timestamp | TCP TSval Option | 32 | Высокая |
| IP ID | IPv4 Identification | 16 | Высокая |

## Установка

```bash
pip install -e .
```

Требования: Python 3.11+, Npcap (Windows) или CAP_NET_RAW (Linux) для работы с сетью.

## Режимы работы

### Режим реальной передачи по сети

Требует права администратора и установленный Npcap (Windows) / libpcap (Linux).

```bash
# Генерация ключа
netstego keygen --output key.bin

# Отправка файла
netstego send --file secret.txt --channel icmp --dest 192.168.1.100 --key-file key.bin

# Отправка текста
netstego send --text "Hello" --channel dns --dest 192.168.1.100 --key-file key.bin

# Приём в реальном времени
netstego receive --channel icmp --sender-ip 192.168.1.50 --key-file key.bin --output received.txt
```

### Режим dry-run (без сети)

Пакеты формируются полностью (шифрование, фрагментация, кодирование), сохраняются в PCAP, но не отправляются по сети. Приём выполняется из PCAP-файла.

```bash
# Отправка (dry-run) — пакеты сохраняются в PCAP
netstego send --text "Secret message" --channel icmp --dest 127.0.0.1 --key-file key.bin --pcap-out packets.pcap --dry-run

# Приём из PCAP
netstego receive --channel icmp --sender-ip 127.0.0.1 --key-file key.bin --output received.txt --pcap-in packets.pcap
```

### Обнаружение скрытых каналов

```bash
netstego detect --input traffic.pcap --report report.json
```

Методы анализа:
- Статистический (энтропия Шеннона, хи-квадрат, KS-тест, анализ IPD, IP ID, TSval, DNS QNAME, ICMP payload)
- ML: Isolation Forest (unsupervised, 9 признаков), Random Forest (supervised)
- Сигнатурный (протокол NST, base32, length prefix)
- Анализ payload (PE, ELF, скрипты, шеллкод, архивы, макро-документы)

### Устойчивость к потере пакетов

```bash
netstego send --file data.bin --channel icmp --dest 192.168.1.100 --key-file key.bin --redundancy 3
```

Каждый чанк дублируется N раз. Приёмник дедуплицирует по номеру. Восстановление при потере до 20% пакетов (при 3x избыточности).

### Бенчмарки и отчёты

```bash
netstego report --output-dir results
netstego benchmark --channel icmp --dest 127.0.0.1
netstego stats
```

## Производительность

| Канал | Пакетов (1 КБ) | Обработка | Пропускная способность |
|-------|----------------|-----------|----------------------|
| ICMP Payload | 1 | 0.62 мс | 1 668 169 Б/с |
| DNS QNAME | 44 | 15.8 мс | 64 982 Б/с |
| TCP ISN | 320 | 44.3 мс | 23 116 Б/с |
| TCP Timestamp | 320 | 63.2 мс | 19 184 Б/с |
| IP ID | 638 | 316.5 мс | 3 238 Б/с |

## Структура проекта

```
netstego/
  cli.py                 — точка входа CLI (7 команд)
  config.py              — модели конфигурации (Pydantic)
  benchmarks.py          — бенчмарки и мониторинг обнаружения
  core/
    crypto.py            — AES-256-GCM, Argon2id KDF
    fragmentation.py     — протокол NST (17-байт заголовок, CRC32, SHA-256)
    reassembly.py        — сборка чанков (out-of-order, дедупликация)
  channels/
    base.py              — абстрактный StegoChannel
    icmp_payload.py      — ICMP Payload (1470 Б/пакет)
    ip_id.py             — IP ID (2 Б/пакет)
    tcp_isn.py           — TCP ISN (4 Б/пакет)
    dns_query.py         — DNS QNAME base32 (30 Б/пакет)
    tcp_timestamp.py     — TCP Timestamp (4 Б/пакет)
  network/
    sender.py            — конвейер отправки (dry-run, redundancy)
    receiver.py          — конвейер приёма (live/PCAP)
  detection/
    analyzer.py          — оркестратор обнаружения
    statistical.py       — 9 статистических тестов
    ml_detector.py       — Isolation Forest + Random Forest
    signatures.py        — сигнатурный поиск + анализ payload
  stats/
    collector.py         — сбор метрик (SQLite)
    reporter.py          — экспорт (JSON, CSV, HTML)
    charts.py            — генерация графиков (Matplotlib)
tests/                   — 269 тестов (134 unit + 68 integration + 67 integrity)
diploma/                 — текст дипломной работы (LaTeX)
```

## Тестирование

```bash
python -m pytest tests/ -v
```

## Команды CLI

| Команда | Описание |
|---------|----------|
| `keygen` | Генерация 256-битного ключа AES |
| `send` | Шифрование, фрагментация и отправка данных |
| `receive` | Приём, сборка и расшифровка данных |
| `detect` | Анализ трафика на скрытые каналы |
| `stats` | Просмотр статистики сессий |
| `benchmark` | Бенчмарк канала |
| `report` | Полные бенчмарки + графики + отчёты |
