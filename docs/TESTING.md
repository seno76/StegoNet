# Руководство по тестированию NetStego

Пошаговая инструкция: от установки до передачи данных между двумя машинами
с анализом в Wireshark.

---

## Часть 1. Установка и подготовка

### Требования (на обеих машинах)

1. **Python 3.11+** -- https://python.org
2. **Npcap** (Windows) -- https://npcap.com, при установке включить "WinPcap API-compatible Mode"
3. **Wireshark** -- https://wireshark.org (для анализа)
4. **Права администратора** -- запускать терминал от имени администратора

### Установка (на обеих машинах)

```bash
# Распаковать архив проекта, перейти в папку
cd DiplomaStegano

# Установить программу и зависимости
pip install -e .

# Проверить установку
netstego --version
```

### Генерация общего ключа шифрования

Ключ генерируется **один раз** и копируется на обе машины:

```bash
netstego keygen --output demo.key
```

Скопируйте файл `demo.key` на вторую машину (флешка, scp, любой способ).
Без одинакового ключа расшифровка невозможна.

### Определение IP-адресов

На каждой машине узнайте свой IP:

```bash
# Windows
ipconfig

# Linux
ip addr
```

Допустим:
- **Машина A (отправитель):** `192.168.1.10`
- **Машина B (получатель):** `192.168.1.20`

Проверьте связь:
```bash
# На машине A
ping 192.168.1.20
```

---

## Часть 2. Передача данных по сети (два компьютера)

### Сценарий: отправка текста через ICMP

**Шаг 1. На машине B (получатель) -- запустить приём:**

```bash
netstego receive --channel icmp --sender-ip 192.168.1.10 --key-file demo.key --output received.txt --timeout 120
```

Программа начнёт слушать сеть и ждать пакеты от 192.168.1.10.

**Шаг 2. На машине A (отправитель) -- отправить данные:**

```bash
netstego send --text "Секретное сообщение" --channel icmp --dest 192.168.1.20 --key-file demo.key --pcap-out sent.pcap
```

**Шаг 3. На машине B -- результат:**

```
Received chunk 0/1
All 1 chunks received
Reassembled: XX bytes
Decrypted successfully
Output saved to received.txt
```

Проверка:
```bash
cat received.txt
# Секретное сообщение
```

### Сценарий: отправка файла через DNS

**На машине B:**
```bash
netstego receive --channel dns --sender-ip 192.168.1.10 --key-file demo.key --output received_file.txt --timeout 120
```

**На машине A:**
```bash
netstego send --file secret.txt --channel dns --dest 192.168.1.20 --key-file demo.key --pcap-out dns_sent.pcap
```

### Сценарий: все 5 каналов

| Канал | Флаг `--channel` | Что скрывается | Скрытность |
|-------|-------------------|----------------|------------|
| ICMP Payload | `icmp` | Данные в теле ping-пакета | Низкая |
| DNS QNAME | `dns` | base32 в имени домена | Средняя |
| TCP ISN | `tcp-isn` | 4 байта в Sequence Number | Высокая |
| TCP Timestamp | `tcp-ts` | 4 байта в TSval | Высокая |
| IP ID | `ip-id` | 2 байта в Identification | Высокая |

Для любого канала команды одинаковые -- меняется только `--channel`:
```bash
# Получатель
netstego receive --channel tcp-isn --sender-ip 192.168.1.10 --key-file demo.key --output received.txt

# Отправитель
netstego send --text "Hello" --channel tcp-isn --dest 192.168.1.20 --key-file demo.key --pcap-out tcp_isn.pcap
```

---

## Часть 3. Тестирование на одной машине (без сети)

Если второго компьютера нет, можно протестировать через PCAP-файл:
отправитель сохраняет пакеты в файл, получатель читает из него.

```bash
# 1. Генерация ключа
netstego keygen --output test.key

# 2. Отправка -- пакеты сохраняются в PCAP (в сеть тоже отправятся, но это не важно)
netstego send --text "Тест на одной машине" --channel icmp --dest 127.0.0.1 --key-file test.key --pcap-out test.pcap

# 3. Приём из PCAP-файла (не из сети)
netstego receive --channel icmp --sender-ip 127.0.0.1 --key-file test.key --output result.txt --pcap-in test.pcap

# 4. Проверка
cat result.txt
# Тест на одной машине
```

Это работает для всех 5 каналов. Замените `--channel icmp` на любой другой.

### Полный тест всех каналов одним скриптом

```bash
netstego keygen --output test.key

for CHANNEL in icmp dns tcp-isn tcp-ts ip-id; do
    echo "=== Тест канала: $CHANNEL ==="
    netstego send --text "Test $CHANNEL" --channel $CHANNEL --dest 127.0.0.1 --key-file test.key --pcap-out "${CHANNEL}.pcap"
    netstego receive --channel $CHANNEL --sender-ip 127.0.0.1 --key-file test.key --output "${CHANNEL}_result.txt" --pcap-in "${CHANNEL}.pcap"
    cat "${CHANNEL}_result.txt"
    echo ""
done
```

---

## Часть 4. Анализ в Wireshark

### Открытие PCAP

После отправки с флагом `--pcap-out` откройте сохранённый файл в Wireshark:

```bash
wireshark sent.pcap
```

### Что смотреть для каждого канала

#### ICMP Payload
1. Фильтр: `icmp.type == 8`
2. Выберите пакет, раскройте **Internet Control Message Protocol**
3. Поле **Data** -- зашифрованные данные
4. Первые 4 байта: `4e 53 54 00` (магическая последовательность NST) -- заголовок протокола

#### DNS QNAME
1. Фильтр: `dns`
2. Раскройте **Domain Name System (query)** -> **Queries**
3. Поле **Name** -- субдомены вида `GEZDGNBV...stego.local`
4. Данные закодированы в base32 внутри имени домена

#### TCP ISN
1. Фильтр: `tcp.flags.syn == 1`
2. Раскройте **Transmission Control Protocol**
3. Поле **Sequence Number** -- 4 байта скрытых данных
4. Каждый SYN-пакет несёт один фрагмент

#### TCP Timestamp
1. Фильтр: `tcp.flags.syn == 1`
2. Раскройте **TCP** -> **Options** -> **Timestamps**
3. Поле **TSval** -- 4 байта скрытых данных
4. Выглядит как обычная временная метка

#### IP ID
1. Фильтр: `ip`
2. Раскройте **Internet Protocol Version 4**
3. Поле **Identification** -- 2 байта скрытых данных
4. Самый скрытный канал -- поле есть в каждом IP-пакете

### Полезные фильтры Wireshark

```
# ICMP echo request с данными больше 100 байт
icmp.type == 8 && data.len > 100

# DNS-запросы с длинными именами (признак стеганографии)
dns.qry.name.len > 50

# TCP SYN с опцией Timestamp
tcp.flags.syn == 1 && tcp.options.timestamp

# Поиск магической последовательности NST в payload
data.data contains 4e:53:54:00
```

---

## Часть 5. Обнаружение скрытых каналов

Запустите детектор на любом PCAP-файле:

```bash
netstego detect --input sent.pcap
```

Результат:
```
=== Covert Channel Detection Report ===
Packets analyzed: N
Confidence: 0.70 (DETECTED)
Methods: statistical, ml, signatures
```

Сохранение отчёта:
```bash
netstego detect --input sent.pcap --report report.json
```

---

## Часть 6. Тест избыточности (защита от потери пакетов)

При передаче по нестабильной сети пакеты могут теряться.
Флаг `--redundancy N` дублирует каждый фрагмент N раз:

```bash
# Отправка с тройной избыточностью
netstego send --text "Важные данные" --channel icmp --dest 192.168.1.20 --key-file demo.key --redundancy 3 --pcap-out redundancy.pcap
```

В Wireshark видно 3 пакета вместо 1. Приёмник автоматически убирает дубликаты:

```bash
netstego receive --channel icmp --sender-ip 192.168.1.10 --key-file demo.key --output received.txt --pcap-in redundancy.pcap
```

```
Deduplicated 2 redundant chunks
Output saved to received.txt
```

---

## Часть 7. Автоматические тесты

Юнит-тесты и интеграционные тесты (не требуют сети и прав администратора):

```bash
python -m pytest tests/ -v
```

Все 188 тестов должны пройти. Запуск по группам:

```bash
python -m pytest tests/unit/ -v          # 96 юнит-тестов
python -m pytest tests/integration/ -v   # 92 интеграционных + целостности
```

---

## Часть 8. Бенчмарки и мониторинг точности обнаружения

```bash
# Производительность конвейера (шифрование, фрагментация, кодирование)
python tools/benchmark.py

# Точность обнаружения -- precision, recall, F1, confusion matrix
python tools/monitoring.py
```

---

## Краткая шпаргалка команд

| Действие | Команда |
|----------|---------|
| Генерация ключа | `netstego keygen --output demo.key` |
| Отправка текста | `netstego send --text "..." --channel icmp --dest IP --key-file demo.key` |
| Отправка файла | `netstego send --file photo.jpg --channel icmp --dest IP --key-file demo.key` |
| Приём из сети | `netstego receive --channel icmp --sender-ip IP --key-file demo.key --output out.txt` |
| Приём из PCAP | `netstego receive --channel icmp --sender-ip IP --key-file demo.key --output out.txt --pcap-in file.pcap` |
| Сохранить в PCAP | Добавить `--pcap-out packets.pcap` к send или receive |
| Избыточность | Добавить `--redundancy 3` к send |
| Обнаружение | `netstego detect --input traffic.pcap` |
| Тесты | `python -m pytest tests/ -v` |

---

## Устранение неполадок

| Проблема | Решение |
|----------|---------|
| `Permission denied` | Запустите терминал от имени администратора |
| `Npcap not found` | Установите Npcap с https://npcap.com |
| Приём зависает | Проверьте `--sender-ip`, `--channel`; используйте `--pcap-in` для теста без сети |
| `Decryption failed` | На обеих машинах должен быть одинаковый ключ |
| `Missing chunks` | Добавьте `--redundancy 3` при отправке |
| Нет пакетов в Wireshark | Убедитесь, что использовали `--pcap-out` при отправке |
| `pip install -e .` ошибка | Убедитесь, что вы в папке DiplomaStegano (где лежит pyproject.toml) |
