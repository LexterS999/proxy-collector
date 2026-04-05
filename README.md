# 📡 Proxy Collector

Автоматический **async** сборщик, дедупликатор и нормализатор прокси-ссылок.  
Запускается ежедневно через **GitHub Actions**, проверяет живость каждого прокси и публикует чистые списки с дашбордом.

[![Daily Proxy Collector](https://github.com/LexterS999/proxy-collector/actions/workflows/collect.yml)](https://github.com/LexterS999/proxy-collector/actions/workflows/collect.yml)

---

## 📦 Поддерживаемые протоколы

| Протокол              | Схемы URI                              | Файл               |
|-----------------------|----------------------------------------|--------------------|
| VLESS                 | `vless://`                             | `results/vless.txt`    |
| VMess                 | `vmess://`                             | `results/vmess.txt`    |
| Trojan                | `trojan://`                            | `results/trojan.txt`   |
| Shadowsocks           | `ss://`                                | `results/ss.txt`       |
| ShadowsocksR          | `ssr://`                               | `results/ssr.txt`      |
| Hysteria 2 / HY2      | `hy2://` `hysteria2://` `hysteria://`  | `results/hy2.txt`  |
| TUIC                  | `tuic://`                              | `results/tuic.txt`     |
| Naive                 | `naive://`                             | `results/naive.txt`    |
| Brook                 | `brook://`                             | `results/brook.txt`    |
| Juicity               | `juicity://`                           | `results/juicity.txt`  |
| WireGuard             | `wg://` `wireguard://`                 | `results/wg.txt`       |

> `hy2://`, `hysteria2://` и `hysteria://` — один протокол, объединяются в **`hy2.txt`**.

---

## 🗂️ Структура проекта

```
proxy-collector/
│
├── .github/workflows/
│   └── collect.yml        # GitHub Actions: 06:00 UTC ежедневно
│
├── results/               # Прокси по протоколам (авто-генерация)
│   ├── vless.txt
│   ├── vmess.txt
│   ├── trojan.txt
│   ├── ss.txt
│   ├── hy2.txt            # hy2 + hysteria2 + hysteria
│   ├── tuic.txt
│   └── ...
│
├── collector.py           # Основной скрипт (v6, asyncio + aiohttp)
├── source.txt             # Список URL-источников (редактируете вы)
├── result.txt             # Все живые прокси + статистика (авто)
├── geo_cache.json         # Кэш геолокации (авто, хранится между запусками)
├── stats.json             # История запусков — до 90 записей (авто)
├── dashboard.html         # Интерактивный дашборд с графиками (авто)
├── collector.log          # Лог последнего запуска (авто)
├── requirements.txt       # Зависимости Python (aiohttp)
├── .gitignore
└── README.md
```

---

## 🚀 Быстрый старт

### 1. Форкните репозиторий и добавьте источники

Откройте `source.txt` и добавьте ссылки — по одной на строку:

```
# Мои источники
https://raw.githubusercontent.com/example/repo/main/proxies.txt
https://pastebin.com/raw/XXXXXXXX
```

Строки начинающиеся с `#` — комментарии, игнорируются.

### 2. Разрешите Actions запись в репозиторий

**Settings → Actions → General → Workflow permissions → Read and write permissions ✓**

### 3. Запустите вручную или дождитесь 06:00 UTC

**Actions → Daily Proxy Collector → Run workflow**

### 4. Запуск локально

```bash
pip install aiohttp
python collector.py
# подробный лог:
python collector.py --verbose
# нестандартные пути:
python collector.py --source my_sources.txt --output my_result.txt --results my_results/
```

---

## ⚡ Производительность v6

| Этап                         | Подход                     | Время (3000 прокси) |
|------------------------------|----------------------------|---------------------|
| Загрузка источников          | aiohttp, 20 паралл.        | **~5–8с**           |
| Проверка живости (TCP)       | asyncio, 800 паралл.       | **~15–30с**         |
| Геолокация (без кэша)        | aiohttp, 3 паралл., rate-limit | **~40–60с**     |
| Геолокация (с кэшем)         | только новые хосты         | **~5–10с**          |
| **Итого (первый запуск)**    |                            | **~70–110с**        |
| **Итого (повторный запуск)** | 60-80% хостов из кэша     | **~30–50с**         |

---

## 📄 Формат `result.txt`

```
# ═══════════════════════════════════════════════════════════
#  Proxy Collector v6
# ─────────────────────────────────────────────────────────
#  Обновлено  : 2025-01-15 06:07 UTC
#  Источников : 8/8 успешно
#  Извлечено  : 6210 (до дедупликации)
#  Дубликатов : 2841 удалено
#  Уникальных : 3369
#  Живых      : 1847 (54%)
# ─────────────────────────────────────────────────────────
#  Протоколы:
#    VLESS         891  ████████████████████████
#    VMESS         612  ████████████████
#    TROJAN        201  █████
#    HY2           143  ████
# ─────────────────────────────────────────────────────────
#  Топ-10 стран:
#    🇺🇸 US     523  ████████████████████████
#    🇩🇪 DE     312  ██████████████
#    🇳🇱 NL     201  █████████
# ═══════════════════════════════════════════════════════════

vless://uuid@host:443?security=tls#🇺🇸 US VLESS
vmess://base64data                 ← имя хранится внутри JSON (поле ps)
trojan://password@host:443#🇩🇪 DE TROJAN
hy2://password@host:8443#🇯🇵 JP HY2
ss://base64@host:port#🇬🇧 GB SS
```

### Формат имени прокси

```
🇺🇸 US VLESS    — флаг страны + ISO-код + протокол
🌐 ?? SS         — глобус, если геолокация не определена
```

Флаги отображаются как **цветные эмодзи** на Android и Linux.  
На **Windows** — пара букв кода страны (`US`, `DE`, `RU`) — читаемо, не ломает клиент.

---

## 📊 Dashboard

После каждого запуска генерируется `dashboard.html` — откройте в браузере.

**Содержит:**
- 📈 История уникальных / живых прокси (последние 30 запусков)
- 🥧 Распределение по протоколам (дугообразная диаграмма)
- 🌍 Топ-15 стран (горизонтальный бар)
- 🔥 Процент живых прокси по дням
- 📊 Динамика протоколов по дням (линейный график)
- 📦 Дедупликация по дням (стековый бар)
- 🔗 Статус каждого источника (OK / FAIL, сколько найдено)
- Карточки: живых, % живых, дедупликация %, гео-покрытие %

---

## 🌍 Геолокация

Используется **[ip-api.com](https://ip-api.com)** — бесплатно, без API-ключа.

| Параметр            | Значение                   |
|---------------------|----------------------------|
| Лимит               | 45 запросов / минута       |
| Используем          | 40 req/min (с запасом)     |
| Batch               | 100 хостов / запрос        |
| Параллельность      | 3 потока                   |
| Кэш                 | `geo_cache.json` (постоянный между запусками) |
| Backoff при 429     | 65с → 130с → 195с          |
| Адаптивные паузы    | Читает X-Rl / X-Ttl из ответа |

---

## 🔍 Проверка живости

Для каждого уникального прокси выполняется **TCP connect** на хост:порт.

| Параметр            | Значение                   |
|---------------------|----------------------------|
| Метод               | `asyncio.open_connection`  |
| Timeout             | 3.0 секунды                |
| Параллельность      | до 800 одновременно        |
| Приватные IP        | считаются живыми (не проверяются) |
| Результат           | в `result.txt` только живые прокси |

---

## 🧩 Архитектура

```
source.txt
    │
    ▼
[Async fetch]          ← aiohttp, 20 паралл., retry×3
    │
    ▼
[Парсинг текста]
  • Regex по всем схемам
  • Рекурсивное декодирование Base64 (до 3 уровней)
    │
    ▼
[Нормализация]         ← валидация URL, vmess JSON, ss-компоненты
    │
    ▼
[Дедупликация]         ← SHA-256 по параметрам соединения (без имени):
                          vmess: add+port+id+net+tls+sni+...
                          ss: method+password+host+port
                          ssr: декодированное ядро без remarks
                          прочие: netloc+path+sorted query (без name-полей)
    │
    ▼
[TCP liveness check]   ← asyncio, 800 паралл., timeout 3s
  → только живые прокси идут дальше
    │
    ▼
[Геолокация]           ← geo_cache.json (hit) + ip-api.com/batch (miss)
  AsyncRateLimiter 40/min, GEO_CONCURRENCY=3, batch=100
    │
    ▼
[Сортировка]           ← протокол → страна → хост → порт
    │
    ▼
[Переименование]       ← "🇺🇸 US VLESS" для всех типов прокси
    │
    ▼
result.txt             ← все живые прокси + статистика в шапке
results/<proto>.txt    ← по одному файлу на протокол
geo_cache.json         ← обновлённый кэш геолокации
stats.json             ← добавлена запись текущего запуска
dashboard.html         ← сгенерированный дашборд
```

---

## ⚙️ Опции CLI

```
python collector.py [-h] [-s SOURCE] [-o OUTPUT] [-r RESULTS] [-v]

  -s, --source   Файл источников (по умолчанию: source.txt)
  -o, --output   Все результаты (по умолчанию: result.txt)
  -r, --results  Папка по протоколам (по умолчанию: results/)
  -v, --verbose  Подробный лог (DEBUG)
```

---

## ⏱️ Расписание (GitHub Actions)

Запуск **только по расписанию** и вручную — коммиты в репо **не** запускают сборку.

```yaml
schedule:
  - cron: "0 6 * * *"    # ежедневно в 06:00 UTC
```

Изменить время: откройте `.github/workflows/collect.yml` → `cron`.

---

## 📝 Лицензия

MIT — используйте свободно.
