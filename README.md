# 🛡️ Proxy Collector

Автоматический параллельный сборщик, дедупликатор и нормализатор прокси-ссылок из внешних источников.  
Запускается ежедневно через **GitHub Actions** и сохраняет чистые списки в `result.txt` и `results/<protocol>.txt`.

[![Daily Proxy Collector](https://github.com/YOUR_USERNAME/proxy-collector/actions/workflows/collect.yml/badge.svg)](https://github.com/YOUR_USERNAME/proxy-collector/actions/workflows/collect.yml)

---

## 📦 Поддерживаемые протоколы

| Протокол          | Схема URI                          | Файл в `results/`   |
|-------------------|------------------------------------|---------------------|
| VLESS             | `vless://`                         | `vless.txt`         |
| VMess             | `vmess://`                         | `vmess.txt`         |
| Trojan            | `trojan://`                        | `trojan.txt`        |
| Shadowsocks       | `ss://`                            | `ss.txt`            |
| ShadowsocksR      | `ssr://`                           | `ssr.txt`           |
| Hysteria 2 / HY2  | `hy2://` `hysteria2://` `hysteria://` | `hy2.txt`        |
| TUIC              | `tuic://`                          | `tuic.txt`          |
| Naive             | `naive://`                         | `naive.txt`         |
| Brook             | `brook://`                         | `brook.txt`         |
| Juicity           | `juicity://`                       | `juicity.txt`       |
| WireGuard         | `wg://` `wireguard://`             | `wg.txt`            |

> `hy2://`, `hysteria2://` и `hysteria://` считаются одним протоколом и объединяются в `hy2.txt`.

---

## 🗂️ Структура проекта

```
proxy-collector/
│
├── .github/
│   └── workflows/
│       └── collect.yml      # GitHub Actions: ежедневный запуск в 06:00 UTC
│
├── results/                 # Прокси, разделённые по протоколам (авто)
│   ├── vless.txt
│   ├── vmess.txt
│   ├── trojan.txt
│   ├── ss.txt
│   ├── hy2.txt              # ← hy2 + hysteria2 + hysteria
│   ├── tuic.txt
│   └── ...
│
├── collector.py             # Основной скрипт (v5)
├── source.txt               # Список URL-источников (редактируете вы)
├── result.txt               # Все прокси + статистика (генерируется автоматически)
├── collector.log            # Лог последнего запуска
├── requirements.txt         # Зависимости Python (только stdlib)
├── .gitignore
└── README.md
```

---

## 🚀 Быстрый старт

### 1. Форкните или клонируйте репозиторий

```bash
git clone https://github.com/YOUR_USERNAME/proxy-collector.git
cd proxy-collector
```

### 2. Добавьте источники в `source.txt`

Откройте `source.txt` и добавьте ссылки — по одной на строку:

```
# Мои источники
https://raw.githubusercontent.com/example/repo/main/proxies.txt
https://pastebin.com/raw/XXXXXXXX
https://some-site.com/subscribe?token=abc
```

Строки, начинающиеся с `#`, игнорируются (комментарии).

### 3. Запустите скрипт локально (опционально)

```bash
python collector.py
# с подробным логом:
python collector.py --verbose
# с нестандартными путями:
python collector.py --source my_sources.txt --output my_result.txt --results my_results/
```

### 4. Включите GitHub Actions

Перейдите в **Settings → Actions → General → Workflow permissions**  
и установите: **Read and write permissions ✓**

---

## ⚙️ Расписание запуска

Скрипт запускается **каждый день в 06:00 UTC** (только по расписанию и вручную — коммиты в репо не запускают сборку).

Изменить расписание можно в `.github/workflows/collect.yml`:

```yaml
schedule:
  - cron: "0 6 * * *"    # каждый день 06:00 UTC
  # "0 */6 * * *"         — каждые 6 часов
  # "0 6,18 * * *"        — дважды в день
```

Ручной запуск: **Actions → Daily Proxy Collector → Run workflow**.

---

## ⚡ Производительность (v5)

| Этап                      | До v5 (seq) | v5 (parallel)  | Ускорение |
|---------------------------|-------------|----------------|-----------|
| Загрузка источников       | ~60с        | ~6с            | **~10×**  |
| Геолокация (3 000 хостов) | ~120с       | ~45с           | **~2.7×** |
| **Итого**                 | ~180с       | **~55с**       | **~3×**   |

**Как работает ускорение:**
- **`ThreadPoolExecutor` для источников** — 10 параллельных HTTP-запросов вместо последовательных
- **`ThreadPoolExecutor` для geo** — 3 параллельных потока для батч-запросов к ip-api.com
- **Token-bucket RateLimiter** — потокобезопасное ограничение 40 req/min глобально по всем потокам
- **Batch 100 хостов** — меньше HTTP-вызовов к ip-api.com
- **Фильтр приватных IP** — `192.168.x`, `10.x`, `127.x`, `::1` не отправляются на геолокацию

---

## 📄 Формат `result.txt`

```
# ═══════════════════════════════════════════════════════════
#  Proxy Collector v5 — результат сборки
# ─────────────────────────────────────────────────────────
#  Обновлено  : 2025-01-15 06:03 UTC
#  Источников : 5/5 успешно
#  Извлечено  : 4821 (до дедупликации)
#  Дубликатов : 1943 удалено
#  Итого      : 2878 уникальных прокси
# ─────────────────────────────────────────────────────────
#  Протоколы:
#    VLESS        1104  ████████████████████████
#    VMESS         821  ██████████████████
#    TROJAN        512  ████████████
#    SS            298  ███████
#    HY2           143  ███
# ─────────────────────────────────────────────────────────
#  Топ-10 стран:
#    🇺🇸 US     891  ████████████████████████
#    🇩🇪 DE     412  ███████████
#    🇳🇱 NL     387  ██████████
# ═══════════════════════════════════════════════════════════

vless://uuid@host:443?security=tls#🇺🇸 VLESS
vmess://base64encodeddata#                     ← имя внутри JSON
trojan://password@host:443?sni=x#🇩🇪 TROJAN
hy2://password@host:8443#🇯🇵 HY2
ss://base64@host:port#🇬🇧 SS
```

### Формат имён

```
🇺🇸 VLESS       — флаг страны + протокол
🌐 TROJAN       — глобус, если IP не определён
```

На **Android** флаги отображаются как цветные эмодзи 🇺🇸.  
На **Windows** — как пара букв кода страны `US`, `DE` (читаемо, не ломает клиент).

---

## 🔧 Опции командной строки

```
python collector.py [-h] [-s SOURCE] [-o OUTPUT] [-r RESULTS] [-v]

  -s, --source   Файл источников (по умолчанию: source.txt)
  -o, --output   Файл всех результатов (по умолчанию: result.txt)
  -r, --results  Папка результатов по протоколам (по умолчанию: results/)
  -v, --verbose  Подробный вывод уровня DEBUG
```

---

## 🧩 Как работает скрипт

```
source.txt
    │
    ▼
[Параллельная загрузка]  ← 10 потоков, urllib, retry × 3
    │
    ▼
[Парсинг текста]
  • Regex по всем схемам
  • Рекурсивное декодирование Base64 (subscription-формат)
    │
    ▼
[Нормализация]           ← базовая валидация URL, vmess JSON, ss-компоненты
    │
    ▼
[Дедупликация]           ← SHA-256 по параметрам соединения (без имени)
                            vmess: по JSON-полям (add, port, id, net, tls…)
                            ss: по method + password + host + port
                            ssr: по декодированному ядру без remarks
                            прочие: netloc + path + sorted query (без name-полей)
    │
    ▼
[Параллельная геолокация]
  • Фильтр приватных IP (192.168.x, 10.x, 127.x, ::1 — не запрашиваются)
  • 3 параллельных потока → ip-api.com/batch (100 хостов/запрос)
  • Token-bucket RateLimiter: 40 req/min глобально
  • Читает X-Rl / X-Ttl для адаптивных пауз
  • Экспоненциальный backoff при 429
    │
    ▼
[Сортировка]             ← протокол → страна → хост → порт
    │
    ▼
[Переименование]         ← "🇺🇸 VLESS" для всех протоколов
    │
    ▼
result.txt + results/<protocol>.txt
```

---

## 🌍 Геолокация

Используется **[ip-api.com](https://ip-api.com)** — полностью бесплатный сервис, не требует API-ключа.

| Параметр         | Значение               |
|------------------|------------------------|
| Лимит            | 45 запросов / минута   |
| Используется     | 40 req/min (с запасом) |
| Batch-размер     | 100 хостов / запрос    |
| Параллельность   | 3 потока               |
| Backoff при 429  | 65с → 130с → 195с      |

---

## 📝 Лицензия

MIT — используйте свободно.
