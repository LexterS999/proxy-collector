# 🛡️ Proxy Collector

Автоматический сборщик, дедупликатор и нормализатор прокси-ссылок из внешних источников.  
Запускается ежедневно через **GitHub Actions** и сохраняет чистый список в `result.txt`.

---

## 📦 Поддерживаемые протоколы

| Протокол     | Схема URI                     |
|--------------|-------------------------------|
| VLESS        | `vless://`                    |
| VMess        | `vmess://`                    |
| Trojan       | `trojan://`                   |
| Shadowsocks  | `ss://`                       |
| ShadowsocksR | `ssr://`                      |
| Hysteria 2   | `hy2://` / `hysteria2://`     |
| Hysteria     | `hysteria://`                 |
| TUIC         | `tuic://`                     |
| Naive        | `naive://`                    |
| Brook        | `brook://`                    |
| Juicity      | `juicity://`                  |
| WireGuard    | `wg://` / `wireguard://`      |

---

## 🗂️ Структура проекта

```
proxy-collector/
│
├── .github/
│   └── workflows/
│       └── collect.yml     # GitHub Actions: ежедневный запуск
│
├── collector.py            # Основной скрипт
├── source.txt              # Список URL-источников (редактируете вы)
├── result.txt              # Итоговый список прокси (генерируется автоматически)
├── collector.log           # Лог последнего запуска
├── requirements.txt        # Зависимости Python (stdlib only)
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

Строки, начинающиеся с `#`, игнорируются.

### 3. Запустите скрипт локально (опционально)

```bash
python collector.py
# или с подробным логом:
python collector.py --verbose
# с указанием нестандартных путей:
python collector.py --source my_sources.txt --output my_result.txt
```

### 4. Включите GitHub Actions

Actions включены по умолчанию для форков.  
Перейдите в **Settings → Actions → General** и убедитесь, что Actions разрешены.

Также нужно разрешить запись в репозиторий:  
**Settings → Actions → General → Workflow permissions → Read and write permissions ✓**

---

## ⚙️ Расписание запуска

По умолчанию скрипт запускается **каждый день в 06:00 UTC**.  
Изменить расписание можно в `.github/workflows/collect.yml`:

```yaml
schedule:
  - cron: "0 6 * * *"   # UTC: каждый день в 06:00
  # Примеры:
  # "0 */6 * * *"  — каждые 6 часов
  # "0 6,18 * * *" — дважды в день: в 06:00 и 18:00
  # "0 6 * * 1"    — каждый понедельник
```

Ручной запуск доступен через вкладку **Actions → Daily Proxy Collector → Run workflow**.

---

## 📄 Формат `result.txt`

```
# ═══════════════════════════════════════════════════════
# Proxy Collector — результат сборки
# Обновлено : 2025-01-15 06:03 UTC
# Источников: 5/5 успешно
# Найдено   : 3421 (до дедупликации)
# Итого     : 847 уникальных прокси
# ───────────────────────────────────────────────────────
#   vless           312
#   vmess           201
#   trojan          158
#   ss               98
#   hy2              78
# ═══════════════════════════════════════════════════════

vless://uuid@host:port?security=tls&sni=example.com#Name
vmess://base64encodeddata
trojan://password@host:443?sni=example.com#Name
ss://base64@host:port#Name
...
```

---

## 🔧 Опции командной строки

```
usage: collector.py [-h] [-s SOURCE] [-o OUTPUT] [-v]

  -s, --source  Путь к файлу источников (по умолчанию: source.txt)
  -o, --output  Путь к файлу результатов (по умолчанию: result.txt)
  -v, --verbose Подробный вывод (уровень DEBUG)
```

---

## 🧩 Как работает скрипт

```
source.txt
    │
    ▼
[Загрузка URL]  ← urllib, повторные попытки, таймаут
    │
    ▼
[Парсинг текста]
  • Прямой поиск по схемам (regex)
  • Декодирование Base64 (subscription-формат)
  • Рекурсивный парсинг декодированного текста
    │
    ▼
[Нормализация]
  • Строчная схема
  • Декодированный fragment (%XX → unicode)
  • Валидация структуры URL
    │
    ▼
[Дедупликация]  ← SHA-256 по canonical URL (без имени)
    │
    ▼
[Сортировка]    ← по протоколу → хосту → порту
    │
    ▼
result.txt      ← статистика + прокси
```

---

## 📝 Лицензия

MIT — используйте свободно.
