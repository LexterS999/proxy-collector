#!/usr/bin/env python3
"""
Proxy Collector — автоматический сборщик прокси из внешних источников.
Поддерживает: vless://, vmess://, trojan://, ss://, hy2://, hysteria://,
              tuic://, wg://, wireguard://, naive://, brook://, juicity://
"""

import re
import sys
import time
import base64
import logging
import hashlib
import argparse
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

# ─── Настройки ────────────────────────────────────────────────────────────────

SOURCE_FILE  = "source.txt"
RESULT_FILE  = "result.txt"
LOG_FILE     = "collector.log"
TIMEOUT      = 20          # секунд на загрузку одного источника
MAX_RETRIES  = 3
RETRY_DELAY  = 3           # секунд между попытками

# Поддерживаемые схемы прокси (регистронезависимо)
PROXY_SCHEMES = [
    "vless", "vmess", "trojan", "ss", "ssr",
    "hy2", "hysteria", "hysteria2",
    "tuic", "naive", "brook", "juicity",
    "wireguard", "wg",
]

# Регулярное выражение для извлечения прокси-ссылок из текста
_SCHEMES_PATTERN = "|".join(re.escape(s) for s in PROXY_SCHEMES)
PROXY_RE = re.compile(
    rf'(?:^|[\s"\'])({_SCHEMES_PATTERN})://([\S]+)',
    re.IGNORECASE | re.MULTILINE,
)

# ─── Логирование ──────────────────────────────────────────────────────────────

def setup_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    fmt   = "%(asctime)s [%(levelname)s] %(message)s"
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ]
    logging.basicConfig(level=level, format=fmt, handlers=handlers)
    return logging.getLogger("collector")


log = logging.getLogger("collector")

# ─── Утилиты ──────────────────────────────────────────────────────────────────

def _safe_b64decode(data: str) -> str:
    """Декодирует Base64 (стандартный + URL-safe) без исключений."""
    data = data.strip()
    # добиваем padding
    pad = 4 - len(data) % 4
    if pad != 4:
        data += "=" * pad
    try:
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
    except Exception:
        try:
            return base64.b64decode(data).decode("utf-8", errors="replace")
        except Exception:
            return ""


def _is_base64(text: str) -> bool:
    """Грубая проверка: строка похожа на Base64-блок."""
    text = text.strip()
    if len(text) < 20:
        return False
    b64_chars = re.compile(r'^[A-Za-z0-9+/\-_=\n\r]+$')
    return bool(b64_chars.match(text))


def proxy_fingerprint(url: str) -> str:
    """Уникальный отпечаток прокси для дедупликации (без имени/комментария)."""
    try:
        parsed = urlparse(url)
        scheme   = parsed.scheme.lower()
        netloc   = parsed.netloc.lower()
        path     = parsed.path
        query    = parsed.query
        # убираем параметры-метки, не влияющие на подключение
        if query:
            params = parse_qs(query, keep_blank_values=True)
            for skip in ("remarks", "remark", "name", "#"):
                params.pop(skip, None)
            query = urlencode(sorted(params.items()))
        canonical = urlunparse((scheme, netloc, path, "", query, ""))
        return hashlib.sha256(canonical.encode()).hexdigest()
    except Exception:
        return hashlib.sha256(url.encode()).hexdigest()


# ─── Нормализация прокси ──────────────────────────────────────────────────────

def normalize_proxy(raw: str) -> str | None:
    """
    Приводит прокси к каноническому виду:
    - строчная схема
    - декодированный fragment (имя/remark)
    - убраны лишние пробелы
    Возвращает None если URL невалиден.
    """
    raw = raw.strip()
    if not raw:
        return None

    # Некоторые источники кодируют имя в fragment как %XX
    # urlparse корректно это разбирает, просто восстановим
    try:
        parsed = urlparse(raw)
    except Exception:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in PROXY_SCHEMES:
        return None

    # Для vmess часто встречается base64-тело после схемы
    if scheme == "vmess":
        encoded_body = parsed.netloc + parsed.path
        decoded = _safe_b64decode(encoded_body)
        if decoded and decoded.strip().startswith("{"):
            # оставляем как есть — уже читаемый JSON внутри vmess://
            pass

    # Нормализуем fragment (remark/имя): декодируем %XX → unicode
    fragment = unquote(parsed.fragment).strip() if parsed.fragment else ""

    # Собираем обратно
    try:
        normalized = urlunparse((
            scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            fragment,
        ))
    except Exception:
        return None

    # Минимальная валидация: должен быть хост или тело
    if len(parsed.netloc) < 2 and len(parsed.path) < 4:
        return None

    return normalized


# ─── Загрузка источников ──────────────────────────────────────────────────────

def fetch_url(url: str) -> str:
    """Скачивает текст по URL с повторными попытками."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; ProxyCollector/2.0; "
            "+https://github.com/your-username/proxy-collector)"
        ),
        "Accept": "text/plain, text/html, */*",
    }
    req = urllib.request.Request(url, headers=headers)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                raw_bytes = resp.read()
                # пробуем угадать кодировку
                for enc in ("utf-8", "latin-1", "cp1251"):
                    try:
                        return raw_bytes.decode(enc)
                    except UnicodeDecodeError:
                        continue
                return raw_bytes.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            log.warning("HTTP %s для %s (попытка %d/%d)", e.code, url, attempt, MAX_RETRIES)
        except urllib.error.URLError as e:
            log.warning("URLError для %s: %s (попытка %d/%d)", url, e.reason, attempt, MAX_RETRIES)
        except Exception as e:
            log.warning("Ошибка загрузки %s: %s (попытка %d/%d)", url, e, attempt, MAX_RETRIES)

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY)

    return ""


def extract_proxies_from_text(text: str) -> list[str]:
    """Извлекает все прокси-ссылки из произвольного текста."""
    proxies: list[str] = []

    # 1. Прямой поиск по схемам
    for match in PROXY_RE.finditer(text):
        scheme = match.group(1)
        rest   = match.group(2)
        # обрезаем по первому пробелу/кавычке/скобке
        rest = re.split(r'[\s"\'\]\)>]', rest)[0]
        proxies.append(f"{scheme}://{rest}")

    # 2. Если текст похож на Base64-blob — декодируем и парсим снова
    if not proxies and _is_base64(text):
        decoded = _safe_b64decode(text)
        if decoded:
            log.debug("Декодирован Base64-блок (%d → %d символов)", len(text), len(decoded))
            proxies.extend(extract_proxies_from_text(decoded))

    # 3. Многострочный Base64 (subscription-формат)
    for line in text.splitlines():
        line = line.strip()
        if _is_base64(line) and not any(line.startswith(s + "://") for s in PROXY_SCHEMES):
            decoded = _safe_b64decode(line)
            if decoded:
                found = extract_proxies_from_text(decoded)
                if found:
                    proxies.extend(found)

    return proxies


def load_sources(source_file: str) -> list[str]:
    """Читает список URL из файла, игнорируя пустые строки и комментарии (#)."""
    path = Path(source_file)
    if not path.exists():
        log.error("Файл источников не найден: %s", source_file)
        return []

    urls = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            urls.append(line)

    log.info("Загружено %d источников из %s", len(urls), source_file)
    return urls


# ─── Сортировка ───────────────────────────────────────────────────────────────

SCHEME_ORDER = {s: i for i, s in enumerate([
    "vless", "vmess", "trojan",
    "ss", "ssr",
    "hy2", "hysteria2", "hysteria",
    "tuic", "naive", "brook", "juicity",
    "wireguard", "wg",
])}


def sort_key(proxy: str) -> tuple:
    """Ключ сортировки: (порядок схемы, хост, порт, полный url)."""
    try:
        parsed = urlparse(proxy)
        scheme = parsed.scheme.lower()
        host   = (parsed.hostname or "").lower()
        try:
            port = int(parsed.port or 0)
        except (ValueError, TypeError):
            port = 0
        order = SCHEME_ORDER.get(scheme, 99)
        return (order, host, port, proxy)
    except Exception:
        return (99, "", 0, proxy)


# ─── Статистика ───────────────────────────────────────────────────────────────

def build_stats(proxies: list[str], sources_total: int, sources_ok: int,
                raw_count: int) -> str:
    """Формирует блок статистики для result.txt."""
    counter: dict[str, int] = defaultdict(int)
    for p in proxies:
        scheme = urlparse(p).scheme.lower()
        counter[scheme] += 1

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# ═══════════════════════════════════════════════════════",
        f"# Proxy Collector — результат сборки",
        f"# Обновлено : {now}",
        f"# Источников: {sources_ok}/{sources_total} успешно",
        f"# Найдено   : {raw_count} (до дедупликации)",
        f"# Итого     : {len(proxies)} уникальных прокси",
        "# ───────────────────────────────────────────────────────",
    ]
    for scheme, count in sorted(counter.items(), key=lambda x: -x[1]):
        lines.append(f"#   {scheme:<14} {count:>5}")
    lines.append("# ═══════════════════════════════════════════════════════")
    return "\n".join(lines)


# ─── Основная логика ──────────────────────────────────────────────────────────

def run(source_file: str = SOURCE_FILE, result_file: str = RESULT_FILE,
        verbose: bool = False) -> int:
    setup_logging(verbose)
    log.info("════ Proxy Collector запущен ════")

    urls = load_sources(source_file)
    if not urls:
        log.error("Нет источников для обработки.")
        return 1

    all_raw: list[str] = []
    sources_ok = 0

    for idx, url in enumerate(urls, 1):
        log.info("[%d/%d] Загружаю: %s", idx, len(urls), url)
        text = fetch_url(url)
        if not text:
            log.warning("  ↳ Пустой ответ или ошибка, пропускаем.")
            continue

        found = extract_proxies_from_text(text)
        log.info("  ↳ Найдено прокси: %d", len(found))
        all_raw.extend(found)
        sources_ok += 1

    raw_count = len(all_raw)
    log.info("Всего извлечено (с дублями): %d", raw_count)

    # Нормализация
    normalized: list[str] = []
    for p in all_raw:
        n = normalize_proxy(p)
        if n:
            normalized.append(n)

    # Дедупликация по отпечатку
    seen:   set[str]  = set()
    unique: list[str] = []
    for p in normalized:
        fp = proxy_fingerprint(p)
        if fp not in seen:
            seen.add(fp)
            unique.append(p)

    log.info("После дедупликации: %d", len(unique))

    # Сортировка
    unique.sort(key=sort_key)

    # Запись результата
    stats   = build_stats(unique, len(urls), sources_ok, raw_count)
    content = stats + "\n\n" + "\n".join(unique) + "\n"

    Path(result_file).write_text(content, encoding="utf-8")
    log.info("Результат сохранён в %s (%d прокси)", result_file, len(unique))
    log.info("════ Готово ════")
    return 0


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Собирает, дедуплицирует и нормализует прокси из внешних источников."
    )
    parser.add_argument(
        "-s", "--source",
        default=SOURCE_FILE,
        help=f"Путь к файлу источников (по умолчанию: {SOURCE_FILE})",
    )
    parser.add_argument(
        "-o", "--output",
        default=RESULT_FILE,
        help=f"Путь к файлу результатов (по умолчанию: {RESULT_FILE})",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Подробный вывод (DEBUG)",
    )
    args = parser.parse_args()
    sys.exit(run(args.source, args.output, args.verbose))
