#!/usr/bin/env python3
"""
Proxy Collector v2 — сборщик, дедупликатор и нормализатор прокси.

Поддерживает: vless://, vmess://, trojan://, ss://, ssr://,
              hy2://, hysteria://, hysteria2://, tuic://,
              naive://, brook://, juicity://, wg://, wireguard://

Стандарт имён: PROTOCOL | host:port | #00001
Дедупликация : по фактическим параметрам подключения (хост, порт,
               UUID/пароль, транспорт) — имена полностью игнорируются.
"""

import re
import sys
import json
import time
import base64
import logging
import hashlib
import argparse
import urllib.request
import urllib.error
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse, unquote, quote,
)
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

# ─── Настройки ────────────────────────────────────────────────────────────────

SOURCE_FILE = "source.txt"
RESULT_FILE = "result.txt"
LOG_FILE    = "collector.log"
TIMEOUT     = 20
MAX_RETRIES = 3
RETRY_DELAY = 3

PROXY_SCHEMES = [
    "vless", "vmess", "trojan",
    "ss", "ssr",
    "hy2", "hysteria2", "hysteria",
    "tuic", "naive", "brook", "juicity",
    "wireguard", "wg",
]

SCHEME_LABEL: dict[str, str] = {
    "vless":     "VLESS",
    "vmess":     "VMESS",
    "trojan":    "TROJAN",
    "ss":        "SS",
    "ssr":       "SSR",
    "hy2":       "HY2",
    "hysteria2": "HY2",
    "hysteria":  "HYSTERIA",
    "tuic":      "TUIC",
    "naive":     "NAIVE",
    "brook":     "BROOK",
    "juicity":   "JUICITY",
    "wireguard": "WG",
    "wg":        "WG",
}

# Параметры запроса, которые несут ТОЛЬКО имя — не влияют на соединение
_NAME_PARAMS = frozenset({"remarks", "remark", "name", "title", "label", "alias"})

# Regex для извлечения прокси из текста
_SCHEMES_PAT = "|".join(re.escape(s) for s in PROXY_SCHEMES)
PROXY_RE = re.compile(
    rf'(?:^|[\s"\',;`])({_SCHEMES_PAT})://([\S]+)',
    re.IGNORECASE | re.MULTILINE,
)

# ─── Логирование ──────────────────────────────────────────────────────────────

log = logging.getLogger("collector")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt   = "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(
        level=level, format=fmt,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
        ],
    )


# ─── Base64 утилиты ───────────────────────────────────────────────────────────

def _b64decode(data: str) -> str:
    data = data.strip().replace("\n", "").replace("\r", "")
    pad  = 4 - len(data) % 4
    if pad != 4:
        data += "=" * pad
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return fn(data).decode("utf-8", errors="replace")
        except Exception:
            pass
    return ""


def _b64encode(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _looks_like_b64(text: str) -> bool:
    text = text.strip()
    return (
        len(text) >= 20
        and bool(re.match(r'^[A-Za-z0-9+/\-_=\n\r]+$', text))
        and not any(text.lower().startswith(s + "://") for s in PROXY_SCHEMES)
    )


# ─── Парсеры протоколов ───────────────────────────────────────────────────────

def _vmess_decode(url: str) -> dict | None:
    try:
        body = url[len("vmess://"):]
        decoded = _b64decode(body)
        if decoded:
            return json.loads(decoded)
    except Exception:
        pass
    return None


def _vmess_encode(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _ss_components(url: str) -> tuple | None:
    """
    Разбирает ss:// -> (method, password, host, port).

    Форматы:
      ss://BASE64(method:pass)@host:port#name   <- современный
      ss://BASE64(method:pass@host:port)#name   <- legacy
      ss://method:pass@host:port#name           <- plain-text
    """
    try:
        clean = url.split("#")[0].strip()
        body  = clean[len("ss://"):]

        if "@" in body:
            at_idx   = body.rindex("@")
            userinfo = body[:at_idx]
            hostport = body[at_idx + 1:]

            decoded_ui = _b64decode(userinfo)
            if decoded_ui and ":" in decoded_ui and len(decoded_ui) < 512:
                method, password = decoded_ui.split(":", 1)
            elif ":" in userinfo:
                method, password = unquote(userinfo).split(":", 1)
            else:
                return None

            h, _, p = hostport.rpartition(":")
            return method.strip().lower(), password.strip(), h.lower(), int(p)

        decoded = _b64decode(body)
        if "@" in decoded:
            creds, hostport = decoded.rsplit("@", 1)
            method, password = creds.split(":", 1) if ":" in creds else (creds, "")
            h, _, p = hostport.rpartition(":")
            return method.strip().lower(), password.strip(), h.lower(), int(p)

    except Exception:
        pass
    return None


def _ssr_core(url: str) -> str:
    try:
        body    = url[len("ssr://"):]
        decoded = _b64decode(body)
        if not decoded:
            return url
        core = decoded.split("/?")[0].split("#")[0]
        return core.lower()
    except Exception:
        return url


def _host_port(url: str) -> tuple:
    scheme = urlparse(url).scheme.lower()

    if scheme == "vmess":
        obj = _vmess_decode(url)
        if obj:
            return str(obj.get("add", "unknown")).lower(), int(obj.get("port", 0))

    if scheme == "ss":
        comp = _ss_components(url)
        if comp:
            return comp[2], comp[3]

    if scheme == "ssr":
        core   = _ssr_core(url)
        parts  = core.split(":")
        if len(parts) >= 2:
            try:
                return parts[0], int(parts[1])
            except ValueError:
                pass

    parsed = urlparse(url)
    return (parsed.hostname or "unknown").lower(), (parsed.port or 0)


# ─── Дедупликация ─────────────────────────────────────────────────────────────

def connection_fingerprint(url: str) -> str:
    """
    SHA-256 от параметров подключения.
    Имя/remark/fragment ПОЛНОСТЬЮ исключены.
    Одинаковые серверы с разными именами -> один отпечаток.
    """
    try:
        scheme = urlparse(url).scheme.lower()

        if scheme == "vmess":
            obj = _vmess_decode(url)
            if obj:
                fields = ("add", "port", "id", "aid", "net", "type",
                          "host", "path", "tls", "sni", "alpn", "fp",
                          "flow", "serviceName")
                key = "|".join(str(obj.get(f, "")).lower() for f in fields)
                return hashlib.sha256(f"vmess:{key}".encode()).hexdigest()

        if scheme == "ss":
            comp = _ss_components(url)
            if comp:
                method, password, host, port = comp
                key = f"ss:{method}:{password}:{host}:{port}"
                return hashlib.sha256(key.encode()).hexdigest()

        if scheme == "ssr":
            core = _ssr_core(url)
            return hashlib.sha256(f"ssr:{core}".encode()).hexdigest()

        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        path   = parsed.path

        params = parse_qs(parsed.query, keep_blank_values=True)
        for k in list(params.keys()):
            if k.lower() in _NAME_PARAMS:
                del params[k]
        sorted_q = urlencode(sorted((k, v[0]) for k, v in params.items()))

        canonical = f"{scheme}://{netloc}{path}"
        if sorted_q:
            canonical += f"?{sorted_q}"
        return hashlib.sha256(canonical.encode()).hexdigest()

    except Exception:
        return hashlib.sha256(url.encode()).hexdigest()


# ─── Стандартное имя ─────────────────────────────────────────────────────────

def apply_standard_name(url: str, counter: int) -> str:
    """
    Заменяет имя прокси стандартным: 'PROTOCOL | host:port | #00001'.
    Работает для всех протоколов, включая vmess (JSON) и ssr (base64).
    """
    scheme = urlparse(url).scheme.lower()
    label  = SCHEME_LABEL.get(scheme, scheme.upper())
    host, port = _host_port(url)
    new_name   = f"{label} | {host}:{port} | #{counter:05d}"

    if scheme == "vmess":
        obj = _vmess_decode(url)
        if obj:
            obj["ps"] = new_name
            return _vmess_encode(obj)
        return url

    if scheme == "ssr":
        body    = url[len("ssr://"):]
        decoded = _b64decode(body)
        if decoded:
            if "/?" in decoded:
                core, qstr = decoded.split("/?", 1)
                params = parse_qs(qstr, keep_blank_values=True)
                params["remarks"] = [_b64encode(new_name)]
                new_q = urlencode({k: v[0] for k, v in params.items()})
                new_decoded = f"{core}/?{new_q}"
            else:
                core = decoded.split("#")[0].rstrip("/")
                new_decoded = f"{core}/?remarks={_b64encode(new_name)}"
            return "ssr://" + base64.urlsafe_b64encode(
                new_decoded.encode()
            ).decode().rstrip("=")
        return url

    # Все остальные: имя в URL-фрагменте
    try:
        parsed = urlparse(url)
        return urlunparse((
            scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            quote(new_name, safe=" |:#"),
        ))
    except Exception:
        return url


# ─── Нормализация и валидация ─────────────────────────────────────────────────

def normalize_proxy(raw: str) -> str | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        parsed = urlparse(raw)
    except Exception:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in PROXY_SCHEMES:
        return None

    if scheme == "vmess":
        if _vmess_decode(raw) is None:
            return None
        return raw

    if scheme == "ss":
        if _ss_components(raw) is None and len(parsed.netloc) < 4:
            return None

    if not parsed.netloc and len(parsed.path) < 4:
        return None

    fragment = unquote(parsed.fragment).strip() if parsed.fragment else ""
    try:
        return urlunparse((
            scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            fragment,
        ))
    except Exception:
        return None


# ─── Загрузка источников ──────────────────────────────────────────────────────

def fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": (
            "Mozilla/5.0 (compatible; ProxyCollector/2.0; "
            "+https://github.com/your-username/proxy-collector)"
        ),
        "Accept": "text/plain, text/html, */*",
    })
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                raw = resp.read()
                for enc in ("utf-8", "latin-1", "cp1251"):
                    try:
                        return raw.decode(enc)
                    except UnicodeDecodeError:
                        continue
                return raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            log.warning("HTTP %s: %s (попытка %d/%d)", e.code, url, attempt, MAX_RETRIES)
        except urllib.error.URLError as e:
            log.warning("URLError: %s — %s (попытка %d/%d)", url, e.reason, attempt, MAX_RETRIES)
        except Exception as e:
            log.warning("Ошибка: %s — %s (попытка %d/%d)", url, e, attempt, MAX_RETRIES)
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY)
    return ""


def extract_proxies(text: str, _depth: int = 0) -> list[str]:
    """
    Извлекает прокси из текста:
    1. Прямой regex-поиск по схемам
    2. Декодирование Base64-блоков (subscription-формат, рекурсивно)
    """
    if _depth > 3:
        return []

    proxies: list[str] = []

    for match in PROXY_RE.finditer(text):
        scheme = match.group(1)
        rest   = match.group(2)
        rest   = re.split(r'[\s"\'\]\)>]', rest)[0]
        proxies.append(f"{scheme}://{rest}")

    if proxies:
        return proxies

    if _looks_like_b64(text):
        decoded = _b64decode(text)
        if decoded:
            log.debug("Base64-блок (%d->%d) уровень %d", len(text), len(decoded), _depth)
            proxies.extend(extract_proxies(decoded, _depth + 1))
            if proxies:
                return proxies

    for line in text.splitlines():
        line = line.strip()
        if _looks_like_b64(line):
            decoded = _b64decode(line)
            if decoded:
                found = extract_proxies(decoded, _depth + 1)
                if found:
                    proxies.extend(found)

    return proxies


def load_sources(source_file: str) -> list[str]:
    path = Path(source_file)
    if not path.exists():
        log.error("Файл источников не найден: %s", source_file)
        return []
    urls = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    log.info("Источников: %d из %s", len(urls), source_file)
    return urls


# ─── Сортировка ───────────────────────────────────────────────────────────────

_SCHEME_ORDER = {s: i for i, s in enumerate([
    "vless", "vmess", "trojan",
    "ss", "ssr",
    "hy2", "hysteria2", "hysteria",
    "tuic", "naive", "brook", "juicity",
    "wireguard", "wg",
])}


def _sort_key(proxy: str) -> tuple:
    try:
        host, port = _host_port(proxy)
        scheme     = urlparse(proxy).scheme.lower()
        order      = _SCHEME_ORDER.get(scheme, 99)
        return (order, host, port, proxy)
    except Exception:
        return (99, "", 0, proxy)


# ─── Статистика ───────────────────────────────────────────────────────────────

def build_stats(
    proxies: list[str],
    sources_total: int,
    sources_ok: int,
    raw_count: int,
    dup_count: int,
) -> str:
    counter: dict[str, int] = defaultdict(int)
    for p in proxies:
        scheme = urlparse(p).scheme.lower()
        label  = SCHEME_LABEL.get(scheme, scheme.upper())
        counter[label] += 1

    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    w     = 57
    lines = [
        "# " + "═" * w,
        "#  Proxy Collector v2 — результат сборки",
        "# " + "─" * w,
        f"#  Обновлено  : {now}",
        f"#  Источников : {sources_ok}/{sources_total} успешно загружено",
        f"#  Извлечено  : {raw_count} (до дедупликации)",
        f"#  Дубликатов : {dup_count} удалено",
        f"#  Итого      : {len(proxies)} уникальных прокси",
        "# " + "─" * w,
        "#  По протоколам:",
    ]
    max_c = max(counter.values()) if counter else 1
    for label, count in sorted(counter.items(), key=lambda x: -x[1]):
        bar = "█" * max(1, round(count / max_c * 25))
        lines.append(f"#    {label:<12} {count:>5}  {bar}")
    lines.append("# " + "═" * w)
    return "\n".join(lines)


# ─── Основная логика ──────────────────────────────────────────────────────────

def run(
    source_file: str = SOURCE_FILE,
    result_file: str = RESULT_FILE,
    verbose: bool = False,
) -> int:
    setup_logging(verbose)
    log.info("════ Proxy Collector v2 запущен ════")

    urls = load_sources(source_file)
    if not urls:
        log.error("Нет источников.")
        return 1

    all_raw: list[str] = []
    sources_ok = 0
    for idx, url in enumerate(urls, 1):
        log.info("[%d/%d] %s", idx, len(urls), url)
        text = fetch_url(url)
        if not text:
            log.warning("  ↳ Пустой ответ, пропускаем.")
            continue
        found = extract_proxies(text)
        log.info("  ↳ Найдено: %d", len(found))
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
    log.info("После нормализации: %d", len(normalized))

    # Дедупликация по отпечатку соединения (имя игнорируется)
    seen:   set[str]  = set()
    unique: list[str] = []
    for p in normalized:
        fp = connection_fingerprint(p)
        if fp not in seen:
            seen.add(fp)
            unique.append(p)

    dup_count = len(normalized) - len(unique)
    log.info("После дедупликации: %d (удалено дублей: %d)", len(unique), dup_count)

    # Сортировка
    unique.sort(key=_sort_key)

    # Применяем стандартные имена (глобальный счётчик)
    renamed: list[str] = []
    for counter, proxy in enumerate(unique, start=1):
        renamed.append(apply_standard_name(proxy, counter))

    # Запись
    stats   = build_stats(renamed, len(urls), sources_ok, raw_count, dup_count)
    content = stats + "\n\n" + "\n".join(renamed) + "\n"
    Path(result_file).write_text(content, encoding="utf-8")

    log.info("Сохранено: %s (%d прокси)", result_file, len(renamed))
    log.info("════ Готово ════")
    return 0


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Proxy Collector v2 — сборщик, дедупликатор, нормализатор."
    )
    parser.add_argument("-s", "--source", default=SOURCE_FILE,
                        help=f"Файл источников (по умолчанию: {SOURCE_FILE})")
    parser.add_argument("-o", "--output", default=RESULT_FILE,
                        help=f"Файл результатов (по умолчанию: {RESULT_FILE})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Подробный вывод (DEBUG)")
    args = parser.parse_args()
    sys.exit(run(args.source, args.output, args.verbose))
