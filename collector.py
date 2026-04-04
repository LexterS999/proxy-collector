#!/usr/bin/env python3
"""
Proxy Collector v4 — сборщик, дедупликатор и нормализатор прокси.

Поддерживает: vless://, vmess://, trojan://, ss://, ssr://,
              hy2://, hysteria://, hysteria2://, tuic://,
              naive://, brook://, juicity://, wg://, wireguard://

Геолокация : ip-api.com (бесплатно, без ключа, до 45 req/min)
             Умный rate-limit: читает заголовки X-Rl / X-Ttl,
             экспоненциальный backoff при 429, фильтр приватных IP.
Имя прокси : "🇺🇸 VLESS"  (флаг + протокол, без лишних полей)
Результаты : result.txt (все протоколы) + results/<protocol>.txt
"""

import re
import sys
import json
import time
import socket
import base64
import logging
import hashlib
import argparse
import ipaddress
import urllib.request
import urllib.error
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse, unquote,
)
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

# ─── Настройки ────────────────────────────────────────────────────────────────

SOURCE_FILE  = "source.txt"
RESULT_FILE  = "result.txt"
RESULTS_DIR  = "results"
LOG_FILE     = "collector.log"
TIMEOUT      = 20    # сек на загрузку источника
MAX_RETRIES  = 3
RETRY_DELAY  = 3     # сек между попытками загрузки

# ip-api.com: batch POST, бесплатно, до 45 req/min без ключа
# Документация: https://ip-api.com/docs/api:batch
GEO_API_URL     = "http://ip-api.com/batch"
GEO_BATCH_SIZE  = 50    # уменьшаем до 50 (запас по rate-limit)
GEO_TIMEOUT     = 15    # сек ожидания ответа
GEO_RATE_SLEEP  = 2.0   # базовая пауза между батчами (30 батчей/мин < 45 лимита)
GEO_RETRY_SLEEP = 65    # сек ожидания после 429 (подождать сброс минутного окна)
GEO_MAX_RETRY   = 3     # максимум повторов при 429

# ─── Протоколы ────────────────────────────────────────────────────────────────

PROXY_SCHEMES = [
    "vless", "vmess", "trojan",
    "ss", "ssr",
    "hy2", "hysteria2", "hysteria",
    "tuic", "naive", "brook", "juicity",
    "wireguard", "wg",
]

# Красивые метки протоколов для имён прокси
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

# Канонические имена файлов в results/ (несколько схем → один файл)
SCHEME_FILENAME: dict[str, str] = {
    "vless":     "vless",
    "vmess":     "vmess",
    "trojan":    "trojan",
    "ss":        "ss",
    "ssr":       "ssr",
    "hy2":       "hy2",
    "hysteria2": "hy2",
    "hysteria":  "hysteria",
    "tuic":      "tuic",
    "naive":     "naive",
    "brook":     "brook",
    "juicity":   "juicity",
    "wireguard": "wg",
    "wg":        "wg",
}

# Параметры запроса, несущие ТОЛЬКО имя — не влияют на соединение
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


# ─── Геолокация — ip-api.com ──────────────────────────────────────────────────

def _country_flag(country_code: str) -> str:
    """
    ISO 3166-1 alpha-2 → Unicode Regional Indicator Symbol пара (флаг).
    Например: "US" → "🇺🇸", "DE" → "🇩🇪".
    На Android и Linux отображается как цветной флаг.
    На Windows (без поддержки флагов) — читаемая пара букв: US, DE, RU.
    Для неизвестных хостов возвращает 🌐 (U+1F310).
    """
    if not country_code or len(country_code) != 2:
        return "\U0001F310"
    cc = country_code.upper()
    if not cc.isalpha():
        return "\U0001F310"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc)


def _is_private_host(host: str) -> bool:
    """True для приватных/зарезервированных IP и localhost — геолокация им не нужна."""
    if not host or host in ("unknown", "localhost", ""):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_unspecified
    except ValueError:
        # Домен — не приватный
        return host.endswith((".local", ".internal", ".localhost"))


def _geo_batch_request(batch: list[str]) -> dict[str, str]:
    """
    Один POST-запрос к ip-api.com/batch с автоматическим backoff при 429.
    Возвращает {host: country_code} для успешных записей.
    Читает заголовки X-Rl (requests left) и X-Ttl (seconds to reset)
    для точного управления паузами.
    """
    payload = json.dumps(
        [{"query": h, "fields": "query,countryCode,status"} for h in batch]
    ).encode("utf-8")
    req = urllib.request.Request(
        GEO_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    for attempt in range(1, GEO_MAX_RETRY + 1):
        try:
            with urllib.request.urlopen(req, timeout=GEO_TIMEOUT) as resp:
                # Читаем X-Rl / X-Ttl для точного rate-limit контроля
                rl  = resp.headers.get("X-Rl",  "")
                ttl = resp.headers.get("X-Ttl", "")
                try:
                    remaining = int(rl)
                    if remaining <= 2:
                        # Почти достигли лимита — ждём сброс окна
                        wait = max(int(ttl) if ttl else GEO_RETRY_SLEEP, 5)
                        log.info("Rate-limit: осталось %d req, жду %d сек...", remaining, wait)
                        time.sleep(wait)
                except (ValueError, TypeError):
                    pass

                result: dict[str, str] = {}
                items = json.loads(resp.read().decode("utf-8"))
                for item in items:
                    if item.get("status") == "success":
                        q  = item.get("query", "").lower()
                        cc = item.get("countryCode", "").upper()
                        if q and cc and len(cc) == 2 and cc.isalpha():
                            result[q] = cc
                return result

        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = GEO_RETRY_SLEEP * attempt  # экспоненциальный backoff
                log.warning("429 Too Many Requests — жду %d сек (попытка %d/%d)...",
                            wait, attempt, GEO_MAX_RETRY)
                time.sleep(wait)
            else:
                log.warning("Geo HTTP %s, пропускаем батч: %s", e.code, e)
                return {}
        except Exception as e:
            if attempt < GEO_MAX_RETRY:
                wait = GEO_RATE_SLEEP * (2 ** attempt)
                log.warning("Geo ошибка (%s), retry %d/%d через %.0f сек...",
                            e, attempt, GEO_MAX_RETRY, wait)
                time.sleep(wait)
            else:
                log.warning("Geo батч пропущен после %d попыток: %s", GEO_MAX_RETRY, e)
                return {}

    return {}


def geolocate_hosts(hosts: list[str]) -> dict[str, str]:
    """
    Геолоцирует список хостов через ip-api.com/batch.
    Возвращает {host.lower(): "US"}.

    Оптимизации:
    - Фильтрует приватные/loopback IP (геолокация не нужна)
    - Дедуплицирует хосты перед запросами
    - Управляет паузами по заголовкам X-Rl / X-Ttl
    - Экспоненциальный backoff при 429
    """
    if not hosts:
        return {}

    # Фильтруем: только уникальные публичные хосты
    public_hosts = list(dict.fromkeys(
        h.lower() for h in hosts
        if h and not _is_private_host(h)
    ))

    if not public_hosts:
        log.info("Геолокация: нет публичных хостов для запроса.")
        return {}

    total_batches = (len(public_hosts) + GEO_BATCH_SIZE - 1) // GEO_BATCH_SIZE
    log.info("Геолокация: %d уникальных хостов → %d батч(ей) по %d...",
             len(public_hosts), total_batches, GEO_BATCH_SIZE)

    result: dict[str, str] = {}

    for batch_idx, i in enumerate(range(0, len(public_hosts), GEO_BATCH_SIZE), 1):
        batch = public_hosts[i : i + GEO_BATCH_SIZE]
        batch_result = _geo_batch_request(batch)
        result.update(batch_result)
        log.debug("Батч %d/%d: определено %d/%d", batch_idx, total_batches,
                  len(batch_result), len(batch))

        # Фиксированная пауза между батчами (кроме последнего)
        if i + GEO_BATCH_SIZE < len(public_hosts):
            time.sleep(GEO_RATE_SLEEP)

    log.info("Геолокация: определено %d/%d (не определено: %d)",
             len(result), len(public_hosts), len(public_hosts) - len(result))
    return result


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
    ss:// → (method, password, host, port).
    Поддерживает форматы: base64(method:pass)@host:port,
    base64(method:pass@host:port), plain method:pass@host:port.
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
        return decoded.split("/?")[0].split("#")[0].lower()
    except Exception:
        return url


def _host_port(url: str) -> tuple:
    """
    Возвращает (host, port) из любого прокси-URL.
    Устойчив к IPv6-адресам и нестандартным портам.
    """
    scheme = urlparse(url).scheme.lower()

    if scheme == "vmess":
        obj = _vmess_decode(url)
        if obj:
            try:
                return str(obj.get("add", "unknown")).lower(), int(obj.get("port", 0))
            except (ValueError, TypeError):
                return str(obj.get("add", "unknown")).lower(), 0

    if scheme == "ss":
        comp = _ss_components(url)
        if comp:
            return comp[2], comp[3]

    if scheme == "ssr":
        core  = _ssr_core(url)
        parts = core.split(":")
        if len(parts) >= 2:
            try:
                return parts[0], int(parts[1])
            except (ValueError, IndexError):
                pass

    parsed = urlparse(url)
    host   = (parsed.hostname or "unknown").lower()

    # Безопасное извлечение порта — порт может быть невалидным у некоторых
    # источников (например IPv6 без скобок внутри netloc).
    try:
        port = parsed.port or 0
    except ValueError:
        # Fallback: парсим порт вручную из netloc
        netloc = parsed.netloc
        # Убираем возможный userinfo
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
        # Ищем последнее ":" не внутри IPv6 []
        if netloc.startswith("["):
            # IPv6: [addr]:port или просто [addr]
            bracket_end = netloc.find("]")
            if bracket_end != -1 and bracket_end + 2 <= len(netloc):
                try:
                    port = int(netloc[bracket_end + 2:])
                except ValueError:
                    port = 0
            else:
                port = 0
        else:
            # Обычный host: берём всё после последнего ":"
            parts = netloc.rsplit(":", 1)
            try:
                port = int(parts[1]) if len(parts) == 2 else 0
            except (ValueError, IndexError):
                port = 0

    return host, (port or 0)


# ─── Дедупликация — отпечаток соединения ─────────────────────────────────────

def connection_fingerprint(url: str) -> str:
    """
    SHA-256 от параметров подключения. Имя/remark/fragment исключены.
    Один сервер с разными именами → один отпечаток.
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
                return hashlib.sha256(
                    f"ss:{method}:{password}:{host}:{port}".encode()
                ).hexdigest()

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


# ─── Стандартное имя с флагом ─────────────────────────────────────────────────

def apply_standard_name(url: str, country_code: str = "") -> str:
    """
    Заменяет имя прокси стандартным: "FLAG PROTOCOL"
    Пример: "🇺🇸 VLESS"

    Для vmess — меняет поле ps в JSON.
    Для ssr   — меняет remarks в base64-теле.
    Для всех остальных — ставит в URL-фрагмент (после #).
    """
    scheme   = urlparse(url).scheme.lower()
    label    = SCHEME_LABEL.get(scheme, scheme.upper())
    flag     = _country_flag(country_code)
    new_name = f"{flag} {label}"

    # ── VMess ──────────────────────────────────────────────────────────────
    if scheme == "vmess":
        obj = _vmess_decode(url)
        if obj:
            obj["ps"] = new_name
            return _vmess_encode(obj)
        return url

    # ── SSR ────────────────────────────────────────────────────────────────
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

    # ── Все остальные: имя в URL-фрагменте ─────────────────────────────────
    # Строим вручную чтобы emoji-флаги не кодировались в %XX
    try:
        parsed   = urlparse(url)
        base_url = urlunparse((
            scheme, parsed.netloc, parsed.path,
            parsed.params, parsed.query, "",
        ))
        return base_url + "#" + new_name
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
            scheme, parsed.netloc, parsed.path,
            parsed.params, parsed.query, fragment,
        ))
    except Exception:
        return None


# ─── Загрузка источников ──────────────────────────────────────────────────────

def fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": (
            "Mozilla/5.0 (compatible; ProxyCollector/4.0; "
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
            log.debug("Base64-блок (%d→%d), уровень %d", len(text), len(decoded), _depth)
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


def _sort_key(item: tuple) -> tuple:
    proxy, country_code = item
    try:
        host, port = _host_port(proxy)
        scheme     = urlparse(proxy).scheme.lower()
        order      = _SCHEME_ORDER.get(scheme, 99)
        return (order, country_code or "ZZ", host, port)
    except Exception:
        return (99, "ZZ", "", 0)


# ─── Запись результатов ───────────────────────────────────────────────────────

def _file_header(title: str, now: str, count: int) -> str:
    w = 59
    return "\n".join([
        "# " + "═" * w,
        f"#  {title}",
        f"#  Обновлено: {now}",
        f"#  Прокси  : {count}",
        "# " + "═" * w,
        "",
    ])


def write_results(
    proxies: list[str],
    geo_cache: dict[str, str],
    result_file: str,
    results_dir: str,
    sources_total: int,
    sources_ok: int,
    raw_count: int,
    dup_count: int,
) -> None:
    """
    1. result.txt  — все протоколы с полной статистикой
    2. results/<protocol>.txt — отдельный файл на каждый протокол
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Статистика по протоколам и странам ────────────────────────────────
    proto_counter:   dict[str, int] = defaultdict(int)
    country_counter: dict[str, int] = defaultdict(int)
    for p in proxies:
        scheme = urlparse(p).scheme.lower()
        label  = SCHEME_LABEL.get(scheme, scheme.upper())
        proto_counter[label] += 1
        host, _ = _host_port(p)
        cc      = geo_cache.get(host.lower(), "")
        country_counter[cc or "??"] += 1

    w = 59
    stats_lines = [
        "# " + "═" * w,
        "#  Proxy Collector v4 — результат сборки",
        "# " + "─" * w,
        f"#  Обновлено  : {now}",
        f"#  Источников : {sources_ok}/{sources_total} успешно",
        f"#  Извлечено  : {raw_count} (до дедупликации)",
        f"#  Дубликатов : {dup_count} удалено",
        f"#  Итого      : {len(proxies)} уникальных прокси",
        "# " + "─" * w,
        "#  Протоколы:",
    ]
    max_p = max(proto_counter.values()) if proto_counter else 1
    for label, count in sorted(proto_counter.items(), key=lambda x: -x[1]):
        bar = "█" * max(1, round(count / max_p * 24))
        stats_lines.append(f"#    {label:<12} {count:>5}  {bar}")

    stats_lines.append("# " + "─" * w)
    stats_lines.append("#  Топ-10 стран:")
    top10 = sorted(country_counter.items(), key=lambda x: -x[1])[:10]
    max_c = top10[0][1] if top10 else 1
    for cc, count in top10:
        flag = _country_flag(cc) if cc not in ("??", "") else "🌐"
        bar  = "█" * max(1, round(count / max_c * 24))
        stats_lines.append(f"#    {flag} {cc:<4} {count:>5}  {bar}")
    stats_lines.append("# " + "═" * w)

    # ── Запись result.txt ─────────────────────────────────────────────────
    content = "\n".join(stats_lines) + "\n\n" + "\n".join(proxies) + "\n"
    Path(result_file).write_text(content, encoding="utf-8")
    log.info("Записан %s: %d прокси", result_file, len(proxies))

    # ── Запись results/<protocol>.txt ─────────────────────────────────────
    rd = Path(results_dir)
    rd.mkdir(exist_ok=True)

    # Группируем по каноническому имени файла
    groups: dict[str, list[str]] = defaultdict(list)
    for p in proxies:
        scheme   = urlparse(p).scheme.lower()
        filename = SCHEME_FILENAME.get(scheme, scheme)
        groups[filename].append(p)

    for filename, group_proxies in sorted(groups.items()):
        fpath  = rd / f"{filename}.txt"
        header = _file_header(
            f"{filename.upper()} — {len(group_proxies)} прокси",
            now,
            len(group_proxies),
        )
        fpath.write_text(header + "\n".join(group_proxies) + "\n", encoding="utf-8")
        log.info("  results/%s.txt: %d прокси", filename, len(group_proxies))

    # Удаляем файлы протоколов, которых нет в текущей выборке
    for old_file in rd.glob("*.txt"):
        if old_file.stem not in groups:
            old_file.unlink()
            log.info("  Удалён устаревший %s", old_file)


# ─── Основная логика ──────────────────────────────────────────────────────────

def run(
    source_file: str = SOURCE_FILE,
    result_file: str = RESULT_FILE,
    results_dir: str = RESULTS_DIR,
    verbose: bool = False,
) -> int:
    setup_logging(verbose)
    log.info("════ Proxy Collector v4 запущен ════")

    # 1. Загрузка источников
    urls = load_sources(source_file)
    if not urls:
        log.error("Нет источников.")
        return 1

    # 2. Сбор сырых прокси
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

    # 3. Нормализация
    normalized: list[str] = []
    for p in all_raw:
        n = normalize_proxy(p)
        if n:
            normalized.append(n)
    log.info("После нормализации: %d", len(normalized))

    # 4. Дедупликация по отпечатку соединения (имена игнорируются)
    seen:   set[str]  = set()
    unique: list[str] = []
    for p in normalized:
        fp = connection_fingerprint(p)
        if fp not in seen:
            seen.add(fp)
            unique.append(p)

    dup_count = len(normalized) - len(unique)
    log.info("После дедупликации: %d (удалено дублей: %d)", len(unique), dup_count)

    # 5. Безопасное извлечение хостов (с защитой от IPv6-ошибок)
    all_hosts: list[str] = []
    for p in unique:
        try:
            host, _ = _host_port(p)
            all_hosts.append(host)
        except Exception as e:
            log.debug("_host_port error для %s: %s", p[:80], e)
            all_hosts.append("unknown")

    # 6. Геолокация публичных хостов
    geo_cache = geolocate_hosts(all_hosts)

    # 7. Сортировка: протокол → страна → хост → порт
    pairs = [
        (p, geo_cache.get(all_hosts[i].lower(), ""))
        for i, p in enumerate(unique)
    ]
    pairs.sort(key=_sort_key)

    # 8. Применяем стандартные имена "FLAG PROTOCOL"
    renamed: list[str] = []
    for proxy, cc in pairs:
        renamed.append(apply_standard_name(proxy, cc))

    # 9. Запись всех файлов
    geo_final = {all_hosts[i].lower(): geo_cache.get(all_hosts[i].lower(), "")
                 for i in range(len(unique))}
    write_results(
        renamed, geo_final,
        result_file, results_dir,
        len(urls), sources_ok, raw_count, dup_count,
    )

    log.info("════ Готово ════")
    return 0


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Proxy Collector v4 — сборщик, дедупликатор, нормализатор."
    )
    parser.add_argument("-s", "--source",  default=SOURCE_FILE,
                        help=f"Файл источников (по умолчанию: {SOURCE_FILE})")
    parser.add_argument("-o", "--output",  default=RESULT_FILE,
                        help=f"Файл результатов (по умолчанию: {RESULT_FILE})")
    parser.add_argument("-r", "--results", default=RESULTS_DIR,
                        help=f"Папка результатов по протоколам (по умолчанию: {RESULTS_DIR})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Подробный вывод (DEBUG)")
    args = parser.parse_args()
    sys.exit(run(args.source, args.output, args.results, args.verbose))
