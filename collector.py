#!/usr/bin/env python3
"""
Proxy Collector v5 — сборщик, дедупликатор и нормализатор прокси.

Поддерживает: vless://, vmess://, trojan://, ss://, ssr://,
              hy2://, hysteria://, hysteria2://, tuic://,
              naive://, brook://, juicity://, wg://, wireguard://

Ускорения v5:
  • Параллельная загрузка источников (ThreadPoolExecutor)
  • Параллельные geo-батчи с token-bucket rate limiter (40 req/min)
  • Увеличен batch до 100 хостов (меньше HTTP-запросов)
  • Фильтрация приватных IP до геолокации
  • Автоматический backoff при 429 с чтением X-Rl / X-Ttl

Геолокация : ip-api.com (бесплатно, без ключа)
Имя прокси : "🇺🇸 VLESS"
Результаты : result.txt + results/<protocol>.txt
"""

import re
import sys
import json
import time
import base64
import logging
import hashlib
import argparse
import ipaddress
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse, unquote,
)
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

# ─── Настройки ────────────────────────────────────────────────────────────────

SOURCE_FILE      = "source.txt"
RESULT_FILE      = "result.txt"
RESULTS_DIR      = "results"
LOG_FILE         = "collector.log"
FETCH_TIMEOUT    = 20    # сек на загрузку одного источника
FETCH_WORKERS    = 10    # параллельных загрузок источников
MAX_RETRIES      = 3
RETRY_DELAY      = 3

# Геолокация — ip-api.com
GEO_API_URL      = "http://ip-api.com/batch"
GEO_BATCH_SIZE   = 100   # max разрешённый batch
GEO_WORKERS      = 3     # параллельных geo-потоков (3 × ≈13 req/min = 39 < 45)
GEO_RATE_PER_MIN = 40    # консервативный лимит (45 — официальный, берём 40)
GEO_TIMEOUT      = 15
GEO_MAX_RETRY    = 3
GEO_RETRY_BASE   = 65    # сек backoff при 429

# ─── Протоколы ────────────────────────────────────────────────────────────────

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
    "hysteria":  "HY2",    # hy2:// hysteria2:// hysteria:// — один тип
    "tuic":      "TUIC",
    "naive":     "NAIVE",
    "brook":     "BROOK",
    "juicity":   "JUICITY",
    "wireguard": "WG",
    "wg":        "WG",
}

# Все варианты Hysteria → один файл hy2.txt
SCHEME_FILENAME: dict[str, str] = {
    "vless":     "vless",
    "vmess":     "vmess",
    "trojan":    "trojan",
    "ss":        "ss",
    "ssr":       "ssr",
    "hy2":       "hy2",
    "hysteria2": "hy2",
    "hysteria":  "hy2",
    "tuic":      "tuic",
    "naive":     "naive",
    "brook":     "brook",
    "juicity":   "juicity",
    "wireguard": "wg",
    "wg":        "wg",
}

_NAME_PARAMS = frozenset({"remarks", "remark", "name", "title", "label", "alias"})

_SCHEMES_PAT = "|".join(re.escape(s) for s in PROXY_SCHEMES)
PROXY_RE = re.compile(
    rf'(?:^|[\s"\',;`])({_SCHEMES_PAT})://([\S]+)',
    re.IGNORECASE | re.MULTILINE,
)

# ─── Логирование ──────────────────────────────────────────────────────────────

log = logging.getLogger("collector")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
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


# ─── Token-bucket rate limiter ────────────────────────────────────────────────

class RateLimiter:
    """
    Потокобезопасный token-bucket rate limiter.
    Гарантирует не более rate_per_minute вызовов/мин глобально
    среди всех потоков через общий мьютекс и монотонный таймер.
    """

    def __init__(self, rate_per_minute: int) -> None:
        self._interval = 60.0 / rate_per_minute  # минимальный интервал между вызовами
        self._lock      = threading.Lock()
        self._last_time = 0.0

    def acquire(self) -> None:
        """Блокирует вызывающий поток до получения разрешения."""
        with self._lock:
            now  = time.monotonic()
            wait = self._last_time + self._interval - now
            if wait > 0:
                time.sleep(wait)
            self._last_time = time.monotonic()


# Глобальный лимитер — один на весь процесс
_geo_limiter = RateLimiter(GEO_RATE_PER_MIN)


# ─── Геолокация — ip-api.com ──────────────────────────────────────────────────

def _country_flag(country_code: str) -> str:
    """
    ISO 3166-1 alpha-2 → Unicode Regional Indicator Symbol пара (флаг).
    "US" → "🇺🇸", "DE" → "🇩🇪".
    На Android/Linux — цветной флаг. На Windows — читаемая пара букв (US, DE).
    Для неизвестных возвращает 🌐 (U+1F310).
    """
    if not country_code or len(country_code) != 2:
        return "\U0001F310"
    cc = country_code.upper()
    if not cc.isalpha():
        return "\U0001F310"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc)


def _is_private_host(host: str) -> bool:
    """True для приватных/зарезервированных IP и localhost — не геолоцируем."""
    if not host or host in ("unknown", "localhost", ""):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return (addr.is_private or addr.is_loopback
                or addr.is_reserved or addr.is_unspecified)
    except ValueError:
        return host.endswith((".local", ".internal", ".localhost"))


def _geo_single_batch(batch: list[str]) -> dict[str, str]:
    """
    Один POST-запрос к ip-api.com/batch.
    Вызывает _geo_limiter.acquire() перед отправкой — потокобезопасно.
    Читает X-Rl / X-Ttl для дополнительной паузы если лимит почти исчерпан.
    Экспоненциальный backoff при 429.
    """
    payload = json.dumps(
        [{"query": h, "fields": "query,countryCode,status"} for h in batch]
    ).encode("utf-8")
    req = urllib.request.Request(
        GEO_API_URL, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    for attempt in range(1, GEO_MAX_RETRY + 1):
        _geo_limiter.acquire()   # ждём своей очереди согласно rate limit
        try:
            with urllib.request.urlopen(req, timeout=GEO_TIMEOUT) as resp:
                # Читаем X-Rl: если осталось ≤ 2 запроса — даём паузу сверху
                try:
                    rl = int(resp.headers.get("X-Rl", "99"))
                    if rl <= 2:
                        ttl = int(resp.headers.get("X-Ttl", "5"))
                        log.debug("Rate-limit: X-Rl=%d, дополнительная пауза %ds", rl, ttl)
                        time.sleep(max(ttl, 2))
                except (ValueError, TypeError):
                    pass

                result: dict[str, str] = {}
                for item in json.loads(resp.read().decode("utf-8")):
                    if item.get("status") == "success":
                        q  = item.get("query", "").lower()
                        cc = item.get("countryCode", "").upper()
                        if q and cc and len(cc) == 2 and cc.isalpha():
                            result[q] = cc
                return result

        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = GEO_RETRY_BASE * attempt
                log.warning("429 Too Many Requests — backoff %ds (попытка %d/%d)",
                            wait, attempt, GEO_MAX_RETRY)
                time.sleep(wait)
            else:
                log.warning("Geo HTTP %s, пропускаем батч.", e.code)
                return {}
        except Exception as e:
            if attempt < GEO_MAX_RETRY:
                wait = 5 * (2 ** attempt)
                log.debug("Geo ошибка (%s), retry %d/%d через %ds", e, attempt, GEO_MAX_RETRY, wait)
                time.sleep(wait)
            else:
                log.warning("Geo батч пропущен: %s", e)
                return {}

    return {}


def geolocate_hosts(hosts: list[str]) -> dict[str, str]:
    """
    Геолоцирует список хостов через ip-api.com/batch.
    Возвращает {host.lower(): "US"}.

    Оптимизации v5:
    - Фильтрует приватные/loopback IP (не запрашиваем их)
    - Дедуплицирует хосты
    - GEO_WORKERS параллельных потоков с общим RateLimiter
    - Батч 100 хостов — минимум HTTP-вызовов
    """
    if not hosts:
        return {}

    public_hosts = list(dict.fromkeys(
        h.lower() for h in hosts
        if h and not _is_private_host(h)
    ))

    if not public_hosts:
        log.info("Геолокация: публичных хостов нет.")
        return {}

    batches = [
        public_hosts[i : i + GEO_BATCH_SIZE]
        for i in range(0, len(public_hosts), GEO_BATCH_SIZE)
    ]
    total = len(batches)
    log.info(
        "Геолокация: %d хостов → %d батч(ей) × %d, %d воркеров, лимит %d req/min",
        len(public_hosts), total, GEO_BATCH_SIZE, GEO_WORKERS, GEO_RATE_PER_MIN,
    )

    result:   dict[str, str] = {}
    done_lock = threading.Lock()
    done_count = [0]  # list для мутации внутри closure

    def _run_batch(idx: int, batch: list[str]) -> dict[str, str]:
        res = _geo_single_batch(batch)
        with done_lock:
            done_count[0] += 1
            if done_count[0] % 10 == 0 or done_count[0] == total:
                log.info("  Geo: %d/%d батчей завершено...", done_count[0], total)
        return res

    with ThreadPoolExecutor(max_workers=GEO_WORKERS, thread_name_prefix="geo") as pool:
        futures = {
            pool.submit(_run_batch, idx, batch): idx
            for idx, batch in enumerate(batches, 1)
        }
        for future in as_completed(futures):
            try:
                result.update(future.result())
            except Exception as e:
                log.warning("Geo future error: %s", e)

    log.info(
        "Геолокация завершена: определено %d/%d (не определено: %d)",
        len(result), len(public_hosts), len(public_hosts) - len(result),
    )
    return result


# ─── Парсеры протоколов ───────────────────────────────────────────────────────

def _vmess_decode(url: str) -> dict | None:
    try:
        decoded = _b64decode(url[len("vmess://"):])
        if decoded:
            return json.loads(decoded)
    except Exception:
        pass
    return None


def _vmess_encode(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _ss_components(url: str) -> tuple | None:
    try:
        body = url.split("#")[0].strip()[len("ss://"):]
        if "@" in body:
            at_idx   = body.rindex("@")
            userinfo = body[:at_idx]
            hostport = body[at_idx + 1:]
            dec_ui   = _b64decode(userinfo)
            if dec_ui and ":" in dec_ui and len(dec_ui) < 512:
                method, password = dec_ui.split(":", 1)
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
        decoded = _b64decode(url[len("ssr://"):])
        return decoded.split("/?")[0].split("#")[0].lower() if decoded else url
    except Exception:
        return url


def _host_port(url: str) -> tuple:
    """
    Возвращает (host, port). Устойчив к IPv6 и нестандартным портам.
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
        parts = _ssr_core(url).split(":")
        if len(parts) >= 2:
            try:
                return parts[0], int(parts[1])
            except (ValueError, IndexError):
                pass

    parsed = urlparse(url)
    host   = (parsed.hostname or "unknown").lower()

    try:
        port = parsed.port or 0
    except ValueError:
        # IPv6 без скобок или другой нестандартный netloc
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
        if netloc.startswith("["):
            bk = netloc.find("]")
            try:
                port = int(netloc[bk + 2:]) if bk != -1 and bk + 2 <= len(netloc) else 0
            except ValueError:
                port = 0
        else:
            parts = netloc.rsplit(":", 1)
            try:
                port = int(parts[1]) if len(parts) == 2 else 0
            except (ValueError, IndexError):
                port = 0

    return host, (port or 0)


# ─── Дедупликация ─────────────────────────────────────────────────────────────

def connection_fingerprint(url: str) -> str:
    """SHA-256 от параметров подключения. Имя/remark/fragment исключены."""
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
            return hashlib.sha256(f"ssr:{_ssr_core(url)}".encode()).hexdigest()

        parsed  = urlparse(url)
        params  = parse_qs(parsed.query, keep_blank_values=True)
        for k in list(params.keys()):
            if k.lower() in _NAME_PARAMS:
                del params[k]
        sorted_q  = urlencode(sorted((k, v[0]) for k, v in params.items()))
        canonical = f"{scheme}://{parsed.netloc.lower()}{parsed.path}"
        if sorted_q:
            canonical += f"?{sorted_q}"
        return hashlib.sha256(canonical.encode()).hexdigest()

    except Exception:
        return hashlib.sha256(url.encode()).hexdigest()


# ─── Стандартное имя ──────────────────────────────────────────────────────────

def apply_standard_name(url: str, country_code: str = "") -> str:
    """
    Устанавливает стандартное имя прокси: "FLAG PROTOCOL"
    Пример: "🇺🇸 VLESS", "🇩🇪 VMESS", "🌐 SS"
    """
    scheme   = urlparse(url).scheme.lower()
    label    = SCHEME_LABEL.get(scheme, scheme.upper())
    new_name = f"{_country_flag(country_code)} {label}"

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
                new_decoded = f"{core}/?{urlencode({k: v[0] for k, v in params.items()})}"
            else:
                new_decoded = f"{decoded.split('#')[0].rstrip('/')}/?remarks={_b64encode(new_name)}"
            return "ssr://" + base64.urlsafe_b64encode(
                new_decoded.encode()).decode().rstrip("=")
        return url

    # Остальные: имя в URL-фрагменте; строим вручную чтобы emoji не кодировались
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
        return raw if _vmess_decode(raw) is not None else None

    if scheme == "ss":
        if _ss_components(raw) is None and len(parsed.netloc) < 4:
            return None

    if not parsed.netloc and len(parsed.path) < 4:
        return None

    try:
        return urlunparse((
            scheme, parsed.netloc, parsed.path, parsed.params,
            parsed.query, unquote(parsed.fragment).strip(),
        ))
    except Exception:
        return None


# ─── Параллельная загрузка источников ────────────────────────────────────────

def fetch_url(url: str) -> str:
    """Загружает URL с повторными попытками."""
    req = urllib.request.Request(url, headers={
        "User-Agent": (
            "Mozilla/5.0 (compatible; ProxyCollector/5.0; "
            "+https://github.com/your-username/proxy-collector)"
        ),
        "Accept": "text/plain, text/html, */*",
    })
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
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
            log.warning("URLError %s — %s (попытка %d/%d)", url, e.reason, attempt, MAX_RETRIES)
        except Exception as e:
            log.warning("Ошибка %s — %s (попытка %d/%d)", url, e, attempt, MAX_RETRIES)
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY)
    return ""


def fetch_all_sources(urls: list[str]) -> tuple[list[str], int]:
    """
    Параллельная загрузка всех источников (FETCH_WORKERS потоков).
    Возвращает (список_всех_прокси, количество_успешных_источников).
    """
    all_raw: list[str] = []
    sources_ok          = 0
    lock                = threading.Lock()
    total               = len(urls)

    def _fetch_one(idx: int, url: str) -> tuple[list[str], bool]:
        log.info("[%d/%d] %s", idx, total, url)
        text = fetch_url(url)
        if not text:
            log.warning("  ↳ Пустой ответ, пропускаем.")
            return [], False
        found = extract_proxies(text)
        log.info("  ↳ Найдено: %d", len(found))
        return found, True

    with ThreadPoolExecutor(max_workers=FETCH_WORKERS, thread_name_prefix="fetch") as pool:
        futures = {
            pool.submit(_fetch_one, idx, url): url
            for idx, url in enumerate(urls, 1)
        }
        for future in as_completed(futures):
            try:
                proxies, ok = future.result()
                with lock:
                    all_raw.extend(proxies)
                    if ok:
                        sources_ok += 1
            except Exception as e:
                log.warning("Fetch future error: %s", e)

    return all_raw, sources_ok


# ─── Извлечение прокси из текста ──────────────────────────────────────────────

def extract_proxies(text: str, _depth: int = 0) -> list[str]:
    if _depth > 3:
        return []

    proxies: list[str] = []

    for match in PROXY_RE.finditer(text):
        scheme = match.group(1)
        rest   = re.split(r'[\s"\'\]\)>]', match.group(2))[0]
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
        l.strip()
        for l in path.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.strip().startswith("#")
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
    proxy, cc = item
    try:
        host, port = _host_port(proxy)
        order      = _SCHEME_ORDER.get(urlparse(proxy).scheme.lower(), 99)
        return (order, cc or "ZZ", host, port)
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
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    proto_counter:   dict[str, int] = defaultdict(int)
    country_counter: dict[str, int] = defaultdict(int)
    for p in proxies:
        scheme = urlparse(p).scheme.lower()
        proto_counter[SCHEME_LABEL.get(scheme, scheme.upper())] += 1
        host, _ = _host_port(p)
        cc      = geo_cache.get(host.lower(), "")
        country_counter[cc or "??"] += 1

    w = 59
    stats = [
        "# " + "═" * w,
        "#  Proxy Collector v5 — результат сборки",
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
        stats.append(f"#    {label:<12} {count:>5}  {bar}")

    stats.append("# " + "─" * w)
    stats.append("#  Топ-10 стран:")
    top10 = sorted(country_counter.items(), key=lambda x: -x[1])[:10]
    max_c = top10[0][1] if top10 else 1
    for cc, count in top10:
        flag = _country_flag(cc) if cc not in ("??", "") else "🌐"
        bar  = "█" * max(1, round(count / max_c * 24))
        stats.append(f"#    {flag} {cc:<4} {count:>5}  {bar}")
    stats.append("# " + "═" * w)

    # ── result.txt ────────────────────────────────────────────────────────
    Path(result_file).write_text(
        "\n".join(stats) + "\n\n" + "\n".join(proxies) + "\n",
        encoding="utf-8",
    )
    log.info("Записан %s: %d прокси", result_file, len(proxies))

    # ── results/<protocol>.txt ────────────────────────────────────────────
    rd = Path(results_dir)
    rd.mkdir(exist_ok=True)

    groups: dict[str, list[str]] = defaultdict(list)
    for p in proxies:
        groups[SCHEME_FILENAME.get(urlparse(p).scheme.lower(), "other")].append(p)

    for fname, gproxies in sorted(groups.items()):
        fpath = rd / f"{fname}.txt"
        fpath.write_text(
            _file_header(f"{fname.upper()} — {len(gproxies)} прокси", now, len(gproxies))
            + "\n".join(gproxies) + "\n",
            encoding="utf-8",
        )
        log.info("  results/%s.txt: %d прокси", fname, len(gproxies))

    # Удаляем устаревшие файлы протоколов
    for old in rd.glob("*.txt"):
        if old.stem not in groups:
            old.unlink()
            log.info("  Удалён устаревший %s", old.name)


# ─── Основная логика ──────────────────────────────────────────────────────────

def run(
    source_file: str = SOURCE_FILE,
    result_file: str = RESULT_FILE,
    results_dir: str = RESULTS_DIR,
    verbose: bool = False,
) -> int:
    setup_logging(verbose)
    log.info("════ Proxy Collector v5 запущен ════")

    t_start = time.monotonic()

    # 1. Загрузка источников
    urls = load_sources(source_file)
    if not urls:
        log.error("Нет источников.")
        return 1

    # 2. Параллельная загрузка (FETCH_WORKERS потоков)
    t0 = time.monotonic()
    all_raw, sources_ok = fetch_all_sources(urls)
    raw_count = len(all_raw)
    log.info("Загрузка: %.1fс, извлечено %d (с дублями)", time.monotonic() - t0, raw_count)

    # 3. Нормализация
    normalized = [n for p in all_raw if (n := normalize_proxy(p))]
    log.info("После нормализации: %d", len(normalized))

    # 4. Дедупликация
    seen:   set[str]  = set()
    unique: list[str] = []
    for p in normalized:
        fp = connection_fingerprint(p)
        if fp not in seen:
            seen.add(fp)
            unique.append(p)

    dup_count = len(normalized) - len(unique)
    log.info("После дедупликации: %d (удалено: %d)", len(unique), dup_count)

    # 5. Безопасное извлечение хостов
    all_hosts: list[str] = []
    for p in unique:
        try:
            all_hosts.append(_host_port(p)[0])
        except Exception:
            all_hosts.append("unknown")

    # 6. Параллельная геолокация
    t0 = time.monotonic()
    geo_cache = geolocate_hosts(all_hosts)
    log.info("Геолокация: %.1fс", time.monotonic() - t0)

    # 7. Сортировка: протокол → страна → хост → порт
    pairs = [(p, geo_cache.get(all_hosts[i].lower(), "")) for i, p in enumerate(unique)]
    pairs.sort(key=_sort_key)

    # 8. Стандартные имена
    renamed = [apply_standard_name(proxy, cc) for proxy, cc in pairs]

    # 9. Запись
    geo_final = {all_hosts[i].lower(): geo_cache.get(all_hosts[i].lower(), "")
                 for i in range(len(unique))}
    write_results(renamed, geo_final, result_file, results_dir,
                  len(urls), sources_ok, raw_count, dup_count)

    log.info("════ Готово за %.1fс ════", time.monotonic() - t_start)
    return 0


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Proxy Collector v5 — параллельный сборщик прокси."
    )
    parser.add_argument("-s", "--source",  default=SOURCE_FILE)
    parser.add_argument("-o", "--output",  default=RESULT_FILE)
    parser.add_argument("-r", "--results", default=RESULTS_DIR)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    sys.exit(run(args.source, args.output, args.results, args.verbose))
