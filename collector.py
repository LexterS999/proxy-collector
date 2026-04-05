#!/usr/bin/env python3
"""
Proxy Collector v6 — async параллельный сборщик прокси.

Новое в v6:
  • asyncio + aiohttp: загрузка источников (20 параллельных)
  • Async TCP-пингер: проверка живости (800 параллельных, timeout 3s)
  • geo_cache.json: кэш геолокации между запусками (экономия 60-80% запросов)
  • Имя прокси: "🇺🇸 US VLESS" (флаг + ISO-код + протокол)
  • stats.json + dashboard.html: метрики, графики, история 90 запусков
"""

import re
import sys
import json
import asyncio
import base64
import logging
import hashlib
import argparse
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse, unquote,
)

import aiohttp

# ─── Настройки ────────────────────────────────────────────────────────────────

SOURCE_FILE    = "source.txt"
RESULT_FILE    = "result.txt"
RESULTS_DIR    = "results"
GEO_CACHE_FILE = "geo_cache.json"
STATS_FILE     = "stats.json"
DASHBOARD_FILE = "dashboard.html"
LOG_FILE       = "collector.log"

FETCH_TIMEOUT     = 25
FETCH_CONCURRENCY = 20

ALIVE_TIMEOUT     = 3.0
ALIVE_CONCURRENCY = 800

GEO_API_URL      = "http://ip-api.com/batch"
GEO_BATCH_SIZE   = 100
GEO_CONCURRENCY  = 3
GEO_RATE_PER_MIN = 40
GEO_TIMEOUT      = 15
GEO_MAX_RETRY    = 3
GEO_RETRY_BASE   = 65

STATS_MAX_ENTRIES = 90

# ─── Протоколы ────────────────────────────────────────────────────────────────

PROXY_SCHEMES = [
    "vless", "vmess", "trojan",
    "ss", "ssr",
    "hy2", "hysteria2", "hysteria",
    "tuic", "naive", "brook", "juicity",
    "wireguard", "wg",
]

SCHEME_LABEL: dict[str, str] = {
    "vless": "VLESS", "vmess": "VMESS", "trojan": "TROJAN",
    "ss": "SS", "ssr": "SSR",
    "hy2": "HY2", "hysteria2": "HY2", "hysteria": "HY2",
    "tuic": "TUIC", "naive": "NAIVE", "brook": "BROOK",
    "juicity": "JUICITY", "wireguard": "WG", "wg": "WG",
}

SCHEME_FILENAME: dict[str, str] = {
    "vless": "vless", "vmess": "vmess", "trojan": "trojan",
    "ss": "ss", "ssr": "ssr",
    "hy2": "hy2", "hysteria2": "hy2", "hysteria": "hy2",
    "tuic": "tuic", "naive": "naive", "brook": "brook",
    "juicity": "juicity", "wireguard": "wg", "wg": "wg",
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
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
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


# ─── Async Rate Limiter ───────────────────────────────────────────────────────

class AsyncRateLimiter:
    """
    Потокобезопасный asyncio rate limiter (token bucket).
    Ограничивает вызовы до rate_per_minute в минуту глобально.
    """
    def __init__(self, rate_per_minute: int) -> None:
        self._interval  = 60.0 / rate_per_minute
        self._lock      = asyncio.Lock()
        self._last_time = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            loop = asyncio.get_event_loop()
            now  = loop.time()
            wait = self._last_time + self._interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_time = loop.time()


# ─── Кэш геолокации ───────────────────────────────────────────────────────────

def load_geo_cache(path: str = GEO_CACHE_FILE) -> dict[str, str]:
    """Загружает кэш {host: country_code} из geo_cache.json."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, dict) and "hosts" in data:
            return {k: v for k, v in data["hosts"].items()
                    if isinstance(k, str) and isinstance(v, str)}
    except Exception:
        pass
    return {}


def save_geo_cache(cache: dict[str, str], path: str = GEO_CACHE_FILE) -> None:
    """Сохраняет кэш геолокации в geo_cache.json."""
    try:
        Path(path).write_text(
            json.dumps({
                "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "count": len(cache),
                "hosts": cache,
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        log.info("Geo cache: сохранено %d записей → %s", len(cache), path)
    except Exception as e:
        log.warning("Geo cache save error: %s", e)


# ─── Флаги и имена ────────────────────────────────────────────────────────────

def _country_flag(cc: str) -> str:
    """
    ISO 3166-1 alpha-2 → Unicode Regional Indicator пара (emoji-флаг).
    "US" → "🇺🇸". На Android/Linux — цветной флаг.
    На Windows — читаемые буквы кода страны (US, DE, RU).
    Неизвестная страна → 🌐 (U+1F310).
    """
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "\U0001F310"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


def _make_proxy_name(cc: str, scheme: str) -> str:
    """
    Формирует стандартное имя: "🇺🇸 US VLESS".
    Флаг + ISO-код + метка протокола.
    """
    label = SCHEME_LABEL.get(scheme, scheme.upper())
    if cc and len(cc) == 2 and cc.isalpha():
        return f"{_country_flag(cc)} {cc.upper()} {label}"
    return f"\U0001F310 ?? {label}"


# ─── Геолокация — ip-api.com ──────────────────────────────────────────────────

def _is_private_host(host: str) -> bool:
    if not host or host in ("unknown", "localhost", ""):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_unspecified
    except ValueError:
        return host.endswith((".local", ".internal", ".localhost"))


async def _geo_batch(
    session: aiohttp.ClientSession,
    batch: list[str],
    limiter: AsyncRateLimiter,
) -> dict[str, str]:
    """Один POST к ip-api.com/batch с backoff при 429."""
    payload = [{"query": h, "fields": "query,countryCode,status"} for h in batch]

    for attempt in range(1, GEO_MAX_RETRY + 1):
        await limiter.acquire()
        try:
            async with session.post(
                GEO_API_URL, json=payload,
                timeout=aiohttp.ClientTimeout(total=GEO_TIMEOUT),
            ) as resp:
                try:
                    rl = int(resp.headers.get("X-Rl", "99"))
                    if rl <= 2:
                        ttl = max(int(resp.headers.get("X-Ttl", "5")), 2)
                        log.debug("Rate-limit X-Rl=%d, extra sleep %ds", rl, ttl)
                        await asyncio.sleep(ttl)
                except (ValueError, TypeError):
                    pass

                if resp.status == 429:
                    wait = GEO_RETRY_BASE * attempt
                    log.warning("Geo 429 — backoff %ds (попытка %d/%d)",
                                wait, attempt, GEO_MAX_RETRY)
                    await asyncio.sleep(wait)
                    continue

                result: dict[str, str] = {}
                for item in await resp.json(content_type=None):
                    if item.get("status") == "success":
                        q  = item.get("query", "").lower()
                        cc = item.get("countryCode", "").upper()
                        if q and cc and len(cc) == 2 and cc.isalpha():
                            result[q] = cc
                return result

        except asyncio.TimeoutError:
            log.debug("Geo timeout (попытка %d/%d)", attempt, GEO_MAX_RETRY)
        except Exception as e:
            log.debug("Geo error: %s (попытка %d/%d)", e, attempt, GEO_MAX_RETRY)
        if attempt < GEO_MAX_RETRY:
            await asyncio.sleep(5 * (2 ** attempt))
    return {}


async def geolocate_hosts(
    hosts: list[str],
    geo_cache: dict[str, str],
) -> dict[str, str]:
    """
    Геолоцирует список хостов через ip-api.com/batch.
    Хосты из кэша geo_cache не запрашиваются повторно.
    """
    public      = list(dict.fromkeys(h.lower() for h in hosts if h and not _is_private_host(h)))
    need_query  = [h for h in public if h not in geo_cache]

    log.info("Геолокация: %d хостов | кэш: %d hit | запросы: %d",
             len(public), len(public) - len(need_query), len(need_query))

    if not need_query:
        return geo_cache

    batches    = [need_query[i:i + GEO_BATCH_SIZE] for i in range(0, len(need_query), GEO_BATCH_SIZE)]
    limiter    = AsyncRateLimiter(GEO_RATE_PER_MIN)
    sem        = asyncio.Semaphore(GEO_CONCURRENCY)
    new_res    : dict[str, str] = {}
    done_count = [0]

    async with aiohttp.ClientSession() as session:
        async def _run(batch: list[str]) -> None:
            async with sem:
                res = await _geo_batch(session, batch, limiter)
                new_res.update(res)
                done_count[0] += 1
                if done_count[0] % 5 == 0 or done_count[0] == len(batches):
                    log.info("  Geo: %d/%d батчей, %d определено",
                             done_count[0], len(batches), len(new_res))

        await asyncio.gather(*[_run(b) for b in batches])

    geo_cache.update(new_res)
    log.info("Геолокация завершена: +%d новых, итого %d в кэше", len(new_res), len(geo_cache))
    return geo_cache


# ─── Парсеры протоколов ───────────────────────────────────────────────────────

def _vmess_decode(url: str) -> dict | None:
    try:
        decoded = _b64decode(url[len("vmess://"):])
        return json.loads(decoded) if decoded else None
    except Exception:
        return None


def _vmess_encode(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _ss_components(url: str) -> tuple | None:
    try:
        body = url.split("#")[0].strip()[len("ss://"):]
        if "@" in body:
            at  = body.rindex("@")
            ui  = body[:at]
            hp  = body[at + 1:]
            dui = _b64decode(ui)
            if dui and ":" in dui and len(dui) < 512:
                method, password = dui.split(":", 1)
            elif ":" in ui:
                method, password = unquote(ui).split(":", 1)
            else:
                return None
            h, _, p = hp.rpartition(":")
            return method.strip().lower(), password.strip(), h.lower(), int(p)
        dec = _b64decode(body)
        if "@" in dec:
            creds, hp = dec.rsplit("@", 1)
            method, password = creds.split(":", 1) if ":" in creds else (creds, "")
            h, _, p = hp.rpartition(":")
            return method.strip().lower(), password.strip(), h.lower(), int(p)
    except Exception:
        pass
    return None


def _ssr_core(url: str) -> str:
    try:
        dec = _b64decode(url[len("ssr://"):])
        return dec.split("/?")[0].split("#")[0].lower() if dec else url
    except Exception:
        return url


def _host_port(url: str) -> tuple:
    """Возвращает (host, port). Устойчив к IPv6 и нестандартным портам."""
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
    """SHA-256 от параметров подключения. Имя/fragment исключены полностью."""
    try:
        scheme = urlparse(url).scheme.lower()
        if scheme == "vmess":
            obj = _vmess_decode(url)
            if obj:
                fields = ("add", "port", "id", "aid", "net", "type",
                          "host", "path", "tls", "sni", "alpn", "fp", "flow", "serviceName")
                key = "|".join(str(obj.get(f, "")).lower() for f in fields)
                return hashlib.sha256(f"vmess:{key}".encode()).hexdigest()
        if scheme == "ss":
            comp = _ss_components(url)
            if comp:
                m, pw, h, p = comp
                return hashlib.sha256(f"ss:{m}:{pw}:{h}:{p}".encode()).hexdigest()
        if scheme == "ssr":
            return hashlib.sha256(f"ssr:{_ssr_core(url)}".encode()).hexdigest()
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
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

def apply_standard_name(url: str, cc: str = "") -> str:
    """
    Устанавливает стандартное имя прокси: "🇺🇸 US VLESS".
    Флаг Unicode + ISO-код страны + метка протокола.
    """
    scheme   = urlparse(url).scheme.lower()
    new_name = _make_proxy_name(cc, scheme)

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

    # Все остальные: фрагмент строим вручную (emoji не кодируем в %XX)
    try:
        parsed   = urlparse(url)
        base_url = urlunparse((scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))
        return base_url + "#" + new_name
    except Exception:
        return url


# ─── Нормализация ─────────────────────────────────────────────────────────────

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
    if scheme == "ss" and _ss_components(raw) is None and len(parsed.netloc) < 4:
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


# ─── Извлечение прокси из текста ──────────────────────────────────────────────

def extract_proxies(text: str, _depth: int = 0) -> list[str]:
    if _depth > 3:
        return []
    proxies: list[str] = []
    for match in PROXY_RE.finditer(text):
        rest = re.split(r'[\s"\'\]\)>]', match.group(2))[0]
        proxies.append(f"{match.group(1)}://{rest}")
    if proxies:
        return proxies
    if _looks_like_b64(text):
        decoded = _b64decode(text)
        if decoded:
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


# ─── Async загрузка источников ────────────────────────────────────────────────

async def _fetch_one(
    session: aiohttp.ClientSession,
    url: str,
    sem: asyncio.Semaphore,
    idx: int,
    total: int,
) -> tuple[str, list[str], bool]:
    """Загружает один URL. Возвращает (url, proxies, ok)."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; ProxyCollector/6.0; "
            "+https://github.com/your-username/proxy-collector)"
        ),
        "Accept": "text/plain, text/html, */*",
    }
    async with sem:
        log.info("[%d/%d] %s", idx, total, url)
        for attempt in range(1, 4):
            try:
                async with session.get(
                    url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
                    ssl=False,
                ) as resp:
                    raw = await resp.read()
                    for enc in ("utf-8", "latin-1", "cp1251"):
                        try:
                            text = raw.decode(enc)
                            break
                        except UnicodeDecodeError:
                            continue
                    else:
                        text = raw.decode("utf-8", errors="replace")
                    found = extract_proxies(text)
                    log.info("  ↳ Найдено: %d", len(found))
                    return url, found, True
            except asyncio.TimeoutError:
                log.warning("  Timeout %s (попытка %d/3)", url, attempt)
            except Exception as e:
                log.warning("  Ошибка %s: %s (попытка %d/3)", url, e, attempt)
            if attempt < 3:
                await asyncio.sleep(3)
        log.warning("  ↳ Пропущен: %s", url)
        return url, [], False


async def fetch_all_sources(urls: list[str]) -> tuple[list[str], list[dict], int]:
    """
    Параллельная загрузка всех источников (aiohttp, FETCH_CONCURRENCY).
    Возвращает (все_прокси, source_stats, кол-во_успешных).
    """
    sem         = asyncio.Semaphore(FETCH_CONCURRENCY)
    all_raw     : list[str]  = []
    source_stats: list[dict] = []
    sources_ok  = 0

    conn = aiohttp.TCPConnector(limit=FETCH_CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [
            _fetch_one(session, url, sem, idx, len(urls))
            for idx, url in enumerate(urls, 1)
        ]
        for coro in asyncio.as_completed(tasks):
            url, proxies, ok = await coro
            all_raw.extend(proxies)
            source_stats.append({"url": url, "found": len(proxies), "ok": ok})
            if ok:
                sources_ok += 1

    return all_raw, source_stats, sources_ok


# ─── Async проверка живости (TCP) ─────────────────────────────────────────────

async def _tcp_check(host: str, port: int, sem: asyncio.Semaphore) -> bool:
    """TCP connect проверка. Открытый порт = прокси считается живым."""
    if not port or _is_private_host(host):
        return True
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=ALIVE_TIMEOUT,
            )
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
            return True
        except Exception:
            return False


async def check_alive_batch(proxies: list[str]) -> list[bool]:
    """
    Асинхронная TCP-проверка всех прокси.
    До ALIVE_CONCURRENCY параллельных соединений.
    """
    sem = asyncio.Semaphore(ALIVE_CONCURRENCY)
    log.info(
        "Проверка живости: %d прокси (TCP %.0fs timeout, %d parallel)...",
        len(proxies), ALIVE_TIMEOUT, ALIVE_CONCURRENCY,
    )
    loop = asyncio.get_event_loop()
    t0   = loop.time()

    host_ports = []
    for p in proxies:
        try:
            host_ports.append(_host_port(p))
        except Exception:
            host_ports.append(("unknown", 0))

    results = await asyncio.gather(
        *[_tcp_check(h, p, sem) for h, p in host_ports],
        return_exceptions=True,
    )
    alive_flags = [bool(r) if not isinstance(r, Exception) else False for r in results]
    alive_count = sum(alive_flags)
    log.info(
        "Живых: %d/%d (%.0f%%) за %.1fс",
        alive_count, len(proxies),
        100 * alive_count / max(1, len(proxies)),
        loop.time() - t0,
    )
    return alive_flags


# ─── Сортировка ───────────────────────────────────────────────────────────────

_SCHEME_ORDER = {s: i for i, s in enumerate([
    "vless", "vmess", "trojan", "ss", "ssr",
    "hy2", "hysteria2", "hysteria",
    "tuic", "naive", "brook", "juicity", "wireguard", "wg",
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
    return "\n".join(["# " + "═" * w, f"#  {title}",
                       f"#  Обновлено: {now}", f"#  Прокси  : {count}",
                       "# " + "═" * w, ""])


def write_results(
    proxies: list[str],
    geo_cache: dict[str, str],
    result_file: str,
    results_dir: str,
    sources_total: int,
    sources_ok: int,
    raw_count: int,
    dup_count: int,
    alive_count: int,
    unique_count: int,
) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    proto_counter:   dict[str, int] = defaultdict(int)
    country_counter: dict[str, int] = defaultdict(int)
    for p in proxies:
        scheme = urlparse(p).scheme.lower()
        proto_counter[SCHEME_LABEL.get(scheme, scheme.upper())] += 1
        try:
            host, _ = _host_port(p)
        except Exception:
            host = "unknown"
        country_counter[geo_cache.get(host.lower(), "") or "??"] += 1

    w = 59
    stats = [
        "# " + "═" * w,
        "#  Proxy Collector v6",
        "# " + "─" * w,
        f"#  Обновлено  : {now}",
        f"#  Источников : {sources_ok}/{sources_total} успешно",
        f"#  Извлечено  : {raw_count} (до дедупликации)",
        f"#  Дубликатов : {dup_count} удалено",
        f"#  Уникальных : {unique_count}",
        f"#  Живых      : {alive_count} ({100*alive_count//max(1,unique_count)}%)",
        "# " + "─" * w, "#  Протоколы:",
    ]
    max_p = max(proto_counter.values()) if proto_counter else 1
    for label, cnt in sorted(proto_counter.items(), key=lambda x: -x[1]):
        stats.append(f"#    {label:<12} {cnt:>5}  {'█' * max(1, round(cnt/max_p*24))}")
    stats.append("# " + "─" * w)
    stats.append("#  Топ-10 стран:")
    top10 = sorted(country_counter.items(), key=lambda x: -x[1])[:10]
    max_c = top10[0][1] if top10 else 1
    for cc, cnt in top10:
        flag = _country_flag(cc) if cc not in ("??", "") else "🌐"
        stats.append(f"#    {flag} {cc:<4} {cnt:>5}  {'█' * max(1, round(cnt/max_c*24))}")
    stats.append("# " + "═" * w)

    Path(result_file).write_text(
        "\n".join(stats) + "\n\n" + "\n".join(proxies) + "\n", encoding="utf-8")
    log.info("Записан %s: %d прокси", result_file, len(proxies))

    rd = Path(results_dir)
    rd.mkdir(exist_ok=True)
    groups: dict[str, list[str]] = defaultdict(list)
    for p in proxies:
        groups[SCHEME_FILENAME.get(urlparse(p).scheme.lower(), "other")].append(p)
    for fname, gp in sorted(groups.items()):
        (rd / f"{fname}.txt").write_text(
            _file_header(f"{fname.upper()} — {len(gp)} прокси", now, len(gp))
            + "\n".join(gp) + "\n", encoding="utf-8")
        log.info("  results/%s.txt: %d", fname, len(gp))
    for old in rd.glob("*.txt"):
        if old.stem not in groups:
            old.unlink()
            log.info("  Удалён устаревший %s", old.name)


# ─── Статистика ───────────────────────────────────────────────────────────────

def load_stats(path: str = STATS_FILE) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_stats(
    history: list[dict],
    source_stats: list[dict],
    sources_total: int,
    sources_ok: int,
    raw_count: int,
    unique_count: int,
    alive_count: int,
    dup_count: int,
    geo_cache: dict[str, str],
    proxies: list[str],
    path: str = STATS_FILE,
) -> list[dict]:
    proto_counter:   dict[str, int] = defaultdict(int)
    country_counter: dict[str, int] = defaultdict(int)
    geo_covered = 0
    for p in proxies:
        scheme = urlparse(p).scheme.lower()
        proto_counter[SCHEME_LABEL.get(scheme, scheme.upper())] += 1
        try:
            host, _ = _host_port(p)
        except Exception:
            host = "unknown"
        cc = geo_cache.get(host.lower(), "")
        country_counter[cc or "??"] += 1
        if cc:
            geo_covered += 1

    entry = {
        "ts":            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "date":          datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "sources_total": sources_total,
        "sources_ok":    sources_ok,
        "raw":           raw_count,
        "unique":        unique_count,
        "alive":         alive_count,
        "alive_pct":     round(100 * alive_count / max(1, unique_count), 1),
        "dups":          dup_count,
        "geo_covered":   geo_covered,
        "protocols":     dict(proto_counter),
        "countries":     dict(sorted(country_counter.items(), key=lambda x: -x[1])[:20]),
        "sources":       source_stats,
    }
    history.append(entry)
    if len(history) > STATS_MAX_ENTRIES:
        history = history[-STATS_MAX_ENTRIES:]
    Path(path).write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("Статистика: %d записей → %s", len(history), path)
    return history


# ─── HTML Dashboard ───────────────────────────────────────────────────────────

_DASH_TPL = (
    '<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>Proxy Collector Dashboard</title>'
    '<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>'
    '<style>'
    ':root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;'
    '--muted:#8b949e;--accent:#58a6ff;--green:#3fb950;--yellow:#d29922;'
    '--red:#f85149;--purple:#bc8cff}'
    '*{box-sizing:border-box;margin:0;padding:0}'
    'body{background:var(--bg);color:var(--text);font-family:"Segoe UI",system-ui,sans-serif;padding:20px}'
    'h1{font-size:1.6rem;font-weight:700;color:var(--accent);margin-bottom:4px}'
    '.sub{color:var(--muted);font-size:.85rem;margin-bottom:22px}'
    '.g4{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:20px}'
    '.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}'
    '.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:20px}'
    '@media(max-width:860px){.g2,.g3{grid-template-columns:1fr}}'
    '.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px}'
    '.mc .lbl{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px}'
    '.mc .val{font-size:1.9rem;font-weight:700;line-height:1}'
    '.mc .hint{font-size:.78rem;color:var(--muted);margin-top:3px}'
    '.green{color:var(--green)}.yellow{color:var(--yellow)}.blue{color:var(--accent)}.purple{color:var(--purple)}'
    '.card h2{font-size:.85rem;color:var(--muted);margin-bottom:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}'
    '.cw{position:relative;height:240px}.cwtall{position:relative;height:320px}'
    'table{width:100%;border-collapse:collapse;font-size:.8rem}'
    'th{text-align:left;color:var(--muted);font-weight:500;padding:5px 8px;border-bottom:1px solid var(--border)}'
    'td{padding:5px 8px;border-bottom:1px solid #21262d;max-width:380px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}'
    'tr:last-child td{border-bottom:none}'
    '.ok{display:inline-block;padding:1px 7px;border-radius:10px;font-size:.72rem;font-weight:600}'
    '.ok-y{background:#1a3a24;color:var(--green)}.ok-n{background:#3a1a1a;color:var(--red)}'
    'footer{text-align:center;color:var(--muted);font-size:.78rem;margin-top:20px}'
    'a{color:var(--accent)}'
    '</style></head><body>'
    '<h1>&#128225; Proxy Collector</h1>'
    '<p class="sub" id="lu"></p>'
    '<div class="g4" id="cards"></div>'
    '<div class="g2">'
    '<div class="card"><h2>&#128200; История</h2><div class="cw"><canvas id="hc"></canvas></div></div>'
    '<div class="card"><h2>&#129321; Протоколы</h2><div class="cw"><canvas id="pc"></canvas></div></div>'
    '</div>'
    '<div class="g2">'
    '<div class="card"><h2>&#127758; Страны топ-15</h2><div class="cwtall"><canvas id="cc"></canvas></div></div>'
    '<div class="card"><h2>&#128293; Живых % по дням</h2><div class="cwtall"><canvas id="ac"></canvas></div></div>'
    '</div>'
    '<div class="g2" style="margin-bottom:20px">'
    '<div class="card"><h2>&#128202; Протоколы по дням</h2><div class="cwtall"><canvas id="pdc"></canvas></div></div>'
    '<div class="card"><h2>&#128196; Дедупликация по дням</h2><div class="cwtall"><canvas id="ddc"></canvas></div></div>'
    '</div>'
    '<div class="card" style="margin-bottom:20px">'
    '<h2>&#128279; Источники (последний запуск)</h2>'
    '<table><thead><tr><th>#</th><th>URL</th><th>Найдено</th><th>Статус</th></tr></thead>'
    '<tbody id="st"></tbody></table></div>'
    '<footer>Proxy Collector v6 &middot; <a href="result.txt">result.txt</a> &middot; '
    '<a href="stats.json">stats.json</a></footer>'
    '<script>'
    'const S=__STATS_DATA__;'
    'const L=S[S.length-1]||{},P=S[S.length-2]||{};'
    'document.getElementById("lu").textContent="Последнее обновление: "+(L.ts||"—");'
    'function pct(a,b){return b?Math.round(100*a/b):0}'
    'const cards=['
    '{lbl:"Живых прокси",val:L.alive||0,hint:"из "+(L.unique||0)+" уникальных",cls:"green"},'
    '{lbl:"Процент живых",val:(L.alive_pct||0)+"%",hint:"пред: "+((P.alive_pct||0))+"%",cls:"yellow"},'
    '{lbl:"Дедупликация",val:pct(L.dups||0,L.raw||1)+"%",hint:(L.dups||0)+" дублей удалено",cls:"purple"},'
    '{lbl:"Гео покрытие",val:pct(L.geo_covered||0,L.unique||1)+"%",hint:(L.geo_covered||0)+" хостов",cls:"blue"},'
    '{lbl:"Источников",val:(L.sources_ok||0)+"/"+(L.sources_total||0),hint:"успешно загружено",cls:"blue"},'
    '{lbl:"Всего собрано",val:L.raw||0,hint:"до дедупликации",cls:"yellow"},'
    '];'
    'const cd=document.getElementById("cards");'
    'cards.forEach(c=>{cd.innerHTML+=`<div class="card mc"><div class="lbl">${c.lbl}</div>'
    '<div class="val ${c.cls}">${c.val}</div><div class="hint">${c.hint}</div></div>`});'
    'const R=S.slice(-30),lbs=R.map(s=>s.date);'
    'const base={responsive:true,maintainAspectRatio:false,'
    'plugins:{legend:{labels:{color:"#8b949e",boxWidth:11}}},'
    'scales:{x:{ticks:{color:"#8b949e",maxRotation:45},grid:{color:"#21262d"}},'
    'y:{ticks:{color:"#8b949e"},grid:{color:"#21262d"}}}};'
    'new Chart(document.getElementById("hc"),{type:"line",data:{labels:lbs,datasets:['
    '{label:"Уникальных",data:R.map(s=>s.unique),borderColor:"#58a6ff",'
    'backgroundColor:"rgba(88,166,255,.15)",tension:.3,fill:true,pointRadius:2},'
    '{label:"Живых",data:R.map(s=>s.alive),borderColor:"#3fb950",'
    'backgroundColor:"rgba(63,185,80,.15)",tension:.3,fill:true,pointRadius:2}'
    ']},options:base});'
    'const pr=L.protocols||{},pk=Object.keys(pr),pv=Object.values(pr);'
    'const pal=["#58a6ff","#3fb950","#d29922","#bc8cff","#f85149","#79c0ff",'
    '"#56d364","#e3b341","#db61a2","#39d353","#ff7b72","#ffa657"];'
    'new Chart(document.getElementById("pc"),{type:"doughnut",data:{labels:pk,'
    'datasets:[{data:pv,backgroundColor:pal,borderColor:"#161b22",borderWidth:2}]},'
    'options:{responsive:true,maintainAspectRatio:false,'
    'plugins:{legend:{position:"right",labels:{color:"#8b949e",boxWidth:11,padding:6}}}}});'
    'const ct=L.countries||{},ck=Object.keys(ct).slice(0,15),cv=ck.map(k=>ct[k]);'
    'new Chart(document.getElementById("cc"),{type:"bar",data:{labels:ck,'
    'datasets:[{label:"Прокси",data:cv,backgroundColor:"rgba(88,166,255,.7)",borderRadius:3}]},'
    'options:{...base,indexAxis:"y",plugins:{legend:{display:false}}}});'
    'new Chart(document.getElementById("ac"),{type:"line",data:{labels:lbs,'
    'datasets:[{label:"Живых %",data:R.map(s=>s.alive_pct),'
    'borderColor:"#3fb950",backgroundColor:"rgba(63,185,80,.2)",'
    'tension:.3,fill:true,pointRadius:2}]},'
    'options:{...base,plugins:{legend:{display:false}},'
    'scales:{...base.scales,y:{...base.scales.y,min:0,max:100}}}});'
    'const allProtos=[...new Set(S.flatMap(s=>Object.keys(s.protocols||{})))];'
    'const protoColors={"VLESS":"#58a6ff","VMESS":"#3fb950","TROJAN":"#d29922",'
    '"SS":"#bc8cff","SSR":"#f85149","HY2":"#79c0ff","TUIC":"#56d364",'
    '"WG":"#e3b341","NAIVE":"#db61a2","BROOK":"#ffa657","JUICITY":"#39d353"};'
    'new Chart(document.getElementById("pdc"),{type:"line",data:{labels:lbs,'
    'datasets:allProtos.slice(0,6).map((proto,i)=>({'
    'label:proto,data:R.map(s=>(s.protocols||{})[proto]||0),'
    'borderColor:protoColors[proto]||pal[i],'
    'backgroundColor:"transparent",tension:.3,pointRadius:2'
    '}))},'
    'options:{...base,plugins:{legend:{labels:{color:"#8b949e",boxWidth:11}}}}});'
    'new Chart(document.getElementById("ddc"),{type:"bar",data:{labels:lbs,'
    'datasets:['
    '{label:"Уникальных",data:R.map(s=>s.unique),backgroundColor:"rgba(88,166,255,.6)",borderRadius:2},'
    '{label:"Дублей",data:R.map(s=>s.dups),backgroundColor:"rgba(248,81,73,.5)",borderRadius:2},'
    '{label:"Живых",data:R.map(s=>s.alive),backgroundColor:"rgba(63,185,80,.7)",borderRadius:2}'
    ']},'
    'options:{...base,plugins:{legend:{labels:{color:"#8b949e",boxWidth:11}}}}});'
    'const st=document.getElementById("st");'
    '(L.sources||[]).forEach((s,i)=>{'
    'const url=s.url||"",short=url.length>55?url.slice(0,55)+"…":url;'
    'const tr=document.createElement("tr");'
    'tr.innerHTML=`<td>${i+1}</td><td title="${url}">${short}</td>'
    '<td>${s.found||0}</td>'
    '<td><span class="ok ${s.ok?"ok-y":"ok-n"}">${s.ok?"✓ OK":"✗ FAIL"}</span></td>`;'
    'st.appendChild(tr)});'
    '</script></body></html>'
)


def generate_dashboard(history: list[dict], output_path: str = DASHBOARD_FILE) -> None:
    """Генерирует интерактивный HTML-дашборд из stats.json."""
    html = _DASH_TPL.replace("__STATS_DATA__", json.dumps(history, ensure_ascii=False))
    Path(output_path).write_text(html, encoding="utf-8")
    log.info("Dashboard → %s", output_path)


# ─── Основной async процесс ───────────────────────────────────────────────────

async def run(
    source_file: str = SOURCE_FILE,
    result_file: str = RESULT_FILE,
    results_dir: str = RESULTS_DIR,
    verbose: bool = False,
) -> int:
    setup_logging(verbose)
    log.info("════ Proxy Collector v6 запущен ════")
    loop    = asyncio.get_event_loop()
    t_start = loop.time()

    # 1. Источники
    path = Path(source_file)
    if not path.exists():
        log.error("Файл источников не найден: %s", source_file)
        return 1
    urls = [l.strip() for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")]
    if not urls:
        log.error("Нет источников в %s", source_file)
        return 1
    log.info("Источников: %d из %s", len(urls), source_file)

    # 2. Async загрузка источников (aiohttp)
    t0 = loop.time()
    all_raw, source_stats, sources_ok = await fetch_all_sources(urls)
    raw_count = len(all_raw)
    log.info("Загрузка: %.1fс | извлечено %d (с дублями)", loop.time() - t0, raw_count)

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

    # 5. Проверка живости (TCP connect)
    t0          = loop.time()
    alive_flags = await check_alive_batch(unique)
    alive       = [p for p, ok in zip(unique, alive_flags) if ok]
    alive_count = len(alive)
    log.info("Живых: %d/%d за %.1fс", alive_count, len(unique), loop.time() - t0)

    # 6. Геолокация (с кэшем)
    geo_cache    = load_geo_cache()
    cache_before = len(geo_cache)
    all_hosts    = []
    for p in alive:
        try:
            all_hosts.append(_host_port(p)[0])
        except Exception:
            all_hosts.append("unknown")

    t0 = loop.time()
    geo_cache = await geolocate_hosts(all_hosts, geo_cache)
    log.info("Геолокация: %.1fс (+%d в кэше)", loop.time() - t0, len(geo_cache) - cache_before)
    save_geo_cache(geo_cache)

    # 7. Сортировка + переименование
    pairs = [(p, geo_cache.get(all_hosts[i].lower(), "")) for i, p in enumerate(alive)]
    pairs.sort(key=_sort_key)
    renamed = [apply_standard_name(proxy, cc) for proxy, cc in pairs]

    # 8. Запись результатов
    write_results(renamed, geo_cache, result_file, results_dir,
                  len(urls), sources_ok, raw_count, dup_count, alive_count, len(unique))

    # 9. Статистика + дашборд
    history = load_stats()
    history = save_stats(history, source_stats, len(urls), sources_ok,
                         raw_count, len(unique), alive_count, dup_count, geo_cache, renamed)
    generate_dashboard(history)

    log.info("════ Готово за %.1fс ════", loop.time() - t_start)
    return 0


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Proxy Collector v6 — async сборщик прокси с дашбордом."
    )
    parser.add_argument("-s", "--source",  default=SOURCE_FILE)
    parser.add_argument("-o", "--output",  default=RESULT_FILE)
    parser.add_argument("-r", "--results", default=RESULTS_DIR)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    sys.exit(asyncio.run(run(args.source, args.output, args.results, args.verbose)))
