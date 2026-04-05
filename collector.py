#!/usr/bin/env python3
"""
Proxy Collector v7

Изменения v7:
  1. Двухуровневая дедупликация после TCP-проверки:
       - Уровень A (до TCP): SHA-256 по всем параметрам соединения
       - Уровень B (после TCP): по (host, port, credential) — убирает один сервер
         с разными transport-настройками (разные path/sni/fp при одном UUID/пароле)
  2. Rate-limit геолокации полностью решён:
       - GEO_CONCURRENCY=1 (строго последовательно) — исключает гонку потоков
       - AsyncRateLimiter читает X-Rl/X-Ttl и БЛОКИРУЕТ лимитер до сброса окна
       - Три уровня защиты: token-bucket → X-Rl guard → 429 backoff
  3. Расширенный geo-запрос: добавлены поля org, as, isp, hosting (ip-api.com, бесплатно)
       - ISP/ASN сохраняются в geo_cache.json и добавляются в статистику дашборда
  4. TCP-латентность: измеряется при alive-проверке, прокси сортируются быстрые→медленные
  5. Поле "hosting" из ip-api.com: помечает датацентровые IP — полезно для фильтрации
"""

import re
import sys
import json
import time
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

FETCH_TIMEOUT      = 25
FETCH_CONCURRENCY  = 20

ALIVE_TIMEOUT      = 3.0
ALIVE_CONCURRENCY  = 500   # снизили с 800 → меньше SYN флуда

# ── Геолокация ip-api.com ─────────────────────────────────────────────────────
# Ключевое решение rate-limit: GEO_CONCURRENCY = 1 (строго последовательно).
# С одним потоком гонки нет в принципе. Token-bucket = 40/min даёт 1.5s интервал.
# 9500 хостов / 100 per batch = 95 батчей × 1.5s = ~145s (2.4 мин) — приемлемо.
GEO_API_URL       = "http://ip-api.com/batch"
GEO_BATCH_SIZE    = 100
GEO_CONCURRENCY   = 1      # ТОЛЬКО 1 — исключает гонку при X-Rl=0
GEO_RATE_PER_MIN  = 38     # немного ниже лимита 45 для запаса
GEO_TIMEOUT       = 20
GEO_MAX_RETRY     = 4
GEO_RETRY_BASE    = 70     # сек backoff при 429
# Поля ip-api.com (все бесплатны в batch-режиме):
GEO_FIELDS        = "query,status,country,countryCode,org,as,isp,hosting"

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


# ─── Async Rate Limiter (v7: с блокировкой по X-Rl/X-Ttl) ────────────────────

class AsyncRateLimiter:
    """
    Token-bucket rate limiter с возможностью принудительной паузы
    при получении X-Rl=0 от сервера (блокирует все последующие acquire).

    С GEO_CONCURRENCY=1 гонки нет в принципе — лимитер дополнительная защита.
    """
    def __init__(self, rate_per_minute: int) -> None:
        self._interval   = 60.0 / rate_per_minute
        self._lock        = asyncio.Lock()
        self._last_time   = 0.0
        self._force_until = 0.0   # монотонное время до которого запрещены запросы

    async def acquire(self) -> None:
        async with self._lock:
            loop = asyncio.get_event_loop()
            now  = loop.time()

            # Принудительная пауза (установлена при X-Rl=0 или 429)
            if now < self._force_until:
                wait = self._force_until - now
                log.debug("RateLimiter: forced wait %.1fs", wait)
                await asyncio.sleep(wait)

            # Обычный token-bucket интервал
            now  = asyncio.get_event_loop().time()
            wait = self._last_time + self._interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_time = asyncio.get_event_loop().time()

    def force_pause(self, seconds: float) -> None:
        """Запрещает любые новые запросы на `seconds` секунд."""
        loop          = asyncio.get_event_loop()
        self._force_until = max(self._force_until, loop.time() + seconds)
        log.info("RateLimiter: пауза %.0fs до сброса окна ip-api.com", seconds)


# ─── Кэш геолокации (расширенный: хранит org/isp/asn/hosting) ────────────────

def load_geo_cache(path: str = GEO_CACHE_FILE) -> dict[str, dict]:
    """
    Загружает расширенный кэш.
    Поддерживает старый формат {host: "US"} и новый {host: {cc, org, isp, asn, hosting}}.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, dict) and "hosts" in data:
            result: dict[str, dict] = {}
            for k, v in data["hosts"].items():
                if not isinstance(k, str):
                    continue
                if isinstance(v, str):
                    # Старый формат — апгрейд
                    result[k] = {"cc": v, "org": "", "isp": "", "asn": "", "hosting": False}
                elif isinstance(v, dict):
                    result[k] = v
            return result
    except Exception:
        pass
    return {}


def save_geo_cache(cache: dict[str, dict], path: str = GEO_CACHE_FILE) -> None:
    try:
        Path(path).write_text(
            json.dumps({
                "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "count":   len(cache),
                "hosts":   cache,
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        log.info("Geo cache: %d записей → %s", len(cache), path)
    except Exception as e:
        log.warning("Geo cache save error: %s", e)


def geo_cc(cache: dict[str, dict], host: str) -> str:
    """Возвращает country_code для хоста из кэша."""
    entry = cache.get(host.lower(), {})
    if isinstance(entry, dict):
        return entry.get("cc", "")
    return str(entry)  # старый формат


def geo_isp(cache: dict[str, dict], host: str) -> str:
    """Возвращает ISP/org для хоста из кэша."""
    entry = cache.get(host.lower(), {})
    if isinstance(entry, dict):
        return entry.get("isp") or entry.get("org") or ""
    return ""


def geo_hosting(cache: dict[str, dict], host: str) -> bool:
    """True если хост — датацентр/хостинг (по полю hosting от ip-api.com)."""
    entry = cache.get(host.lower(), {})
    if isinstance(entry, dict):
        return bool(entry.get("hosting", False))
    return False


# ─── Флаги и имена ────────────────────────────────────────────────────────────

def _country_flag(cc: str) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "\U0001F310"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


def _make_proxy_name(cc: str, scheme: str) -> str:
    """Формирует стандартное имя: "🇺🇸 US VLESS"."""
    label = SCHEME_LABEL.get(scheme, scheme.upper())
    if cc and len(cc) == 2 and cc.isalpha():
        return f"{_country_flag(cc)} {cc.upper()} {label}"
    return f"\U0001F310 ?? {label}"


# ─── Проверка приватных хостов ────────────────────────────────────────────────

def _is_private_host(host: str) -> bool:
    if not host or host in ("unknown", "localhost", ""):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_unspecified
    except ValueError:
        return host.endswith((".local", ".internal", ".localhost"))


# ─── Геолокация — ip-api.com (расширенная, sequential) ───────────────────────

async def _geo_batch_sequential(
    session: aiohttp.ClientSession,
    batch: list[str],
    limiter: AsyncRateLimiter,
) -> dict[str, dict]:
    """
    Один POST к ip-api.com/batch. Строго последовательно (GEO_CONCURRENCY=1).

    Три уровня защиты от rate-limit:
      1. Token-bucket (acquire): 38 req/min интервал
      2. X-Rl guard: если X-Rl <= 3, блокируем лимитер на X-Ttl секунд
      3. 429 backoff: экспоненциальный, до 4 попыток

    Возвращает {host: {cc, org, isp, asn, hosting}}.
    """
    payload = [{"query": h, "fields": GEO_FIELDS} for h in batch]

    for attempt in range(1, GEO_MAX_RETRY + 1):
        await limiter.acquire()
        try:
            async with session.post(
                GEO_API_URL, json=payload,
                timeout=aiohttp.ClientTimeout(total=GEO_TIMEOUT),
            ) as resp:
                # ── X-Rl guard ──────────────────────────────────────────────
                try:
                    rl = int(resp.headers.get("X-Rl", "99"))
                    if rl <= 3:
                        ttl = max(int(resp.headers.get("X-Ttl", "60")), 5)
                        log.info(
                            "X-Rl=%d — блокирую лимитер на %ds (сброс окна)",
                            rl, ttl,
                        )
                        limiter.force_pause(ttl + 2)  # +2с запас
                except (ValueError, TypeError):
                    pass

                # ── 429 ─────────────────────────────────────────────────────
                if resp.status == 429:
                    wait = GEO_RETRY_BASE * attempt
                    log.warning(
                        "429 Too Many Requests — backoff %ds (попытка %d/%d)",
                        wait, attempt, GEO_MAX_RETRY,
                    )
                    limiter.force_pause(wait)
                    await asyncio.sleep(wait)
                    continue

                # ── Успех ───────────────────────────────────────────────────
                result: dict[str, dict] = {}
                for item in await resp.json(content_type=None):
                    if item.get("status") == "success":
                        q = item.get("query", "").lower()
                        if not q:
                            continue
                        cc = item.get("countryCode", "").upper()
                        result[q] = {
                            "cc":      cc if len(cc) == 2 and cc.isalpha() else "",
                            "org":     item.get("org", ""),
                            "isp":     item.get("isp", ""),
                            "asn":     item.get("as", ""),
                            "hosting": bool(item.get("hosting", False)),
                        }
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
    geo_cache: dict[str, dict],
) -> dict[str, dict]:
    """
    Последовательная геолокация хостов (GEO_CONCURRENCY=1).
    Хосты из кэша не запрашиваются повторно.
    """
    public     = list(dict.fromkeys(
        h.lower() for h in hosts if h and not _is_private_host(h)
    ))
    need_query = [h for h in public if h not in geo_cache]

    log.info(
        "Геолокация: %d хостов | кэш: %d hit | запросы: %d новых",
        len(public), len(public) - len(need_query), len(need_query),
    )
    if not need_query:
        return geo_cache

    batches = [
        need_query[i : i + GEO_BATCH_SIZE]
        for i in range(0, len(need_query), GEO_BATCH_SIZE)
    ]
    total   = len(batches)
    limiter = AsyncRateLimiter(GEO_RATE_PER_MIN)
    new_res : dict[str, dict] = {}

    # GEO_CONCURRENCY=1: строго последовательно — никакой гонки
    async with aiohttp.ClientSession() as session:
        for idx, batch in enumerate(batches, 1):
            res = await _geo_batch_sequential(session, batch, limiter)
            new_res.update(res)
            if idx % 10 == 0 or idx == total:
                log.info(
                    "  Geo: %d/%d батчей | определено %d/%d",
                    idx, total, len(new_res), len(need_query),
                )

    geo_cache.update(new_res)
    log.info(
        "Геолокация завершена: +%d новых записей, итого %d в кэше",
        len(new_res), len(geo_cache),
    )
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


# ─── Дедупликация — два уровня ────────────────────────────────────────────────

def connection_fingerprint(url: str) -> str:
    """
    Уровень A: SHA-256 по ВСЕМ параметрам соединения.
    Применяется до TCP-проверки.
    """
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
        parsed   = urlparse(url)
        params   = parse_qs(parsed.query, keep_blank_values=True)
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


def server_credential_key(url: str) -> str:
    """
    Уровень B: ключ по (scheme_canonical, host, port, credential).
    Применяется ПОСЛЕ TCP-проверки.

    Убирает прокси у которых одинаковый сервер (host+port) и
    одинаковые учётные данные (UUID/пароль), но разные transport-параметры
    (sni, path, obfs, fp и т.п.). Оставляем только ПЕРВЫЙ живой вариант.

    Логика:
      vless/vmess: (host, port, uuid)
      trojan:      (host, port, password)
      ss:          (host, port, method, password)
      ssr:         (host, port) из ядра
      tuic:        (host, port, uuid)
      hy2/hysteria:(host, port, password)
      прочие:      (host, port)
    """
    try:
        scheme = urlparse(url).scheme.lower()
        host, port = _host_port(url)

        if scheme == "vmess":
            obj = _vmess_decode(url)
            cred = str(obj.get("id", "")).lower() if obj else ""
            return f"vmess:{host}:{port}:{cred}"

        if scheme == "vless":
            parsed = urlparse(url)
            cred   = (parsed.username or "").lower()
            return f"vless:{host}:{port}:{cred}"

        if scheme == "trojan":
            parsed = urlparse(url)
            cred   = (parsed.username or parsed.password or "").lower()
            return f"trojan:{host}:{port}:{cred}"

        if scheme == "ss":
            comp = _ss_components(url)
            if comp:
                m, pw, h, p = comp
                return f"ss:{h}:{p}:{m}:{hashlib.md5(pw.encode()).hexdigest()[:8]}"
            return f"ss:{host}:{port}"

        if scheme == "ssr":
            core  = _ssr_core(url)
            parts = core.split(":")
            # SSR: host:port:protocol:method:obfs:base64pass
            key   = ":".join(parts[:6]) if len(parts) >= 6 else core
            return f"ssr:{key}"

        if scheme == "tuic":
            parsed = urlparse(url)
            cred   = (parsed.username or "").lower()
            return f"tuic:{host}:{port}:{cred}"

        if scheme in ("hy2", "hysteria2", "hysteria"):
            parsed = urlparse(url)
            cred   = (parsed.username or parsed.password or "").lower()
            return f"hy2:{host}:{port}:{cred}"

        # Все остальные: по host+port
        return f"{scheme}:{host}:{port}"

    except Exception:
        return hashlib.sha256(url.encode()).hexdigest()[:16]


def dedup_level_a(proxies: list[str]) -> tuple[list[str], int]:
    """Уровень A: дедупликация по полному отпечатку соединения."""
    seen:   set[str]  = set()
    result: list[str] = []
    for p in proxies:
        fp = connection_fingerprint(p)
        if fp not in seen:
            seen.add(fp)
            result.append(p)
    return result, len(proxies) - len(result)


def dedup_level_b(proxies: list[str]) -> tuple[list[str], int]:
    """
    Уровень B (post-TCP): дедупликация по (host, port, credential).
    Убирает один сервер с разными transport-вариантами.
    """
    seen:   set[str]  = set()
    result: list[str] = []
    for p in proxies:
        key = server_credential_key(p)
        if key not in seen:
            seen.add(key)
            result.append(p)
    return result, len(proxies) - len(result)


# ─── Стандартное имя ──────────────────────────────────────────────────────────

def apply_standard_name(url: str, cc: str = "") -> str:
    """Устанавливает имя: "🇺🇸 US VLESS"."""
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

    try:
        parsed   = urlparse(url)
        base_url = urlunparse((scheme, parsed.netloc, parsed.path,
                               parsed.params, parsed.query, ""))
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
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; ProxyCollector/7.0; "
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


# ─── Async проверка живости с измерением латентности ─────────────────────────

async def _tcp_check(
    host: str,
    port: int,
    sem: asyncio.Semaphore,
) -> tuple[bool, float]:
    """
    TCP connect с замером латентности.
    Возвращает (is_alive, latency_ms).
    """
    if not port or _is_private_host(host):
        return True, 0.0
    async with sem:
        t0 = asyncio.get_event_loop().time()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=ALIVE_TIMEOUT,
            )
            latency_ms = (asyncio.get_event_loop().time() - t0) * 1000
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
            return True, round(latency_ms, 1)
        except Exception:
            return False, 0.0


async def check_alive_batch(
    proxies: list[str],
) -> list[tuple[bool, float]]:
    """
    Асинхронная TCP-проверка. Возвращает список (is_alive, latency_ms).
    Живые прокси будут отсортированы по латентности в run().
    """
    sem = asyncio.Semaphore(ALIVE_CONCURRENCY)
    log.info(
        "Проверка живости: %d прокси (TCP %.0fs, %d parallel)...",
        len(proxies), ALIVE_TIMEOUT, ALIVE_CONCURRENCY,
    )
    t0   = asyncio.get_event_loop().time()

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

    alive_results: list[tuple[bool, float]] = []
    for r in results:
        if isinstance(r, Exception):
            alive_results.append((False, 0.0))
        else:
            alive_results.append(r)

    alive_count = sum(1 for ok, _ in alive_results if ok)
    log.info(
        "Живых: %d/%d (%.0f%%) за %.1fс",
        alive_count, len(proxies),
        100 * alive_count / max(1, len(proxies)),
        asyncio.get_event_loop().time() - t0,
    )
    return alive_results


# ─── Сортировка (по латентности внутри каждой группы) ────────────────────────

_SCHEME_ORDER = {s: i for i, s in enumerate([
    "vless", "vmess", "trojan", "ss", "ssr",
    "hy2", "hysteria2", "hysteria",
    "tuic", "naive", "brook", "juicity", "wireguard", "wg",
])}


def _sort_key(item: tuple) -> tuple:
    """Сортировка: протокол → страна → латентность (мс) → хост → порт."""
    proxy, cc, latency_ms = item
    try:
        host, port = _host_port(proxy)
        order      = _SCHEME_ORDER.get(urlparse(proxy).scheme.lower(), 99)
        return (order, cc or "ZZ", latency_ms, host, port)
    except Exception:
        return (99, "ZZ", 9999.0, "", 0)


# ─── Запись результатов ───────────────────────────────────────────────────────

def _file_header(title: str, now: str, count: int) -> str:
    w = 59
    return "\n".join(["# " + "═" * w, f"#  {title}",
                       f"#  Обновлено: {now}", f"#  Прокси  : {count}",
                       "# " + "═" * w, ""])


def write_results(
    proxies: list[str],
    geo_cache: dict[str, dict],
    result_file: str,
    results_dir: str,
    sources_total: int,
    sources_ok: int,
    raw_count: int,
    dup_a: int,
    dup_b: int,
    alive_count: int,
    unique_count: int,
) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    proto_counter:   dict[str, int] = defaultdict(int)
    country_counter: dict[str, int] = defaultdict(int)
    dc_count = 0

    for p in proxies:
        scheme = urlparse(p).scheme.lower()
        proto_counter[SCHEME_LABEL.get(scheme, scheme.upper())] += 1
        try:
            host, _ = _host_port(p)
        except Exception:
            host = "unknown"
        cc = geo_cc(geo_cache, host)
        country_counter[cc or "??"] += 1
        if geo_hosting(geo_cache, host):
            dc_count += 1

    w = 59
    stats = [
        "# " + "═" * w,
        "#  Proxy Collector v7",
        "# " + "─" * w,
        f"#  Обновлено  : {now}",
        f"#  Источников : {sources_ok}/{sources_total} успешно",
        f"#  Извлечено  : {raw_count} (до дедупликации)",
        f"#  Деdup A    : -{dup_a} (полный отпечаток соединения)",
        f"#  Деdup B    : -{dup_b} (по host+port+credential, post-TCP)",
        f"#  Уникальных : {unique_count}",
        f"#  Живых      : {alive_count} ({100*alive_count//max(1,unique_count)}%)",
        f"#  Датацентры : {dc_count} ({100*dc_count//max(1,len(proxies))}% помечено)",
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
    dup_a: int,
    dup_b: int,
    geo_cache: dict[str, dict],
    proxies: list[str],
    avg_latency_ms: float,
    path: str = STATS_FILE,
) -> list[dict]:
    proto_counter:   dict[str, int] = defaultdict(int)
    country_counter: dict[str, int] = defaultdict(int)
    isp_counter:     dict[str, int] = defaultdict(int)
    geo_covered = dc_count = 0

    for p in proxies:
        scheme = urlparse(p).scheme.lower()
        proto_counter[SCHEME_LABEL.get(scheme, scheme.upper())] += 1
        try:
            host, _ = _host_port(p)
        except Exception:
            host = "unknown"
        cc = geo_cc(geo_cache, host)
        isp = geo_isp(geo_cache, host)
        country_counter[cc or "??"] += 1
        if cc:
            geo_covered += 1
        if isp:
            isp_short = isp[:40]
            isp_counter[isp_short] += 1
        if geo_hosting(geo_cache, host):
            dc_count += 1

    entry = {
        "ts":             datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "date":           datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "sources_total":  sources_total,
        "sources_ok":     sources_ok,
        "raw":            raw_count,
        "unique":         unique_count,
        "alive":          alive_count,
        "alive_pct":      round(100 * alive_count / max(1, unique_count), 1),
        "dup_a":          dup_a,
        "dup_b":          dup_b,
        "geo_covered":    geo_covered,
        "dc_count":       dc_count,
        "avg_latency_ms": round(avg_latency_ms, 1),
        "protocols":      dict(proto_counter),
        "countries":      dict(sorted(country_counter.items(), key=lambda x: -x[1])[:20]),
        "top_isps":       dict(sorted(isp_counter.items(),     key=lambda x: -x[1])[:10]),
        "sources":        source_stats,
    }
    history.append(entry)
    if len(history) > STATS_MAX_ENTRIES:
        history = history[-STATS_MAX_ENTRIES:]
    Path(path).write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("Статистика: %d записей → %s", len(history), path)
    return history


# ─── HTML Dashboard ───────────────────────────────────────────────────────────

_DASH = (
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
    '.g4{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px;margin-bottom:20px}'
    '.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}'
    '.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:20px}'
    '@media(max-width:860px){.g2,.g3{grid-template-columns:1fr}}'
    '.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px}'
    '.mc .lbl{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px}'
    '.mc .val{font-size:1.85rem;font-weight:700;line-height:1}'
    '.mc .hint{font-size:.78rem;color:var(--muted);margin-top:3px}'
    '.green{color:var(--green)}.yellow{color:var(--yellow)}.blue{color:var(--accent)}.purple{color:var(--purple)}.red{color:var(--red)}'
    '.card h2{font-size:.85rem;color:var(--muted);margin-bottom:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}'
    '.cw{position:relative;height:240px}.cwtall{position:relative;height:310px}'
    'table{width:100%;border-collapse:collapse;font-size:.8rem}'
    'th{text-align:left;color:var(--muted);font-weight:500;padding:5px 8px;border-bottom:1px solid var(--border)}'
    'td{padding:5px 8px;border-bottom:1px solid #21262d;max-width:360px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}'
    'tr:last-child td{border-bottom:none}'
    '.ok{display:inline-block;padding:1px 7px;border-radius:10px;font-size:.72rem;font-weight:600}'
    '.oy{background:#1a3a24;color:var(--green)}.on{background:#3a1a1a;color:var(--red)}'
    'footer{text-align:center;color:var(--muted);font-size:.78rem;margin-top:20px}'
    'a{color:var(--accent)}'
    '</style></head><body>'
    '<h1>&#128225; Proxy Collector v7</h1>'
    '<p class="sub" id="lu"></p>'
    '<div class="g4" id="cards"></div>'
    '<div class="g2">'
    '<div class="card"><h2>&#128200; История прокси</h2><div class="cw"><canvas id="hc"></canvas></div></div>'
    '<div class="card"><h2>&#129321; Протоколы</h2><div class="cw"><canvas id="pc"></canvas></div></div>'
    '</div>'
    '<div class="g3">'
    '<div class="card"><h2>&#127758; Страны топ-15</h2><div class="cwtall"><canvas id="cc"></canvas></div></div>'
    '<div class="card"><h2>&#128293; Живых % по дням</h2><div class="cwtall"><canvas id="ac"></canvas></div></div>'
    '<div class="card"><h2>&#9201; Средняя латентность (мс)</h2><div class="cwtall"><canvas id="lc"></canvas></div></div>'
    '</div>'
    '<div class="g2">'
    '<div class="card"><h2>&#128202; Протоколы по дням</h2><div class="cwtall"><canvas id="pdc"></canvas></div></div>'
    '<div class="card"><h2>&#128257; Дедупликация по дням</h2><div class="cwtall"><canvas id="ddc"></canvas></div></div>'
    '</div>'
    '<div class="g2" style="margin-bottom:20px">'
    '<div class="card"><h2>&#127970; Топ ISP/провайдеры</h2><div class="cwtall"><canvas id="ic"></canvas></div></div>'
    '<div class="card"><h2>&#128279; Источники (последний запуск)</h2>'
    '<table><thead><tr><th>#</th><th>URL</th><th>Найдено</th><th>Статус</th></tr></thead>'
    '<tbody id="st"></tbody></table></div>'
    '</div>'
    '<footer>Proxy Collector v7 &middot; '
    '<a href="result.txt">result.txt</a> &middot; '
    '<a href="stats.json">stats.json</a></footer>'
    '<script>'
    'const S=__STATS_DATA__;'
    'const L=S[S.length-1]||{},P=S[S.length-2]||{};'
    'document.getElementById("lu").textContent="Последнее обновление: "+(L.ts||"—");'
    'function pct(a,b){return b?Math.round(100*a/b):0}'
    'const cards=['
    '{lbl:"Живых прокси",val:L.alive||0,hint:"из "+(L.unique||0)+" уникальных",cls:"green"},'
    '{lbl:"Процент живых",val:(L.alive_pct||0)+"%",hint:"предыдущий: "+((P.alive_pct||0))+"%",cls:"yellow"},'
    '{lbl:"Средняя латентность",val:(L.avg_latency_ms||0)+"мс",hint:"TCP connect время",cls:"blue"},'
    '{lbl:"Деdup A+B",val:((L.dup_a||0)+(L.dup_b||0)),hint:"A: "+(L.dup_a||0)+" B: "+(L.dup_b||0),cls:"purple"},'
    '{lbl:"Датацентры",val:(L.dc_count||0),hint:pct(L.dc_count||0,L.alive||1)+"% от живых",cls:"red"},'
    '{lbl:"Гео покрытие",val:pct(L.geo_covered||0,L.unique||1)+"%",hint:(L.geo_covered||0)+" хостов",cls:"blue"},'
    '{lbl:"Источников",val:(L.sources_ok||0)+"/"+(L.sources_total||0),hint:"успешно",cls:"green"},'
    '{lbl:"Собрано raw",val:L.raw||0,hint:"до дедупликации",cls:"yellow"},'
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
    'backgroundColor:"rgba(88,166,255,.12)",tension:.3,fill:true,pointRadius:2},'
    '{label:"Живых",data:R.map(s=>s.alive),borderColor:"#3fb950",'
    'backgroundColor:"rgba(63,185,80,.12)",tension:.3,fill:true,pointRadius:2}'
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
    'borderColor:"#3fb950",backgroundColor:"rgba(63,185,80,.18)",'
    'tension:.3,fill:true,pointRadius:2}]},'
    'options:{...base,plugins:{legend:{display:false}},'
    'scales:{...base.scales,y:{...base.scales.y,min:0,max:100}}}});'
    'new Chart(document.getElementById("lc"),{type:"line",data:{labels:lbs,'
    'datasets:[{label:"Латентность мс",data:R.map(s=>s.avg_latency_ms||0),'
    'borderColor:"#d29922",backgroundColor:"rgba(210,153,34,.15)",'
    'tension:.3,fill:true,pointRadius:2}]},'
    'options:{...base,plugins:{legend:{display:false}}}});'
    'const allProtos=[...new Set(S.flatMap(s=>Object.keys(s.protocols||{})))];'
    'const pc2={"VLESS":"#58a6ff","VMESS":"#3fb950","TROJAN":"#d29922","SS":"#bc8cff",'
    '"SSR":"#f85149","HY2":"#79c0ff","TUIC":"#56d364","WG":"#e3b341",'
    '"NAIVE":"#db61a2","BROOK":"#ffa657","JUICITY":"#39d353"};'
    'new Chart(document.getElementById("pdc"),{type:"line",data:{labels:lbs,'
    'datasets:allProtos.slice(0,6).map((p,i)=>({'
    'label:p,data:R.map(s=>(s.protocols||{})[p]||0),'
    'borderColor:pc2[p]||pal[i],backgroundColor:"transparent",tension:.3,pointRadius:2'
    '}))},'
    'options:{...base}});'
    'new Chart(document.getElementById("ddc"),{type:"bar",data:{labels:lbs,'
    'datasets:['
    '{label:"Живых",data:R.map(s=>s.alive),backgroundColor:"rgba(63,185,80,.7)",borderRadius:2},'
    '{label:"Dedup B",data:R.map(s=>s.dup_b||0),backgroundColor:"rgba(188,140,255,.6)",borderRadius:2},'
    '{label:"Dedup A",data:R.map(s=>s.dup_a||0),backgroundColor:"rgba(248,81,73,.5)",borderRadius:2}'
    ']},'
    'options:{...base,plugins:{legend:{labels:{color:"#8b949e",boxWidth:11}}}}});'
    'const isp=L.top_isps||{},ik=Object.keys(isp).slice(0,10),iv=ik.map(k=>isp[k]);'
    'new Chart(document.getElementById("ic"),{type:"bar",data:{labels:ik,'
    'datasets:[{label:"Прокси",data:iv,backgroundColor:"rgba(188,140,255,.7)",borderRadius:3}]},'
    'options:{...base,indexAxis:"y",plugins:{legend:{display:false}}}});'
    'const st=document.getElementById("st");'
    '(L.sources||[]).forEach((s,i)=>{'
    'const url=s.url||"",short=url.length>50?url.slice(0,50)+"…":url;'
    'const tr=document.createElement("tr");'
    'tr.innerHTML=`<td>${i+1}</td><td title="${url}">${short}</td>'
    '<td>${s.found||0}</td>'
    '<td><span class="ok ${s.ok?"oy":"on"}">${s.ok?"✓ OK":"✗ FAIL"}</span></td>`;'
    'st.appendChild(tr)});'
    '</script></body></html>'
)


def generate_dashboard(history: list[dict], output_path: str = DASHBOARD_FILE) -> None:
    html = _DASH.replace("__STATS_DATA__", json.dumps(history, ensure_ascii=False))
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
    log.info("════ Proxy Collector v7 запущен ════")
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

    # 2. Async загрузка (aiohttp, 20 параллельных)
    t0 = loop.time()
    all_raw, source_stats, sources_ok = await fetch_all_sources(urls)
    raw_count = len(all_raw)
    log.info("Загрузка: %.1fс | извлечено %d (raw)", loop.time() - t0, raw_count)

    # 3. Нормализация
    normalized = [n for p in all_raw if (n := normalize_proxy(p))]
    log.info("После нормализации: %d", len(normalized))

    # 4. Дедупликация уровень A (до TCP)
    unique_a, dup_a = dedup_level_a(normalized)
    log.info("Dedup A: %d → %d (удалено %d, полный отпечаток)", len(normalized), len(unique_a), dup_a)

    # 5. TCP-проверка живости с замером латентности
    t0           = loop.time()
    alive_results = await check_alive_batch(unique_a)
    alive_with_lat = [
        (p, lat) for p, (ok, lat) in zip(unique_a, alive_results) if ok
    ]
    alive_count_raw = len(alive_with_lat)
    log.info("Живых (до Dedup B): %d/%d за %.1fс",
             alive_count_raw, len(unique_a), loop.time() - t0)

    # 6. Дедупликация уровень B (post-TCP, по host+port+credential)
    alive_proxies  = [p for p, _ in alive_with_lat]
    alive_proxies_b, dup_b = dedup_level_b(alive_proxies)
    # Сохраняем латентности для отфильтрованных прокси
    lat_map = {p: lat for p, lat in alive_with_lat}
    log.info("Dedup B: %d → %d (удалено %d, host+port+credential)",
             alive_count_raw, len(alive_proxies_b), dup_b)

    unique_count = len(unique_a)
    alive_count  = len(alive_proxies_b)

    # 7. Геолокация (с кэшем, строго последовательно)
    geo_cache    = load_geo_cache()
    cache_before = len(geo_cache)
    all_hosts    = []
    for p in alive_proxies_b:
        try:
            all_hosts.append(_host_port(p)[0])
        except Exception:
            all_hosts.append("unknown")

    t0 = loop.time()
    geo_cache = await geolocate_hosts(all_hosts, geo_cache)
    log.info("Геолокация: %.1fс (+%d новых в кэше)",
             loop.time() - t0, len(geo_cache) - cache_before)
    save_geo_cache(geo_cache)

    # 8. Сортировка: протокол → страна → латентность → хост
    triples = [
        (p, geo_cc(geo_cache, all_hosts[i].lower()), lat_map.get(p, 999.0))
        for i, p in enumerate(alive_proxies_b)
    ]
    triples.sort(key=_sort_key)

    # Средняя латентность для статистики
    lats = [lat for _, _, lat in triples if lat > 0]
    avg_latency_ms = sum(lats) / len(lats) if lats else 0.0

    # 9. Стандартные имена
    renamed = [apply_standard_name(proxy, cc) for proxy, cc, _ in triples]

    # 10. Запись результатов
    write_results(
        renamed, geo_cache, result_file, results_dir,
        len(urls), sources_ok, raw_count,
        dup_a, dup_b, alive_count, unique_count,
    )

    # 11. Статистика + дашборд
    history = load_stats()
    history = save_stats(
        history, source_stats,
        len(urls), sources_ok, raw_count, unique_count,
        alive_count, dup_a, dup_b,
        geo_cache, renamed, avg_latency_ms,
    )
    generate_dashboard(history)

    log.info("════ Готово за %.1fс ════", loop.time() - t_start)
    return 0


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Proxy Collector v7 — async сборщик с двухуровневой дедупликацией."
    )
    parser.add_argument("-s", "--source",  default=SOURCE_FILE)
    parser.add_argument("-o", "--output",  default=RESULT_FILE)
    parser.add_argument("-r", "--results", default=RESULTS_DIR)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    sys.exit(asyncio.run(run(args.source, args.output, args.results, args.verbose)))
