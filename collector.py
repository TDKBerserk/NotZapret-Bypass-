#!/usr/bin/env python3
"""
collector.py — NotZapret | Bypass — сборщик и проверка VPN-конфигов.

Источники конфигов:
  - Telegram-каналы (tg.txt) — публичная страница https://t.me/s/<channel>
  - Внешние подписки (sources.txt) — прямые raw-ссылки
  - Ручные конфиги (my_configs.txt, опционально) — свои ключи построчно
  - Прошлый запуск (all_configs.txt) — carry-over, чтобы не терять рабочие
    конфиги, если источники временно недоступны

Проверка — двухфазная (иначе на 100+ каналах и 5000+ источниках xray-core
не успеет пройти все конфиги за отведённое время джобы):
  1. Дешёвый TCP-прекчек по уникальным (ip, port) — отсеивает мёртвые хосты
     за секунды. Проверяется каждый уникальный сервер один раз, а не каждый
     конфиг (на один IP часто приходится по 5-50 разных ссылок/uuid).
  2. Настоящая проверка через вшитый xray-core: для каждого выжившего
     конфига поднимается временный процесс xray с сгенерированным JSON
     (single outbound + локальный SOCKS5), через него реально проксируется
     HTTP-запрос на gstatic.com/generate_204. 200/204 = конфиг живой,
     засекается пинг.

Ручное исключение (exclude.txt): конфиг, который ты вручную пропинговал в
Happ и он не работает, заносишь туда как "ip:port" — при каждой пересборке
такие эндпоинты выкидываются ДО проверки и никогда больше не попадут в
результат, даже если источник продолжает их отдавать. Тег вида "#001"
исключать нельзя — нумерация каждый прогон пересчитывается заново и не
привязана к конкретному серверу, а ip:port сервера не меняется.

Результат раскладывается на белый/чёрный список так же, как у RKP:
белый = совпадение одновременно первых двух октетов IP (ip_list.txt) И
SNI-домена (sni_list.txt) — такие конфиги маскируются под трафик разрешённых
в РФ сервисов и проходят при белом списке. Всё остальное — чёрный список
(обход обычных блокировок, когда интернет не ограничен белым списком).

Файлы на выходе (в корне репозитория):
  whitelist.txt / blacklist.txt / all_configs.txt      — как раньше
  whitelist_base64.txt / blacklist_base64.txt          — как раньше
  whitelist.yaml / blacklist.yaml                       — Clash-формат
  summary.json                                          — статистика
  details.json                                          — служебный файл
      (host/ip/sni/страна/пинг/категория по каждому живому конфигу) —
      его читает build_balancer.py для сборки JSON с балансировщиком по стране
"""

import argparse
import base64
import json
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote, quote

import requests

# --------------------------------------------------------------------------
# Файлы и константы
# --------------------------------------------------------------------------

CHANNELS_FILE = "tg.txt"
SOURCES_FILE = "sources.txt"
MANUAL_FILE = "my_configs.txt"
WHITELIST_IP_FILE = "ip_list.txt"
WHITELIST_SNI_FILE = "sni_list.txt"
EXCLUDE_FILE = "exclude.txt"
PREV_ALL_FILE = "all_configs.txt"

TELEGRAM_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
HTTP_TIMEOUT = 10
TEST_URL = "https://www.gstatic.com/generate_204"

IPAPI_BATCH_URL = "http://ip-api.com/batch"
IPAPI_BATCH_SIZE = 100

KEY_PREFIXES = ("vless://", "trojan://", "ss://", "vmess://")

LINK_JUNK_MARKERS = (
    "t.me/", "telegram.org", "telesco.pe",
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    "youtube.com", "youtu.be",
)

LINE_URL_RE = re.compile(r'https?://\S+')
KEY_RE = re.compile(r'(?:vless|trojan|ss|vmess)://\S+')
IP_PORT_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$')


# --------------------------------------------------------------------------
# Сбор ссылок и ключей из Telegram-каналов и внешних источников
# --------------------------------------------------------------------------

def fetch_channel_html(channel: str) -> str | None:
    url = f"https://t.me/s/{channel}"
    try:
        resp = requests.get(url, headers={"User-Agent": TELEGRAM_UA}, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        print(f"  [error] канал {channel}: {e}", file=sys.stderr)
        return None


def is_junk_link(url: str) -> bool:
    low = url.lower()
    return any(marker in low for marker in LINK_JUNK_MARKERS)


def extract_from_html(html: str) -> tuple[set[str], set[str]]:
    direct_keys, sub_links = set(), set()
    for line in html.splitlines():
        for match in KEY_RE.findall(line):
            direct_keys.add(match.rstrip('"\'<>).,'))
        for match in LINE_URL_RE.findall(line):
            clean = match.rstrip('"\'<>).,')
            if not is_junk_link(clean):
                sub_links.add(clean)
    return direct_keys, sub_links


def fetch_subscription(url: str) -> set[str]:
    """Скачивает подписку по прямой ссылке (из Telegram или из sources.txt)
    и достаёт из неё ключи — как есть, так и из base64."""
    try:
        resp = requests.get(url, headers={"User-Agent": TELEGRAM_UA}, timeout=HTTP_TIMEOUT,
                             stream=True)
        resp.raise_for_status()
        raw = resp.raw.read(5 * 1024 * 1024, decode_content=True).decode("utf-8", errors="ignore")
    except requests.RequestException:
        return set()

    try:
        padded = raw.strip() + "=" * (-len(raw.strip()) % 4)
        decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
        if any(p in decoded for p in KEY_PREFIXES):
            raw = raw + "\n" + decoded
    except Exception:
        pass

    return {m.strip().rstrip('"\'<>).,') for m in KEY_RE.findall(raw)}


def load_sources_list(path: str) -> list[str]:
    links = []
    p = Path(path)
    if not p.exists():
        return links
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.startswith(("http://", "https://")):
            links.append(line)
    return links


def load_manual_configs(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    return {m.strip() for m in KEY_RE.findall(p.read_text(encoding="utf-8", errors="ignore"))}


def load_previous_keys() -> set[str]:
    path = Path(PREV_ALL_FILE)
    if not path.exists():
        return set()
    try:
        return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
    except Exception:
        return set()


# --------------------------------------------------------------------------
# Разбор ключей: host:port и SNI
# --------------------------------------------------------------------------

def parse_host_port(key: str) -> tuple[str, int] | None:
    try:
        if key.startswith("vmess://"):
            payload = key[len("vmess://"):]
            payload += "=" * (-len(payload) % 4)
            data = json.loads(base64.b64decode(payload).decode("utf-8", errors="ignore"))
            host, port = data.get("add"), int(data.get("port"))
            return (host, port) if host and port else None

        parsed = urlparse(key)
        if parsed.hostname and parsed.port:
            return parsed.hostname, parsed.port

        if key.startswith("ss://"):
            body = key[len("ss://"):].split("#")[0]
            if "@" not in body:
                padded = body + "=" * (-len(body) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                if "@" in decoded:
                    _, hostport = decoded.rsplit("@", 1)
                    host, port = hostport.split(":")
                    return host, int(port)
        return None
    except Exception:
        return None


def parse_sni(key: str) -> str | None:
    try:
        if key.startswith("vmess://"):
            payload = key[len("vmess://"):]
            payload += "=" * (-len(payload) % 4)
            data = json.loads(base64.b64decode(payload).decode("utf-8", errors="ignore"))
            return data.get("sni") or data.get("host") or None

        parsed = urlparse(key)
        qs = parse_qs(parsed.query)
        for param in ("sni", "host", "peer"):
            if param in qs and qs[param][0]:
                return qs[param][0]

        if parsed.hostname:
            try:
                socket.inet_aton(parsed.hostname)
                return None
            except OSError:
                return parsed.hostname
        return None
    except Exception:
        return None


def resolve_ip(host: str) -> str | None:
    if not host or len(host) > 253:
        return None
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError, ValueError, OSError):
        # UnicodeError — idna-кодек падает на "лейбл пустой или слишком
        # длинный" (мусорный host из битой ссылки-источника); это не сбой
        # DNS, а мусорные данные на входе — просто пропускаем такой хост.
        return None


# --------------------------------------------------------------------------
# Ручной чёрный список (exclude.txt) — по ip:port, переживает смену
# UUID/пути/тега у конфига на том же сервере
# --------------------------------------------------------------------------

def load_exclude_set(path: str) -> set[str]:
    excluded = set()
    p = Path(path)
    if not p.exists():
        return excluded
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip() if not line.strip().startswith("#") else ""
        if not line:
            continue
        m = IP_PORT_RE.match(line)
        if m:
            excluded.add(f"{m.group(1)}:{m.group(2)}")
            continue
        # разрешаем вставить домен:порт или целый ключ вместо голого ip:port
        candidate = line
        if any(candidate.startswith(p_) for p_ in KEY_PREFIXES):
            hp = parse_host_port(candidate)
        else:
            try:
                host, port = candidate.rsplit(":", 1)
                hp = (host, int(port))
            except Exception:
                hp = None
        if hp:
            ip = resolve_ip(hp[0])
            if ip:
                excluded.add(f"{ip}:{hp[1]}")
    return excluded


# --------------------------------------------------------------------------
# Фаза 1: дешёвый TCP-прекчек по уникальным эндпоинтам
# --------------------------------------------------------------------------

def tcp_alive(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


# --------------------------------------------------------------------------
# Вшитый xray-core: сборка outbound-конфига и реальная проверка
# --------------------------------------------------------------------------

def _stream_settings(qs: dict, network: str, security: str) -> dict:
    ss: dict = {"network": network, "security": security}

    def g(name, default=""):
        return qs.get(name, [default])[0]

    if network == "ws":
        ss["wsSettings"] = {"path": unquote(g("path", "/")), "headers": {"Host": g("host")}} if g("host") else \
            {"path": unquote(g("path", "/"))}
    elif network in ("grpc",):
        ss["grpcSettings"] = {"serviceName": unquote(g("serviceName", g("path", ""))),
                               "multiMode": g("mode") == "multi"}
    elif network in ("h2", "http"):
        ss["network"] = "h2"
        hosts = g("host")
        ss["httpSettings"] = {"path": unquote(g("path", "/")),
                               "host": [h for h in hosts.split(",") if h] if hosts else []}
    elif network == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": unquote(g("path", "/")), "host": g("host")}
    elif network == "xhttp":
        ss["xhttpSettings"] = {"path": unquote(g("path", "/")), "host": g("host"),
                                "mode": g("mode", "auto")}
    elif network == "kcp":
        ss["kcpSettings"] = {"header": {"type": g("headerType", "none")}}
    elif network == "quic":
        ss["quicSettings"] = {"security": g("quicSecurity", "none"), "key": g("key", ""),
                               "header": {"type": g("headerType", "none")}}
    # tcp: без доп. настроек

    if security == "tls":
        tls = {"serverName": g("sni") or g("host"), "allowInsecure": g("allowInsecure") in ("1", "true")}
        if g("alpn"):
            tls["alpn"] = [a for a in unquote(g("alpn")).split(",") if a]
        if g("fp"):
            tls["fingerprint"] = g("fp")
        ss["tlsSettings"] = tls
    elif security == "reality":
        reality = {"serverName": g("sni"), "fingerprint": g("fp", "chrome"),
                   "publicKey": g("pbk"), "shortId": g("sid", ""), "spiderX": g("spx", "")}
        ss["realitySettings"] = reality

    return ss


def build_xray_outbound(key: str) -> dict | None:
    """Парсит ссылку-конфиг (vless/trojan/vmess/ss) в outbound для xray-core."""
    try:
        if key.startswith("vless://"):
            parsed = urlparse(key)
            qs = parse_qs(parsed.query)
            network = qs.get("type", ["tcp"])[0]
            security = qs.get("security", ["none"])[0]
            user = {"id": parsed.username, "encryption": qs.get("encryption", ["none"])[0]}
            if qs.get("flow", [""])[0]:
                user["flow"] = qs["flow"][0]
            outbound = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": parsed.hostname, "port": parsed.port,
                                         "users": [user]}]},
                "streamSettings": _stream_settings(qs, network, security),
            }
            return outbound

        if key.startswith("trojan://"):
            parsed = urlparse(key)
            qs = parse_qs(parsed.query)
            network = qs.get("type", ["tcp"])[0]
            security = qs.get("security", ["tls"])[0]
            outbound = {
                "protocol": "trojan",
                "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port,
                                           "password": unquote(parsed.username or "")}]},
                "streamSettings": _stream_settings(qs, network, security),
            }
            return outbound

        if key.startswith("vmess://"):
            payload = key[len("vmess://"):]
            payload += "=" * (-len(payload) % 4)
            data = json.loads(base64.b64decode(payload).decode("utf-8", errors="ignore"))
            network = data.get("net", "tcp") or "tcp"
            security = "tls" if data.get("tls") in ("tls", "reality") else "none"
            qs = {"sni": [data.get("sni", data.get("host", ""))],
                  "host": [data.get("host", "")], "path": [data.get("path", "/")],
                  "serviceName": [data.get("path", "")], "fp": [data.get("fp", "")],
                  "alpn": [data.get("alpn", "")], "allowInsecure": ["0"]}
            outbound = {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": data.get("add"), "port": int(data.get("port")),
                                         "users": [{"id": data.get("id"),
                                                     "alterId": int(data.get("aid", 0) or 0),
                                                     "security": data.get("scy", "auto")}]}]},
                "streamSettings": _stream_settings(qs, network, security),
            }
            return outbound

        if key.startswith("ss://"):
            body = key[len("ss://"):].split("#")[0]
            method = password = None
            if "@" in body:
                userinfo, hostport = body.rsplit("@", 1)
                try:
                    userinfo_dec = base64.b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
                    method, password = userinfo_dec.split(":", 1)
                except Exception:
                    if ":" in userinfo:
                        method, password = userinfo.split(":", 1)
                host, port = hostport.split(":")
            else:
                padded = body + "=" * (-len(body) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                methodpass, hostport = decoded.rsplit("@", 1)
                method, password = methodpass.split(":", 1)
                host, port = hostport.split(":")
            if not method or not password:
                return None
            return {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": host, "port": int(port),
                                           "method": method, "password": password}]},
                "streamSettings": {"network": "tcp"},
            }
    except Exception:
        return None
    return None


class PortPool:
    def __init__(self, start=20000, size=5000):
        self._ports = list(range(start, start + size))
        random.shuffle(self._ports)
        self._lock = __import__("threading").Lock()

    def acquire(self) -> int:
        with self._lock:
            return self._ports.pop()

    def release(self, port: int):
        with self._lock:
            self._ports.append(port)


def real_check(key: str, xray_path: str, port_pool: "PortPool", timeout: float = 8.0) -> float | None:
    """Поднимает временный процесс xray-core с одним outbound и локальным
    SOCKS5-инбаундом, проксирует через него запрос на TEST_URL. 200/204 —
    конфиг реально работает (не просто открыт порт). Возвращает пинг в мс."""
    outbound = build_xray_outbound(key)
    if not outbound:
        return None
    outbound["tag"] = "proxy"

    port = port_pool.acquire()
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"udp": False}}],
        "outbounds": [outbound],
    }

    proc = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="xray_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f)

        proc = subprocess.Popen([xray_path, "run", "-c", tmp_path],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.35)  # дать ядру подняться
        if proc.poll() is not None:
            return None

        proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
        start = time.perf_counter()
        resp = requests.get(TEST_URL, proxies=proxies, timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000
        if resp.status_code in (200, 204):
            return round(elapsed, 1)
        return None
    except Exception:
        return None
    finally:
        if proc is not None:
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        port_pool.release(port)


# --------------------------------------------------------------------------
# Белый/чёрный список: IP-префикс + SNI
# --------------------------------------------------------------------------

def load_ip_prefixes(path: str) -> set[str]:
    prefixes = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    prefixes.add(line)
    except FileNotFoundError:
        print(f"  [warn] {path} не найден — все конфиги попадут в чёрный список.", file=sys.stderr)
    return prefixes


def load_sni_domains(path: str) -> set[str]:
    domains = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    domains.add(line)
    except FileNotFoundError:
        print(f"  [warn] {path} не найден — все конфиги попадут в чёрный список.", file=sys.stderr)
    return domains


def ip_prefix_matches(ip: str, prefixes: set[str]) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return f"{parts[0]}.{parts[1]}" in prefixes


def sni_matches(sni: str | None, domains: set[str]) -> bool:
    if not sni:
        return False
    sni = sni.lower()
    labels = sni.split(".")
    for i in range(len(labels) - 1):
        if ".".join(labels[i:]) in domains:
            return True
    return False


def classify(ip: str, sni: str | None, ip_prefixes: set[str], sni_domains: set[str]) -> str:
    if ip_prefix_matches(ip, ip_prefixes) and sni_matches(sni, sni_domains):
        return "white"
    return "black"


# --------------------------------------------------------------------------
# Страна и тег
# --------------------------------------------------------------------------

COUNTRY_NAMES_RU = {
    "AD": "Андорра", "AE": "ОАЭ", "AL": "Албания", "AM": "Армения", "AR": "Аргентина",
    "AT": "Австрия", "AU": "Австралия", "AZ": "Азербайджан", "BA": "Босния и Герцеговина",
    "BE": "Бельгия", "BG": "Болгария", "BR": "Бразилия", "BY": "Беларусь", "CA": "Канада",
    "CH": "Швейцария", "CL": "Чили", "CN": "Китай", "CY": "Кипр", "CZ": "Чехия",
    "DE": "Германия", "DK": "Дания", "EE": "Эстония", "EG": "Египет", "ES": "Испания",
    "FI": "Финляндия", "FR": "Франция", "GB": "Великобритания", "GE": "Грузия",
    "GR": "Греция", "HK": "Гонконг", "HR": "Хорватия", "HU": "Венгрия", "ID": "Индонезия",
    "IE": "Ирландия", "IL": "Израиль", "IN": "Индия", "IS": "Исландия", "IT": "Италия",
    "JP": "Япония", "KG": "Кыргызстан", "KR": "Южная Корея", "KZ": "Казахстан",
    "LT": "Литва", "LU": "Люксембург", "LV": "Латвия", "MD": "Молдова", "ME": "Черногория",
    "MK": "Северная Македония", "MT": "Мальта", "MX": "Мексика", "MY": "Малайзия",
    "NL": "Нидерланды", "NO": "Норвегия", "NZ": "Новая Зеландия", "PH": "Филиппины",
    "PL": "Польша", "PT": "Португалия", "RO": "Румыния", "RS": "Сербия", "RU": "Россия",
    "SE": "Швеция", "SG": "Сингапур", "SI": "Словения", "SK": "Словакия", "TH": "Таиланд",
    "TJ": "Таджикистан", "TM": "Туркменистан", "TR": "Турция", "TW": "Тайвань",
    "UA": "Украина", "US": "США", "UZ": "Узбекистан", "VN": "Вьетнам", "ZA": "ЮАР",
}


def country_flag(code: str | None) -> str:
    if not code or len(code) != 2 or not code.isalpha():
        return "🏳️"
    return "".join(chr(127397 + ord(c)) for c in code.upper())


def country_name_ru(code: str | None) -> str:
    if not code:
        return "Неизвестно"
    return COUNTRY_NAMES_RU.get(code.upper(), code.upper())


def lookup_countries(ips: list[str]) -> dict[str, str]:
    countries = {}
    unique_ips = list(dict.fromkeys(ips))
    for i in range(0, len(unique_ips), IPAPI_BATCH_SIZE):
        batch = unique_ips[i:i + IPAPI_BATCH_SIZE]
        try:
            resp = requests.post(IPAPI_BATCH_URL,
                                  json=[{"query": ip, "fields": "query,countryCode"} for ip in batch],
                                  timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            for entry in resp.json():
                if entry.get("countryCode"):
                    countries[entry["query"]] = entry["countryCode"]
        except Exception as e:
            print(f"  [warn] ip-api.com батч не удался: {e}", file=sys.stderr)
    return countries


def rename_key(key: str, country_code: str | None, ping_ms: float) -> str:
    base = key.split("#")[0]
    flag = country_flag(country_code)
    name = country_name_ru(country_code)
    tag = f"{flag} {name} | {ping_ms:.0f}ms | NotZapret | Bypass"
    return f"{base}#{quote(tag)}"


# --------------------------------------------------------------------------
# Clash YAML
# --------------------------------------------------------------------------

def _yaml_str(s: str) -> str:
    escaped = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def to_clash_proxy(item: dict) -> dict | None:
    """dict с полями type/server/port/... под формат Clash proxies:.
    Поддержаны vless/trojan/ss (самые частые в паблик-листах)."""
    key = item["key"]
    display_name = item["display_key"].split("#", 1)[-1]
    name = unquote(display_name) if display_name else item["display_key"]

    try:
        if key.startswith("vless://"):
            parsed = urlparse(key)
            qs = parse_qs(parsed.query)
            proxy = {"name": name, "type": "vless", "server": item["ip"], "port": item["port"],
                     "uuid": parsed.username, "udp": True,
                     "encryption": qs.get("encryption", ["none"])[0],
                     "network": qs.get("type", ["tcp"])[0]}
            if qs.get("security", ["none"])[0] in ("tls", "reality"):
                proxy["tls"] = True
                sni = qs.get("sni", [""])[0]
                if sni:
                    proxy["servername"] = sni
                if qs.get("fp"):
                    proxy["client-fingerprint"] = qs["fp"][0]
            if qs.get("security", [""])[0] == "reality":
                proxy["reality-opts"] = {"public-key": qs.get("pbk", [""])[0],
                                          "short-id": qs.get("sid", [""])[0]}
            if qs.get("flow"):
                proxy["flow"] = qs["flow"][0]
            return proxy

        if key.startswith("trojan://"):
            parsed = urlparse(key)
            qs = parse_qs(parsed.query)
            proxy = {"name": name, "type": "trojan", "server": item["ip"], "port": item["port"],
                     "password": unquote(parsed.username or ""), "udp": True}
            sni = qs.get("sni", [""])[0]
            if sni:
                proxy["sni"] = sni
            if qs.get("allowInsecure", ["0"])[0] in ("1", "true"):
                proxy["skip-cert-verify"] = True
            network = qs.get("type", ["tcp"])[0]
            if network != "tcp":
                proxy["network"] = network
            return proxy

        if key.startswith("ss://"):
            outbound = build_xray_outbound(key)
            if not outbound:
                return None
            srv = outbound["settings"]["servers"][0]
            return {"name": name, "type": "ss", "server": item["ip"], "port": item["port"],
                    "cipher": srv["method"], "password": srv["password"], "udp": True}
    except Exception:
        return None
    return None


def write_clash_yaml(path: Path, items: list[dict], label: str):
    lines = [f"# {path.name} - {label} ({len(items)} конфигов, автогенерация collector.py)",
             "proxies:"]
    kept = 0
    for item in items:
        proxy = to_clash_proxy(item)
        if not proxy:
            continue
        kept += 1
        lines.append(f"- name: {_yaml_str(proxy.pop('name'))}")
        for k, v in proxy.items():
            if isinstance(v, dict):
                lines.append(f"  {k}:")
                for k2, v2 in v.items():
                    lines.append(f"    {k2}: {_yaml_str(v2) if isinstance(v2, str) else v2}")
            elif isinstance(v, str):
                lines.append(f"  {k}: {_yaml_str(v)}")
            else:
                lines.append(f"  {k}: {v}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return kept


# --------------------------------------------------------------------------
# Балансировщик — общий JSON-конфиг xray-core с несколькими outbounds и
# routing.balancers (leastPing) поверх них. Используется и здесь (общий
# balancer.json из вайфай+инет вместе), и в build_balancer.py (тот же
# конструктор, но по одной стране за раз через --country).
# --------------------------------------------------------------------------

def build_balancer_config(items: list[dict], group_tag: str) -> dict:
    outbounds = []
    balancer_tags = []
    for i, item in enumerate(items):
        ob = build_xray_outbound(item["key"])
        if not ob:
            continue
        tag = f"{group_tag}-{i:03d}"
        ob["tag"] = tag
        outbounds.append(ob)
        balancer_tags.append(tag)

    outbounds.append({"protocol": "freedom", "tag": "direct", "settings": {}})
    outbounds.append({"protocol": "blackhole", "tag": "block", "settings": {}})

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": 1080, "protocol": "socks",
            "settings": {"udp": True},
            "tag": "socks-in",
        }],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [{
                "tag": f"balancer-{group_tag}",
                "selector": balancer_tags,
                "strategy": {"type": "leastPing"},
            }],
            "rules": [{
                "type": "field",
                "inboundTag": ["socks-in"],
                "balancerTag": f"balancer-{group_tag}",
            }],
        },
        "observatory": {
            "subjectSelector": balancer_tags,
            "probeUrl": "https://www.gstatic.com/generate_204",
            "probeInterval": "60s",
        },
    }


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--channel-workers", type=int, default=5)
    ap.add_argument("--fetch-workers", type=int, default=20, help="параллельных скачиваний подписок")
    ap.add_argument("--tcp-workers", type=int, default=300, help="параллельность дешёвого TCP-прекчека")
    ap.add_argument("--tcp-timeout", type=float, default=2.5)
    ap.add_argument("--xray-workers", type=int, default=20, help="параллельность реальной xray-проверки")
    ap.add_argument("--xray-path", default="./xray", help="путь к бинарнику xray-core")
    ap.add_argument("--max-per-endpoint", type=int, default=2,
                     help="не больше стольки конфигов с одного ip:port идёт на дорогую xray-проверку")
    ap.add_argument("--max-candidates", type=int, default=6000,
                     help="если живых эндпоинтов больше — берётся случайная выборка")
    ap.add_argument("--no-sources", action="store_true", help="не подключать sources.txt")
    args = ap.parse_args()

    if not shutil.which(args.xray_path) and not Path(args.xray_path).exists():
        print(f"❌ Бинарник xray-core не найден по пути {args.xray_path}. "
              f"Он должен быть скачан шагом в workflow ДО запуска collector.py.", file=sys.stderr)
        sys.exit(1)

    if not Path(CHANNELS_FILE).exists():
        print(f"❌ Файл {CHANNELS_FILE} не найден!", file=sys.stderr)
        sys.exit(1)

    channels = [
        line.strip() for line in Path(CHANNELS_FILE).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    print(f"📡 Загружено каналов: {len(channels)}")

    ip_prefixes = load_ip_prefixes(WHITELIST_IP_FILE)
    sni_domains = load_sni_domains(WHITELIST_SNI_FILE)
    exclude_set = load_exclude_set(EXCLUDE_FILE)
    print(f"🔒 IP-префиксов: {len(ip_prefixes)}, SNI-доменов: {len(sni_domains)}, "
          f"в ручном exclude.txt: {len(exclude_set)}")

    # ---- Сбор кандидатов -------------------------------------------------
    all_direct_keys: set[str] = set()
    all_sub_links: set[str] = set()

    print(f"Обхожу {len(channels)} Telegram-каналов...")
    with ThreadPoolExecutor(max_workers=args.channel_workers) as pool:
        futures = {pool.submit(fetch_channel_html, ch): ch for ch in channels}
        for fut in as_completed(futures):
            html = fut.result()
            if not html:
                continue
            keys, links = extract_from_html(html)
            all_direct_keys.update(keys)
            all_sub_links.update(links)

    if not args.no_sources:
        sources = load_sources_list(SOURCES_FILE)
        print(f"📄 Внешних источников в {SOURCES_FILE}: {len(sources)}")
        all_sub_links.update(sources)

    print(f"Скачиваю {len(all_sub_links)} ссылок-подписок...")
    with ThreadPoolExecutor(max_workers=args.fetch_workers) as pool:
        futures = {pool.submit(fetch_subscription, url): url for url in all_sub_links}
        for fut in as_completed(futures):
            all_direct_keys.update(fut.result())

    manual = load_manual_configs(MANUAL_FILE)
    if manual:
        print(f"✍️  Ручных конфигов из {MANUAL_FILE}: {len(manual)}")
        all_direct_keys.update(manual)

    previous_keys = load_previous_keys()
    if previous_keys:
        print(f"Подмешиваю {len(previous_keys)} ключей из прошлого запуска для повторной проверки...")
        all_direct_keys.update(previous_keys)

    print(f"Всего уникальных ключей-кандидатов: {len(all_direct_keys)}")

    # ---- Группировка по эндпоинту + применение exclude.txt --------------
    endpoint_to_configs: dict[tuple[str, int], list[str]] = {}
    for key in all_direct_keys:
        hp = parse_host_port(key)
        if not hp:
            continue
        ip = resolve_ip(hp[0])
        if not ip:
            continue
        port = hp[1]
        if f"{ip}:{port}" in exclude_set:
            continue
        endpoint_to_configs.setdefault((ip, port), []).append(key)

    print(f"Уникальных серверов после resolve + exclude.txt: {len(endpoint_to_configs)}")

    # ---- Фаза 1: дешёвый TCP-прекчек по уникальным серверам -------------
    print("Фаза 1/2: TCP-прекчек...")
    alive_endpoints: list[tuple[str, int]] = []
    with ThreadPoolExecutor(max_workers=args.tcp_workers) as pool:
        futures = {pool.submit(tcp_alive, ip, port, args.tcp_timeout): (ip, port)
                   for (ip, port) in endpoint_to_configs}
        for fut in as_completed(futures):
            ep = futures[fut]
            if fut.result():
                alive_endpoints.append(ep)

    print(f"Живых по TCP серверов: {len(alive_endpoints)}")

    # ---- Ограничиваем количество кандидатов для дорогой xray-проверки ---
    candidates: list[str] = []
    for ep in alive_endpoints:
        candidates.extend(endpoint_to_configs[ep][:args.max_per_endpoint])

    if len(candidates) > args.max_candidates:
        print(f"Кандидатов {len(candidates)} > лимита {args.max_candidates} — беру случайную выборку.")
        candidates = random.sample(candidates, args.max_candidates)

    print(f"Фаза 2/2: реальная проверка через xray-core ({len(candidates)} конфигов, "
          f"{args.xray_workers} воркеров)...")

    port_pool = PortPool()
    results = []
    with ThreadPoolExecutor(max_workers=args.xray_workers) as pool:
        futures = {pool.submit(real_check, key, args.xray_path, port_pool): key for key in candidates}
        done = 0
        for fut in as_completed(futures):
            key = futures[fut]
            ping_ms = fut.result()
            done += 1
            if done % 200 == 0:
                print(f"  ...проверено {done}/{len(candidates)}")
            if ping_ms is None:
                continue
            hp = parse_host_port(key)
            ip = resolve_ip(hp[0])
            sni = parse_sni(key)
            category = classify(ip, sni, ip_prefixes, sni_domains)
            results.append({"key": key, "host": hp[0], "port": hp[1], "ip": ip, "sni": sni,
                             "category": category, "ping_ms": ping_ms})

    print(f"Живых (реально проверено xray-core) конфигов: {len(results)}. Определяю страны...")
    countries = lookup_countries([r["ip"] for r in results])
    for r in results:
        r["country"] = countries.get(r["ip"])
        r["display_key"] = rename_key(r["key"], r["country"], r["ping_ms"])

    results.sort(key=lambda r: r["ping_ms"])
    white = [r for r in results if r["category"] == "white"]
    black = [r for r in results if r["category"] == "black"]

    print(f"Итого: белых {len(white)}, чёрных {len(black)}")

    # ---- Запись результатов ----------------------------------------------
    def write_list(path: Path, items: list[dict]):
        path.write_text("\n".join(r["display_key"] for r in items) + ("\n" if items else ""),
                         encoding="utf-8")

    def write_raw_list(path: Path, items: list[dict]):
        path.write_text("\n".join(r["key"] for r in items) + ("\n" if items else ""), encoding="utf-8")

    def write_base64(path: Path, items: list[dict]):
        blob = "\n".join(r["display_key"] for r in items)
        path.write_text(base64.b64encode(blob.encode("utf-8")).decode("ascii"), encoding="utf-8")

    # Основные имена (как на скрине): вайфай = белый список (маскировка под
    # разрешённые сервисы), инет = чёрный список (обход обычных блокировок).
    write_list(Path("wifi.txt"), white)
    write_list(Path("inet.txt"), black)
    write_base64(Path("wifi_base64.txt"), white)
    write_base64(Path("inet_base64.txt"), black)
    n_white_yaml = write_clash_yaml(Path("wifi.yaml"), white, "обход белого списка (вайфай)")
    n_black_yaml = write_clash_yaml(Path("inet.yaml"), black, "обход обычных блокировок (инет)")

    # Старые имена оставляю как копии — если ты уже где-то раздавал ссылки
    # на whitelist.txt/blacklist.txt (в т.ч. в старом README), они не
    # отвалятся. Если не нужны — просто убери эти 6 строк.
    write_list(Path("whitelist.txt"), white)
    write_list(Path("blacklist.txt"), black)
    write_base64(Path("whitelist_base64.txt"), white)
    write_base64(Path("blacklist_base64.txt"), black)
    write_clash_yaml(Path("whitelist.yaml"), white, "обход белого списка")
    write_clash_yaml(Path("blacklist.yaml"), black, "обход обычных блокировок")

    write_raw_list(Path("all_configs.txt"), results)

    # Третий, "авто" конфиг — не просто склейка, а полноценный
    # балансировщик: топ по пингу из вайфай+инет вместе, один xray JSON
    # с routing.balancers (leastPing) поверх нескольких outbounds.
    BALANCER_TOP_N = 30
    balancer_items = sorted(results, key=lambda r: r["ping_ms"])[:BALANCER_TOP_N]
    balancer_cfg = build_balancer_config(balancer_items, "notzapret")
    Path("balancer.json").write_text(json.dumps(balancer_cfg, ensure_ascii=False, indent=2),
                                      encoding="utf-8")

    Path("details.json").write_text(
        json.dumps([{k: v for k, v in r.items() if k != "key"} | {"key": r["key"]} for r in results],
                    ensure_ascii=False, indent=2),
        encoding="utf-8")

    summary = {
        "total_keys_checked": len(candidates),
        "endpoints_tcp_alive": len(alive_endpoints),
        "alive": len(results),
        "white": len(white),
        "black": len(black),
        "channels": len(channels),
        "excluded_endpoints": len(exclude_set),
    }
    Path("summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"✅ Готово. wifi.yaml: {n_white_yaml} прокси, inet.yaml: {n_black_yaml} прокси, "
          f"balancer.json: {len(balancer_cfg['routing']['balancers'][0]['selector'])} серверов.")


if __name__ == "__main__":
    main()
    
