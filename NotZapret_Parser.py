#!/usr/bin/env python3
"""
collector.py — White-parser-tg (v2) — адаптирован для GitHub Actions
Собирает VPN-ключи из Telegram-каналов (tg.txt) и делит на белый/чёрный список.
Тег: NotZapret | Bypass
"""

import base64
import json
import re
import socket
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs
from pathlib import Path

import requests

CHANNELS_FILE = "tg.txt"
WHITELIST_IP_FILE = "ip_list.txt"
WHITELIST_SNI_FILE = "sni_list.txt"
OUTPUT_DIR = Path(".")

TELEGRAM_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
HTTP_TIMEOUT = 10
CHECK_TIMEOUT = 5
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


# --------------------------------------------------------------------------
# Сбор ссылок и ключей из Telegram-каналов
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
    try:
        resp = requests.get(url, headers={"User-Agent": TELEGRAM_UA}, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        raw = resp.text
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


def load_previous_keys() -> set[str]:
    """Подмешивает ключи из результата прошлого запуска, чтобы не терять
    рабочие конфиги, если источники временно недоступны."""
    path = Path("all_configs.txt")
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
    """Извлекает SNI-домен из конфига: параметр sni= (vless/trojan reality/tls),
    иначе host= (websocket host header), иначе — сам hostname, если это не IP."""
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

        # Fallback: hostname сам по себе, если это домен, а не IP
        if parsed.hostname:
            try:
                socket.inet_aton(parsed.hostname)
                return None  # это IP, не домен — SNI неизвестен
            except OSError:
                return parsed.hostname
        return None
    except Exception:
        return None


# --------------------------------------------------------------------------
# Проверка доступности через HTTP GET
# --------------------------------------------------------------------------

def measure_ping(ip: str, port: int) -> float | None:
    """TCP-пинг, как в RKP (--tcp-ping): замеряет реальное время
    установления TCP-соединения с ip:port в миллисекундах.
    Возвращает None, если сервер недоступен (сильнее и честнее, чем
    просто bool: заодно даёт данные для сортировки по скорости)."""
    try:
        start = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(CHECK_TIMEOUT)
            result = sock.connect_ex((ip, port))
            if result != 0:
                return None
        return round((time.perf_counter() - start) * 1000, 1)
    except (socket.timeout, OSError):
        return None


def resolve_ip(host: str) -> str | None:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


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
        print(f"  [warn] {path} не найден — все конфиги попадут в чёрный список. "
              f"Запусти update_whitelist_ranges.py перед сбором.", file=sys.stderr)
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
# Переименование с указанием страны + флага (ip-api.com, батчами)
# --------------------------------------------------------------------------

# ISO 3166-1 alpha-2 -> русское название. Покрывает страны, типичные для
# VPN-серверов; для кода, которого нет в словаре, используется сам код.
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
    """Конвертирует ISO 3166-1 alpha-2 код страны в эмодзи-флаг
    (пара regional indicator symbols)."""
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
            resp = requests.post(IPAPI_BATCH_URL, json=[{"query": ip, "fields": "query,countryCode"} for ip in batch],
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
    from urllib.parse import quote
    return f"{base}#{quote(tag)}"


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def process_key(key: str, ip_prefixes: set[str], sni_domains: set[str]) -> dict | None:
    hp = parse_host_port(key)
    if not hp:
        return None
    host, port = hp

    ip = resolve_ip(host)
    if not ip:
        return None

    ping_ms = measure_ping(ip, port)
    if ping_ms is None:
        return None

    sni = parse_sni(key)
    category = classify(ip, sni, ip_prefixes, sni_domains)
    return {"key": key, "host": host, "port": port, "ip": ip, "sni": sni,
            "category": category, "ping_ms": ping_ms}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel-workers", type=int, default=5)
    parser.add_argument("--check-workers", type=int, default=20)
    args = parser.parse_args()

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
    print(f"🔒 IP-префиксов: {len(ip_prefixes)}, SNI-доменов: {len(sni_domains)}")

    all_direct_keys: set[str] = set()
    all_sub_links: set[str] = set()

    print(f"Обхожу {len(channels)} каналов...")
    with ThreadPoolExecutor(max_workers=args.channel_workers) as pool:
        futures = {pool.submit(fetch_channel_html, ch): ch for ch in channels}
        for fut in as_completed(futures):
            ch = futures[fut]
            html = fut.result()
            if not html:
                continue
            keys, links = extract_from_html(html)
            print(f"  [{ch}] прямых ключей: {len(keys)}, ссылок-подписок: {len(links)}")
            all_direct_keys.update(keys)
            all_sub_links.update(links)

    print(f"Скачиваю {len(all_sub_links)} ссылок-подписок...")
    with ThreadPoolExecutor(max_workers=args.check_workers) as pool:
        futures = {pool.submit(fetch_subscription, url): url for url in all_sub_links}
        for fut in as_completed(futures):
            all_direct_keys.update(fut.result())

    previous_keys = load_previous_keys()
    if previous_keys:
        print(f"Подмешиваю {len(previous_keys)} ключей из прошлого запуска для повторной проверки...")
        all_direct_keys.update(previous_keys)

    print(f"Всего уникальных ключей: {len(all_direct_keys)}. Проверяю через TCP ping...")

    results = []
    with ThreadPoolExecutor(max_workers=args.check_workers) as pool:
        futures = {pool.submit(process_key, key, ip_prefixes, sni_domains): key for key in all_direct_keys}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)

    print(f"Живых конфигов: {len(results)}. Определяю страны для тегов...")
    countries = lookup_countries([r["ip"] for r in results])
    for r in results:
        r["country"] = countries.get(r["ip"])
        r["display_key"] = rename_key(r["key"], r["country"], r["ping_ms"])

    # Сортировка по пингу — быстрые первыми
    results.sort(key=lambda r: r["ping_ms"])
    white = [r for r in results if r["category"] == "white"]
    black = [r for r in results if r["category"] == "black"]

    print(f"Итого: белых {len(white)}, чёрных {len(black)}")

    # Сохраняем в корень репозитория
    def write_list(path: Path, items: list[dict]):
        path.write_text("\n".join(r["display_key"] for r in items) + ("\n" if items else ""), encoding="utf-8")

    def write_raw_list(path: Path, items: list[dict]):
        path.write_text("\n".join(r["key"] for r in items) + ("\n" if items else ""), encoding="utf-8")

    def write_base64(path: Path, items: list[dict]):
        blob = "\n".join(r["display_key"] for r in items)
        path.write_text(base64.b64encode(blob.encode("utf-8")).decode("ascii"), encoding="utf-8")

    write_list(Path("whitelist.txt"), white)
    write_list(Path("blacklist.txt"), black)
    write_raw_list(Path("all_configs.txt"), results)
    write_base64(Path("whitelist_base64.txt"), white)
    write_base64(Path("blacklist_base64.txt"), black)

    summary = {
        "total_keys_checked": len(all_direct_keys),
        "alive": len(results),
        "white": len(white),
        "black": len(black),
        "channels": len(channels),
    }
    Path("summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print("✅ Готово. Результаты в корне репозитория.")


if __name__ == "__main__":
    main()
