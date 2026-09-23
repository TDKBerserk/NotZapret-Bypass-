#!/usr/bin/env python3
"""
build_balancer.py — вспомогательный скрипт (см. скрин: "по флагу из ссылки
для импорта собирает все ссылки в одну страну и делает json с
балансировщиком").

Берёт details.json (пишет его collector.py при каждом запуске — там есть
host/ip/sni/страна/пинг по каждому живому конфигу) и по флагу --country
собирает ВСЕ рабочие конфиги этой страны в один xray-core JSON-конфиг:
несколько outbounds (по одному на сервер) + балансировщик (routing.balancers,
strategy leastPing) поверх них. Такой JSON можно импортировать в xray-core
напрямую как полный конфиг клиента — при обрыве текущего сервера xray сам
переключится на следующий по пингу внутри той же страны.

Использование:
    python build_balancer.py --country NL
    python build_balancer.py --country NL --category white
    python build_balancer.py --all            # сразу по всем странам, найденным в details.json
"""

import argparse
import json
from pathlib import Path

from collector import build_balancer_config  # тот же конструктор, что и в общем balancer.json

DETAILS_FILE = "details.json"
OUT_DIR = Path("balancer")


def load_details() -> list[dict]:
    p = Path(DETAILS_FILE)
    if not p.exists():
        raise SystemExit(f"❌ {DETAILS_FILE} не найден — сначала запусти collector.py")
    return json.loads(p.read_text(encoding="utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--country", help="ISO 3166-1 alpha-2 код страны, например NL, DE, NL")
    ap.add_argument("--category", choices=["white", "black", "all"], default="all")
    ap.add_argument("--all", action="store_true", help="собрать JSON сразу по всем странам")
    ap.add_argument("--limit", type=int, default=20, help="сколько серверов страны класть в один balancer JSON")
    args = ap.parse_args()

    if not args.country and not args.all:
        raise SystemExit("Укажи --country CODE или --all")

    details = load_details()
    OUT_DIR.mkdir(exist_ok=True)

    def items_for(country_code: str) -> list[dict]:
        items = [d for d in details if (d.get("country") or "").upper() == country_code.upper()]
        if args.category != "all":
            items = [d for d in items if d.get("category") == args.category]
        items.sort(key=lambda d: d.get("ping_ms", 9e9))
        return items[:args.limit]

    countries = sorted({(d.get("country") or "").upper() for d in details if d.get("country")}) \
        if args.all else [args.country.upper()]

    for code in countries:
        items = items_for(code)
        if not items:
            print(f"  [skip] {code}: нет живых конфигов под текущий фильтр")
            continue
        cfg = build_balancer_config(items, code.lower())
        out_path = OUT_DIR / f"{code}.json"
        out_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  [ok] {out_path}: {len(items)} серверов в балансировщике")


if __name__ == "__main__":
    main()
