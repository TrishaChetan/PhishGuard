"""Command-line interface.

    python -m phishguard.cli url "http://paypa1-secure.xyz/login"
    python -m phishguard.cli email samples/phish.eml
    python -m phishguard.cli batch urls.txt --csv out.csv

Defanged input such as hxxps://paypa1[.]com is accepted everywhere.
Add --defang to print URLs in defanged form (safe to paste into tickets/chat).
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .email_analyzer import analyze_email
from .model import HybridURLModel
from . import allowlist as _allow
from .url_features import defang as _defang


def main(argv=None):
    ap = argparse.ArgumentParser(prog="phishguard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("url"); u.add_argument("url"); u.add_argument("--json", action="store_true")
    e = sub.add_parser("email"); e.add_argument("path"); e.add_argument("--json", action="store_true")
    b = sub.add_parser("batch"); b.add_argument("path"); b.add_argument("--csv")
    for p in (u, e, b):
        p.add_argument("--defang", action="store_true", help="print URLs defanged (hxxp://example[.]com)")
        p.add_argument("--allowlist", metavar="FILE", help="trusted domains, one per line (also: allowlist.txt, PHISHGUARD_ALLOWLIST)")
    args = ap.parse_args(argv)
    allow = _allow.load_allowlist(args.allowlist)
    show = _defang if args.defang else (lambda x: x)
    model = HybridURLModel.load()

    if args.cmd == "url":
        r = model.analyse(args.url, allow)
        if args.json:
            print(json.dumps(r, indent=2)); return
        print(f"{r['verdict'].upper():<11} {r['probability']:.1%}  {show(r['url'])}")
        for reason in r["reasons"]:
            print("  -", reason)
    elif args.cmd == "email":
        rep = analyze_email(Path(args.path).read_bytes(),
                            url_scorer=lambda x: (lambda r: (0.0 if r["allowlisted"] else r["probability"], r["reasons"]))(model.analyse(x, allow)))
        if args.json:
            print(json.dumps(asdict(rep), indent=2)); return
        print(f"{rep.verdict.upper()}  score={rep.score:.2f}  subject={rep.subject!r}")
        for f in rep.header_flags + rep.content_flags:
            print("  -", f)
        for x in rep.url_results:
            print(f"  link {x['probability']:.0%}  {show(x['url'])}")
    else:
        urls = [l.strip() for l in Path(args.path).read_text().splitlines() if l.strip()]
        probs = model.predict_proba(urls)
        out = csv.writer(open(args.csv, "w", newline="") if args.csv else sys.stdout)
        out.writerow(["url", "probability", "phishing", "allowlisted"])
        for url, p in zip(urls, probs):
            trusted = _allow.match(url, allow)
            out.writerow([show(url), f"{p:.4f}", int(p >= model.threshold and not trusted), trusted or ""])


if __name__ == "__main__":
    main()
