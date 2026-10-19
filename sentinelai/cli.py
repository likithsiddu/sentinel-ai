from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .logs import analyze, detect_format, parse_ssh, parse_web
from .logs.report import to_console, to_json, to_markdown
from .logs.simulate import generate

BANNER = r"""
  ____             _   _            _   ___    ___
 / ___|  ___ _ __ | |_(_)_ __   ___| | / _ \  |_ _|
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ || |_| |  | |
  ___) |  __/ | | | |_| | | | |  __/ ||  _  |  | |
 |____/ \___|_| |_|\__|_|_| |_|\___|_||_| |_| |___|   v{v}
"""


def _load_events(path: str, kind: str, year: int | None):
    lines = Path(path).read_text(errors="replace").splitlines()
    if kind == "auto":
        kind = detect_format(lines[:50])
    if kind == "unknown":
        sys.exit("error: could not detect log format. Use --type ssh|web.")
    events = list(parse_ssh(lines, year) if kind == "ssh" else parse_web(lines))
    return events, kind


def _emit(findings, n, notes, fmt, out, color):
    render = {"console": lambda: to_console(findings, n, notes, color=color and not out),
              "json": lambda: to_json(findings, n, notes),
              "markdown": lambda: to_markdown(findings, n, notes)}[fmt]()
    if out:
        Path(out).write_text(render)
        print(f"report written to {out}")
    else:
        print(render)


def cmd_logs_analyze(a) -> int:
    events, kind = _load_events(a.file, a.type, a.year)
    findings, notes = analyze(events, use_ml=not a.no_ml)
    _emit(findings, len(events), [f"parsed as {kind} log"] + notes, a.format, a.out, not a.no_color)
    return 2 if any(f.severity == "CRITICAL" for f in findings) else 0


def cmd_logs_demo(a) -> int:
    ssh, web = generate(a.seed)
    if a.save_dir:
        d = Path(a.save_dir)
        d.mkdir(parents=True, exist_ok=True)
        (d / "auth.log").write_text("\n".join(ssh) + "\n")
        (d / "access.log").write_text("\n".join(web) + "\n")
        print(f"sample logs written to {d}/ (auth.log, access.log)\n")
    events = list(parse_ssh(ssh, 2026)) + list(parse_web(web))
    findings, notes = analyze(events)
    _emit(findings, len(events), ["synthetic demo data (RFC 5737 documentation IPs)"] + notes,
          a.format, a.out, not a.no_color)
    return 0


def cmd_prompt_scan(a) -> int:
    from .promptguard import scan
    if a.file:
        text = Path(a.file).read_text(errors="replace")
    elif a.text:
        text = " ".join(a.text)
    else:
        text = sys.stdin.read()
    r = scan(text, use_ml=not a.no_ml)
    if a.json:
        print(json.dumps(r.to_dict(), indent=2))
    else:
        colors = {"BLOCK": "\033[1;31m", "REVIEW": "\033[1;33m", "ALLOW": "\033[1;32m"}
        tag = f"{colors[r.verdict]}{r.verdict}\033[0m" if not a.no_color else r.verdict
        ml = "n/a" if r.ml_score is None else f"{r.ml_score:.2f}"
        print(f"{tag}  risk={r.score:.2f}  (rules={r.heuristic_score:.2f}, ml={ml})")
        for m in r.matches:
            print(f"  - {m['category']}: {m['rule']}  [OWASP {m['owasp']} | ATLAS {m['atlas']}]")
            print(f"      {m['why']}")
        for s in r.signals:
            print(f"  - obfuscation signal: {s}")
        for p in r.decoded_payloads:
            print(f"  - decoded base64 payload: {p[:80]!r}")
    return 1 if r.verdict == "BLOCK" else 0


def cmd_prompt_eval(a) -> int:
    from .promptguard.evaluate import run
    run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinelai", description="AI-powered defensive security toolkit.")
    p.add_argument("--version", action="version", version=f"sentinelai {__version__}")
    sub = p.add_subparsers(dest="module", required=True)

    logs = sub.add_parser("logs", help="Threat hunting on SSH / web server logs").add_subparsers(
        dest="cmd", required=True)
    an = logs.add_parser("analyze", help="Analyse a log file")
    an.add_argument("file")
    an.add_argument("--type", choices=["auto", "ssh", "web"], default="auto")
    an.add_argument("--year", type=int, help="year for syslog timestamps (auth.log has none)")
    an.add_argument("--format", choices=["console", "json", "markdown"], default="console")
    an.add_argument("--out")
    an.add_argument("--no-ml", action="store_true", help="rules only")
    an.add_argument("--no-color", action="store_true")
    an.set_defaults(fn=cmd_logs_analyze)
    dm = logs.add_parser("demo", help="Generate synthetic attack logs and analyse them")
    dm.add_argument("--seed", type=int, default=7)
    dm.add_argument("--save-dir", help="also write the generated logs here")
    dm.add_argument("--format", choices=["console", "json", "markdown"], default="console")
    dm.add_argument("--out")
    dm.add_argument("--no-color", action="store_true")
    dm.set_defaults(fn=cmd_logs_demo)

    pr = sub.add_parser("prompt", help="Prompt-injection / jailbreak detection").add_subparsers(
        dest="cmd", required=True)
    sc = pr.add_parser("scan", help="Scan text (argument, --file, or stdin)")
    sc.add_argument("text", nargs="*")
    sc.add_argument("--file")
    sc.add_argument("--json", action="store_true")
    sc.add_argument("--no-ml", action="store_true")
    sc.add_argument("--no-color", action="store_true")
    sc.set_defaults(fn=cmd_prompt_scan)
    ev = pr.add_parser("eval", help="Reproduce held-out evaluation metrics")
    ev.set_defaults(fn=cmd_prompt_eval)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if sys.stdout.isatty():
        print(BANNER.format(v=__version__))
    try:
        return args.fn(args)
    except BrokenPipeError:            # e.g. `sentinelai ... | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
