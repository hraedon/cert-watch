#!/usr/bin/env python3
"""Screenshot helper for UI development against the local dev instance.

Usage: .venv/bin/python scripts/dev-screenshot.py /path [out.png] [--theme light] [--width 1600]

Not part of the test suite — a design-loop convenience for eyeballing pages
populated/empty and dark/light, per the AGENTS.md UI definition of done.
"""

import sys

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8123"


def main() -> None:
    args = [a for a in sys.argv[1:]]
    theme = "dark"
    width = 1600
    if "--theme" in args:
        i = args.index("--theme")
        theme = args[i + 1]
        del args[i : i + 2]
    if "--width" in args:
        i = args.index("--width")
        width = int(args[i + 1])
        del args[i : i + 2]
    path = args[0] if args else "/"
    out = args[1] if len(args) > 1 else "/tmp/cw-shot.png"

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 1000})
        page.add_init_script(f"localStorage.setItem('cw-theme', '{theme}')")
        page.goto(BASE + path, wait_until="networkidle")
        page.screenshot(path=out, full_page=True)
        browser.close()
    print(out)


if __name__ == "__main__":
    main()
