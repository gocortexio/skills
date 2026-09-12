#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Render the COMPLETE HTTP status -> XDM_CONST.HTTP_RSP_CODE_* mapping.

``xdm.network.http.response_code`` is a const-typed field. When a rule
populates it, it must map the full set of status codes -- a production
source can return any code, not just the ones in the build sample. This
helper emits the complete ``if()`` chain from the shipped crosswalk asset
(``assets/http_status_crosswalk.json``), so the author never hand-lists a
partial set (which the linter flags as WARN-048).

Usage:
    python3 scripts/http_status_map.py --render [--temp tmp_status]

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict

_CROSSWALK = Path(__file__).resolve().parent.parent / "assets" / "http_status_crosswalk.json"


def load_crosswalk() -> Dict[str, str]:
    """Return ``{code(str): "XDM_CONST.HTTP_RSP_CODE_*"}`` from the asset."""
    data = json.loads(_CROSSWALK.read_text(encoding="utf-8"))
    return dict(data.get("codes") or {})


def render(temp: str = "tmp_status",
           field: str = "xdm.network.http.response_code") -> str:
    """Render the complete response-code ``if()`` chain over ``temp`` (an
    integer status held in a tmp_ variable). No default branch -- an
    unmatched code produces null, which is safe."""
    codes = load_crosswalk()
    branches = [
        f"    {temp} = {code}, {codes[code]}"
        for code in sorted(codes, key=int)
    ]
    body = ",\n".join(branches)
    return f"{field} = if(\n{body})"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--render", action="store_true",
                    help="print the complete response_code if() chain")
    ap.add_argument("--temp", default="tmp_status",
                    help="tmp_ variable holding the integer status (default tmp_status)")
    ap.add_argument("--field", default="xdm.network.http.response_code",
                    help="target XDM field (default xdm.network.http.response_code)")
    args = ap.parse_args(argv)
    if args.render:
        print(render(args.temp, args.field))
        return 0
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
