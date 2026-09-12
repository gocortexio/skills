#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Render a COMPLETE Kerberos code -> XDM_CONST.* if()-chain.

The Kerberos const fields (`xdm.auth.kerberos_tgt.encryption_type` /
`error_code` and their `kerberos_tgs` twins) are const-typed over large
numeric enums. A 4768 / 4769 rule casts the Windows `TicketEncryptionType`
/ `Status` (logged as hex) to an integer and maps it via the full chain --
a production KDC emits codes the build sample never contained. This helper
emits the complete chain from the shipped crosswalk asset
(``assets/kerberos_crosswalk.json``) for the two groups a rule usually
maps: ``encryption_type`` and ``error_code``.

Usage:
    python3 scripts/kerberos_map.py --render --group encryption_type \\
        [--temp tmp_etype] [--field xdm.auth.kerberos_tgt.encryption_type]
    python3 scripts/kerberos_map.py --render --group error_code

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict

_CROSSWALK = Path(__file__).resolve().parent.parent / "assets" / "kerberos_crosswalk.json"

# The two groups this renderer supports, with their default target field and
# the crosswalk group key.
_GROUPS = {
    "encryption_type": (
        "KERBEROS_ENCRYPTION_TYPE",
        "xdm.auth.kerberos_tgt.encryption_type",
        "tmp_etype",
    ),
    "error_code": (
        "KERBEROS_ERROR_CODE",
        "xdm.auth.kerberos_tgt.error_code",
        "tmp_kerb_error",
    ),
}


def load_group(group: str) -> Dict[str, str]:
    """Return ``{code(str): "XDM_CONST.*"}`` for a crosswalk group key."""
    data = json.loads(_CROSSWALK.read_text(encoding="utf-8"))
    return dict((data.get("groups") or {}).get(group) or {})


def render(group: str, temp: str = "", field: str = "") -> str:
    """Render the complete if()-chain for one supported group over an integer
    temp. No default branch -- an unmatched code produces null, which is safe."""
    if group not in _GROUPS:
        raise ValueError(
            f"unsupported group {group!r}; choose from {sorted(_GROUPS)}"
        )
    grp_key, default_field, default_temp = _GROUPS[group]
    temp = temp or default_temp
    field = field or default_field
    codes = load_group(grp_key)
    branches = [
        f"    {temp} = {code}, {codes[code]}"
        for code in sorted(codes, key=int)
    ]
    body = ",\n".join(branches)
    return f"{field} = if(\n{body})"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--render", action="store_true",
                    help="print the complete if() chain for --group")
    ap.add_argument("--group", choices=sorted(_GROUPS), default="encryption_type",
                    help="which Kerberos chain to render (default encryption_type)")
    ap.add_argument("--temp", default="",
                    help="tmp_ variable holding the integer code")
    ap.add_argument("--field", default="",
                    help="target XDM field (defaults to the kerberos_tgt leaf)")
    args = ap.parse_args(argv)
    if args.render:
        print(render(args.group, args.temp, args.field))
        return 0
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
