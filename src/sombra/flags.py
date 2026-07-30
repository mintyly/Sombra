"""Flag detection.

The success condition for every Sombra agent is the same: a ``FLAG{...}`` token
appearing somewhere in captured output. Centralising it here means the regex is
defined once and unit-tested once, rather than re-inlined (with subtle drift —
some copies also matched lowercase ``flag{``) in four scripts.
"""

from __future__ import annotations

import re

# Case-insensitive: some ranges plant lowercase ``flag{...}``. ``[^}]*`` keeps
# the match on a single token and cannot run away across a whole file.
FLAG_RE = re.compile(r"flag\{[^}]*\}", re.IGNORECASE)


def find_flag(text: str) -> str | None:
    """Return the first ``FLAG{...}`` token in *text*, or ``None``."""
    if not text:
        return None
    m = FLAG_RE.search(text)
    return m.group(0) if m else None
