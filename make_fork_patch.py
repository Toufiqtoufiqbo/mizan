"""Generate the Schemathesis fork patch from the standalone Mizan package.

The fork gets the law engine as `schemathesis.laws`, with imports rewritten.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "src" / "mizan"
TARGET = ROOT / "fork-patch"

HEADER = '''"""{doc}"""

from __future__ import annotations

# The engine lives in `schemathesis.laws`; the imports below are rewritten from
# the standalone `mizan` package when this patch is generated.
'''


def rewrite(text: str) -> str:
    text = text.replace("from mizan.", "from schemathesis.laws.")
    text = text.replace("import mizan.", "import schemathesis.laws.")
    return text


def main() -> None:
    docs = {
        "core.py": "Law model: principals, resources, access rules and the access matrix.",
        "taint.py": "Write taint: attribute every database write to the principal that caused it.",
        "proof.py": "Proof bundles: a finding that can be replayed, diffed and regressed against.",
    }
    for name, doc in docs.items():
        target = TARGET / "src" / "schemathesis" / "laws" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        body = rewrite((SOURCE / name).read_text(encoding="utf-8"))
        # Drop the module docstring of the original file, keep the rest.
        body = re.sub(r'^"""(?:.|\n)*?"""\n\n', "", body, count=1)
        target.write_text(HEADER.format(doc=doc) + body, encoding="utf-8")
        print("wrote", target)

    checks = rewrite((SOURCE / "schemathesis_plugin.py").read_text(encoding="utf-8"))
    checks = re.sub(r'^"""(?:.|\n)*?"""\n\n', "", checks, count=1)
    target = TARGET / "src" / "schemathesis" / "laws" / "checks.py"
    target.write_text(
        HEADER.format(doc="Schemathesis check that enforces the learned laws.") + checks, encoding="utf-8"
    )
    print("wrote", target)


if __name__ == "__main__":
    main()
