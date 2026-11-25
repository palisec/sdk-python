"""Builds the palisec wheel with the standard library only, byte-for-byte reproducibly.

    python scripts/build_wheel.py OUT_DIR           write OUT_DIR/palisec-<version>-py3-none-any.whl
    python scripts/build_wheel.py --check OUT_DIR   fail if the wheel in OUT_DIR differs from the source

The web app serves the committed wheel from palisec.tech/sdk/, so customers can
`pip install` it by URL. CI runs --check so the served wheel never drifts from the source.
"""

from __future__ import annotations

import base64
import hashlib
import io
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "palisec"
VERSION = re.search(r'^__version__ = "([^"]+)"', (SRC / "__init__.py").read_text(encoding="utf-8"), re.M).group(1)
DIST = f"palisec-{VERSION}.dist-info"
WHEEL_NAME = f"palisec-{VERSION}-py3-none-any.whl"


def text(path: Path) -> bytes:
    # Normalize line endings so Windows and Linux checkouts build identical wheels.
    return path.read_bytes().replace(b"\r\n", b"\n")


def metadata() -> bytes:
    readme = text(ROOT / "README.md").decode("utf-8")
    head = "\n".join(
        [
            "Metadata-Version: 2.1",
            "Name: palisec",
            f"Version: {VERSION}",
            "Summary: Python client for Palisec: ask before every agent transaction, send only on ALLOW.",
            "Home-page: https://palisec.tech/docs/sdk/python",
            "Author: Palisec",
            "License: MIT",
            "Requires-Python: >=3.10",
            "Classifier: Programming Language :: Python :: 3",
            "Classifier: License :: OSI Approved :: MIT License",
            "Classifier: Framework :: AsyncIO",
            "Classifier: Typing :: Typed",
            "Project-URL: Homepage, https://palisec.tech",
            "Project-URL: Repository, https://github.com/palisec/sdk-python",
            "Project-URL: Issues, https://github.com/palisec/sdk-python/issues",
            "Project-URL: Documentation, https://palisec.tech/docs/sdk/python",
            "Project-URL: Changelog, https://palisec.tech/changelog",
            "Description-Content-Type: text/markdown",
        ]
    )
    return f"{head}\n\n{readme}".encode("utf-8")


def files() -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for p in sorted(SRC.iterdir()):
        if p.suffix == ".py" or p.name == "py.typed":
            out[f"palisec/{p.name}"] = text(p)
    out[f"{DIST}/LICENSE"] = text(ROOT / "LICENSE")
    out[f"{DIST}/METADATA"] = metadata()
    out[f"{DIST}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: palisec-build\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    rows = []
    for name, data in out.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        rows.append(f"{name},sha256={digest},{len(data)}")
    rows.append(f"{DIST}/RECORD,,")
    out[f"{DIST}/RECORD"] = ("\n".join(rows) + "\n").encode()
    return out


def build() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files().items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buf.getvalue()


def contents(wheel: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(wheel)) as z:
        return {n: z.read(n) for n in z.namelist()}


def main(argv: list[str]) -> int:
    check = "--check" in argv
    args = [a for a in argv if a != "--check"]
    if len(args) != 1:
        print(__doc__)
        return 2
    target = Path(args[0]) / WHEEL_NAME
    wheel = build()
    if check:
        if not target.exists():
            print(f"missing {target}: run `pnpm --filter @palisec/sdk-python pack:web` and commit it")
            return 1
        if contents(target.read_bytes()) != contents(wheel):
            print(f"{target} is out of date: run `pnpm --filter @palisec/sdk-python pack:web` and commit it")
            return 1
        print(f"{WHEEL_NAME} matches the source")
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(wheel)
    print(f"wrote {target} ({len(wheel)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
