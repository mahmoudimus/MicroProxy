"""Regenerates the Brotli test fixtures next to this file with the reference encoder.

    python -m pip install brotli==1.2.0
    python generate.py

license.txt is a copy of the repository's LICENSE; records.json is generated here. Each .br file
is the source compressed with the quality (q) and window (w, in bits) in its name.
"""

import pathlib

import brotli

HERE = pathlib.Path(__file__).resolve().parent


def records() -> bytes:
    lines = []
    for i in range(2000):
        lines.append(
            '{"id": %d, "name": "item %d", "price": %d.%02d, "tags": ["%s", "%s"], "active": %s}\n'
            % (i, i * 7919 % 10007, i * 37 % 1000, i % 100, "abcdefgh"[i % 8] * 3,
               "xyz"[i % 3] * (1 + i % 5), "true" if i % 3 else "false"))
    return "".join(lines).encode("ascii")


def main() -> None:
    (HERE / "records.json").write_bytes(records())
    fixtures = {
        "license.txt.q11w22.br": ("license.txt", 11, 22),
        "records.json.q1w16.br": ("records.json", 1, 16),
        "records.json.q6w24.br": ("records.json", 6, 24),
    }
    for name, (source, quality, window) in fixtures.items():
        data = (HERE / source).read_bytes()
        (HERE / name).write_bytes(brotli.compress(data, quality=quality, lgwin=window))


if __name__ == "__main__":
    main()
