#!/usr/bin/env python3
"""Release-claim gate over the MicroProxy crypto obligation ledger.

Normal mode validates the ledger and prints machine-readable claim status.  A
non-supported residual claim is reported but does not fail the normal check.
``--require CLAIM`` and ``--require-all`` fail closed: a deferred, blocked,
snapshot, not-selected or unsupported claim is never accepted as done.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_crypto_obligations import (  # noqa: E402
    COMPLETION_REQUIRED_CLAIMS,
    ROOT,
    STATUS_SCHEMA,
    LedgerError,
    load_json,
    validate_ledger,
)


def _claim_failure(claim: str, reason: str, status: str | None = None) -> dict[str, object]:
    return {"claim": claim, "status": status, "reason": reason}


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require", action="append", default=[], metavar="CLAIM",
                        help="require one supported claim; repeatable")
    parser.add_argument("--require-all", action="store_true",
                        help="require every completion-required claim to be supported")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        status = validate_ledger(args.root, args.ledger)
    except LedgerError as exc:
        status = {"schema": STATUS_SCHEMA, "ok": False,
                  "claim_failures": [_claim_failure(None, str(exc))]}
        code = 1
    except Exception as exc:
        status = {"schema": STATUS_SCHEMA, "ok": False,
                  "claim_failures": [_claim_failure(None, f"internal validator failure: {type(exc).__name__}: {exc}")]}
        code = 2
    else:
        claims_status = status["claims"]
        required = list(dict.fromkeys(args.require))
        if args.require_all:
            required.extend(sorted(COMPLETION_REQUIRED_CLAIMS))
        required = list(dict.fromkeys(required))
        failures: list[dict[str, object]] = []
        for claim in required:
            found = claims_status.get(claim)
            if found is None:
                failures.append(_claim_failure(claim, "unknown claim", None))
            elif found != "supported":
                failures.append(_claim_failure(claim, f"claim is {found}, not supported", found))
        status["required_claims"] = required
        status["claim_failures"] = failures
        status["ok"] = not failures
        code = 0 if not failures else 1

    text = json.dumps(status, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".part")
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(args.output)
    sys.stdout.write(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
