#!/usr/bin/env python3
"""Search driver for engine3: constrain the digest axis to what the
author's OP_RETURNs now require.

Confirmed constraints applied here:
  - digest = contiguous substring of the raw-block hex text,
    UTF-8, no trailing newline (blocks 969361 x3, 719623a4)
  - length even, in {18..32}, SAME for both cosigners (969390)
  - same passphrase for both cosigners (969361)
  - same BIP48 account for both roots (implied by the rule quote)
  - entropy = SHA256(digest)[0:16]  (968996, 969361)
"""
import argparse, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from solve import GENESIS_RAW, passphrase_set, LEAF_SETS_STD  # noqa

# Reuse solve.py's verified 285-byte genesis block.
GENHEX_LOW = GENESIS_RAW.hex()
assert len(GENHEX_LOW) == 570

PASS_CANDIDATES = [
    "Hal Finney", "hal finney", "HAL FINNEY", "HalFinney", "halfinney",
    "HALFINNEY", "Halfinney", "Harold Finney", "harold finney",
    "Harold Thomas Finney", "harold thomas finney", "Harold Thomas Finney II",
    "Hal", "hal", "HAL", "Finney", "finney",
    "Satoshi Nakamoto", "satoshi nakamoto", "SATOSHI NAKAMOTO",
    "SatoshiNakamoto", "satoshinakamoto", "Satoshi", "satoshi", "Nakamoto",
]


def digests_for(hextext, minlen=18, maxlen=32, steplength=2):
    out = []
    L = minlen
    while L <= maxlen:
        for i in range(0, len(hextext) - L + 1):
            out.append((f"L{L}_{i}", hextext[i:i + L].encode()))
        L += steplength
    return out


def accounts_pruned():
    return [
        (0, "zero"), (1, "one"), (2, "two"), (3, "three"),
        (2009, "year"), (2083236893, "nonce"), (1231006505, "time"),
        (486604799, "bits"), (47, "headline_len"), (69, "text_len"),
        (77, "scriptsig_len"), (80, "header_len"), (204, "tx_len"),
        (285, "block_len"), (1032009, "date_mdy"), (20090103, "date_ymd"),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--passes", default="hal")
    ap.add_argument("--accounts", default="pruned")
    ap.add_argument("--source", default="lower",
                    choices=("lower", "upper", "both"))
    ap.add_argument("--minlen", type=int, default=18)
    ap.add_argument("--maxlen", type=int, default=32)
    ap.add_argument("--leaves", default="std")
    ap.add_argument("--chunk-start", type=int, default=0)
    ap.add_argument("--chunk-size", type=int, default=0)
    ap.add_argument("--all-len", action="store_true")
    ap.add_argument("--list-only", action="store_true")
    args = ap.parse_args()

    texts = []
    if args.source in ("lower", "both"):
        texts.append(GENHEX_LOW)
    if args.source in ("upper", "both"):
        texts.append(GENHEX_LOW.upper())

    # Substrings are identified by (source text, start, length); dedupe
    # identical label only when byte-identical within one source.
    specs = []
    seen = set()
    for t in texts:
        for label, data in digests_for(t, args.minlen, args.maxlen):
            if data in seen:
                continue
            seen.add(data)
            specs.append((label, data))

    if args.passes == "hal":
        passes = [p for p in PASS_CANDIDATES
                  if any(k in p.lower() for k in ("hal", "finney", "harold"))]
    elif args.passes == "satoshi":
        passes = [p for p in PASS_CANDIDATES if "satoshi" in p.lower() or "nakamoto" in p.lower()]
    elif args.passes == "all":
        passes = PASS_CANDIDATES
    else:
        passes = args.passes.split(",")

    accounts = accounts_pruned() if args.accounts == "pruned" else [
        (int(x), "explicit") for x in args.accounts.split(",")]

    leaf_std = [("00|00", [0, 0], [0, 0], False),
                ("00|01", [0, 0], [0, 1], False),
                ("|", [], [], False)]
    leaf_hard = [("00h|00h", [0, 0], [0, 0], True),
                 ("00h|01h", [0, 0], [0, 1], True)]
    leaves = leaf_std if args.leaves == "std" else leaf_hard if args.leaves == "hard" else leaf_std + leaf_hard

    if args.chunk_size:
        specs = specs[args.chunk_start:args.chunk_start + args.chunk_size]

    buf = []
    for label, data in specs:
        buf.append(f"D {len(data)} {label}\n".encode())
        buf.append(data.hex().encode() + b"\n")
    for p in passes:
        buf.append(f"P {p}\n".encode())
    for a, lab in accounts:
        buf.append(f"A {a} {lab}\n".encode())
    uniq_paths = set()
    for lab, la, lb, hard in leaves:
        key = (tuple(la), hard)
        uniq_paths.add(key)
        key2 = (tuple(lb), hard)
        uniq_paths.add(key2)
        buf.append((f"L {lab} {len(la)} " + " ".join(map(str, la))
                    + f" {len(lb)} " + " ".join(map(str, lb))
                    + (" h" if hard else " nh") + "\n").encode())
    buf.append(b"Q\n")

    # Rough check count for the log.
    import math
    bylen = {}
    for _, d in specs:
        bylen.setdefault(len(d), 0)
        bylen[len(d)] += 1
    pairs = sum(math.comb(c, 2) for c in bylen.values()) if not args.all_len else math.comb(len(specs), 2)
    total = pairs * len(passes) * len(accounts) * len(leaves)
    print(f"digest pieces={len(specs)} passes={len(passes)} accounts={len(accounts)} "
          f"leafcases={len(leaves)} same_len_pairs={pairs:,} est script checks={total:,}", flush=True)
    if args.list_only:
        print("list-only")
        return 0

    env = dict(os.environ)
    if args.all_len:
        env["ENGINE3_ALLLEN"] = "1"
    t0 = time.time()
    proc = subprocess.run([os.path.join(HERE, "engine3")], input=b"".join(buf),
                          stdout=subprocess.PIPE, cwd=HERE, env=env)
    out = proc.stdout.decode(errors="replace")
    sys.stderr.write(proc.stderr.decode(errors="replace") if proc.stderr else "")
    print(out.strip())
    print(f"elapsed {time.time() - t0:.1f}s")
    return 0 if out.lstrip().startswith("MATCH") else 1


if __name__ == "__main__":
    raise SystemExit(main())
