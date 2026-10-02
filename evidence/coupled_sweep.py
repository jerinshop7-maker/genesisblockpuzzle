#!/usr/bin/env python3
"""Coupled sweep: test whether genesis_data and the digest input are the SAME field.

The author said two separate things that may point at one value:

  - "Yes, both keys use the same Genesis field" (block 963829)
  - "genesis_data = some Genesis-block data used as the BIP48 account number"
    (block 966409)
  - the digest input is "a contiguous piece of the genesis block, exactly as a
    standard tool shows it" (block 968601)

If the design reuses one field for both roles, then the BIP48 account number and
the hashed entropy come from the same bytes. That is a sharp, cheap test: for
each candidate field, only the account number that field implies is worth trying.

A BIP32 hardened index must be below 2^31, so genesis_data has to be a small
value. That rules out the 32-byte merkle root as the account while leaving it
available as a digest source, which is itself informative.

This runs the verified engine only; it never spends or broadcasts.
"""
import os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from solve import (ENGINE, GENESIS_RAW, genesis_views, jq_fields, passphrase_set,  # noqa: E402
                   LEAF_SETS_STD, run, representations)

# (label, digest-input bytes, candidate account numbers it could imply)
def coupled_cases():
    f = genesis_views()
    time_i = int.from_bytes(f["time"], "little")
    bits_i = int.from_bytes(f["bits"], "little")
    nonce_i = int.from_bytes(f["nonce"], "little")
    merkle = f["merkle"]
    cases = []

    def add(label, data, accts):
        for a in accts:
            cases.append((f"{label}#{a}", data, a))

    # --- the three 4-byte header fields, in every rendering a tool shows ---
    for name, raw, val in (("time", f["time"], time_i),
                           ("bits", f["bits"], bits_i),
                           ("nonce", f["nonce"], nonce_i)):
        accts = [val, val % (2 ** 31), val % 100000000]
        add(f"{name}.raw", raw, accts)
        add(f"{name}.hex", raw.hex().encode(), accts)
        add(f"{name}.HEX", raw.hex().upper().encode(), accts)
        add(f"{name}.dec", str(val).encode(), accts)
        add(f"{name}.dec_nl", (str(val) + "\n").encode(), accts)

    # --- merkle root: too large for a BIP32 index, but a fine digest source ---
    merkle_accts = [0, 1, 2, 2009, time_i, bits_i, nonce_i]
    add("merkle.hex", merkle.hex().encode(), merkle_accts)
    add("merkle.hexbe", merkle[::-1].hex().encode(), merkle_accts)
    add("merkle.raw", merkle, merkle_accts)

    # --- lengths and small derived values ---
    for label, val in (("len_block", len(GENESIS_RAW)), ("len_text", 69),
                       ("len_headline", 47), ("len_scriptsig", 77),
                       ("len_hex", len(GENESIS_RAW) * 2), ("year", 2009),
                       ("day_ordinal", 1032009), ("yyyymmdd", 20090103),
                       ("dmy", 3012009), ("mdy", 1032009)):
        add(f"{label}.dec", str(val).encode(), [val])
        add(f"{label}.hex", f"{val:x}".encode(), [val])

    # --- getblock JSON strings, with the account that string itself implies ---
    for k, v in jq_fields().items():
        try:
            implied = [int(v)]
        except ValueError:
            implied = [0, 1, 2, 2009, time_i, bits_i, nonce_i]
        implied = [x for x in implied if 0 <= x < 2 ** 31]
        add(f"jq.{k}", v.encode(), implied or [0])
        add(f"jq.{k}.nl", (v + "\n").encode(), implied or [0])

    # --- the Times text, where "length" is the obvious Genesis-derived account ---
    text = f["coinbase_text"]
    for label, data in (("text.txt", text), ("headline.txt", f["headline"])):
        add(f"{label}", data, [69, 47, 2009, 0, 1, 2])
        add(f"{label}.nl", data + b"\n", [69, 47, 2009, 0, 1, 2])

    # --- whole tool renderings paired with the obvious account ---
    add("block.hex", GENESIS_RAW.hex().encode(), [0, 1, 2, 2009, 285, 570, nonce_i, time_i])
    add("block.hex.nl", (GENESIS_RAW.hex() + "\n").encode(),
        [0, 1, 2, 2009, 285, 570, nonce_i, time_i])
    add("block.raw", GENESIS_RAW, [0, 1, 2, 2009, 285, nonce_i, time_i])
    return cases


def main():
    cases = coupled_cases()
    passes = passphrase_set("basic")
    # Each case keeps only its own account candidates, so build one job per case
    # to preserve the coupling. Group cases that share an account to cut the
    # number of engine invocations.
    by_acct = {}
    for label, data, acct in cases:
        by_acct.setdefault(acct, []).append((label, data))

    total_accounts = len(by_acct)
    print(f"coupled cases={len(cases)} distinct accounts={total_accounts} "
          f"passes={len(passes)} leafsets={len(LEAF_SETS_STD)}", flush=True)
    print(f"total script-hash checks="
          f"{len(cases) * len(passes) * len(LEAF_SETS_STD):,}", flush=True)

    t0 = time.time()
    checked = 0
    for acct, items in sorted(by_acct.items()):
        specs = items
        out = run(passes, [(acct, "coupled")], LEAF_SETS_STD, specs, verbose=False)
        if out.lstrip().startswith("MATCH"):
            print(out)
            print(f"ACCOUNT COUPLED TO DIGEST INPUT: {acct}")
            return 0
        for tok in out.split():
            if tok.startswith("checked="):
                checked += int(tok.split("=")[1])
        print(f"  acct {acct:>12}  digests={len(items):3}  "
              f"elapsed {time.time() - t0:7.1f}s", flush=True)

    print(f"NO_MATCH checked={checked} elapsed={time.time() - t0:.1f}s")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
