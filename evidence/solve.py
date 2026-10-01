#!/usr/bin/env python3
"""Search driver for the Genesis block wallet puzzle.

Confirmed pipeline (from the author's own OP_RETURN answers):
  1. digest_input = a contiguous piece of the Genesis block, exactly as a
     standard tool shows it, copy-pasted (block 968601, author).
  2. entropy = SHA256(digest_input)[0:16]                  (block 968343)
  3. words   = BIP39(entropy) -> 12 words                 (block 966576)
  4. seed    = PBKDF2-HMAC-SHA512(words, "mnemonic" + passphrase)
  5. path    = m/48'/0'/ACCOUNT'/2'/<leaf pair>            (block 964496)
  6. script  = OP_2 <pub1> <pub2> OP_2 OP_CHECKMULTISIG
  7. accept only on SHA256(script) == 4dae67a9...b7964833

The open axes are the exact digest_input byte range, the passphrase (a name,
format unknown), the BIP48 account number, and the two leaf indices.

This driver never spends or broadcasts anything.
"""
import argparse, hashlib, json, os, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "engine")
TARGET = "4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833"
GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

# The 285-byte Genesis block, verified byte-for-byte against
# https://blockstream.info/api/block/000000000019d668.../raw
GENESIS_RAW = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3ed"
    "fd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac"
    "2b7c01010000000100000000000000000000000000000000000000000000000000000000000000"
    "00ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f3230303920436861"
    "6e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f7220"
    "62616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6"
    "a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a"
    "4c702b6bf11d5fac00000000")
assert len(GENESIS_RAW) == 285, len(GENESIS_RAW)


# --------------------------------------------------------------- genesis views
def genesis_views():
    """Named byte ranges of the Genesis block, plus how tools render them."""
    raw = GENESIS_RAW
    header, tx = raw[:80], raw[81:]  # skip the 1-byte tx count
    ss_len = tx[41]
    scriptsig = tx[42:42 + ss_len]
    text = scriptsig[8:]
    # After the scriptSig comes the 4-byte sequence, then the first output.
    out_start = 42 + ss_len + 4
    value = tx[out_start + 1:out_start + 9]
    spk_len = tx[out_start + 9]
    pubkey = tx[out_start + 10:out_start + 10 + spk_len - 2]  # drop push op + OP_CHECKSIG
    f = {
        "raw_block": raw,
        "raw_header": header,
        "raw_tx": tx,
        "raw_scriptsig": scriptsig,
        "coinbase_text": text,
        "headline": text[22:],
        "merkle": header[36:68],
        "time": header[68:72],
        "bits": header[72:76],
        "nonce": header[76:80],
        "block_hash": bytes.fromhex(GENESIS),
        "output_value": value,
        "coinbase_pubkey": pubkey,
        "pubkey_x": pubkey[1:33],
        "pubkey_y": pubkey[33:65],
        "times_full": b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
        "date": b"03/Jan/2009",
    }
    return f


def representations(f):
    """How a standard tool might render each field, as the author copy-pasted it."""
    reps = {}
    for name, val in f.items():
        if not val:
            continue
        reps[f"{name}:raw"] = val
        reps[f"{name}:hex"] = val.hex().encode()
        reps[f"{name}:HEX"] = val.hex().upper().encode()
        reps[f"{name}:0xhex"] = ("0x" + val.hex()).encode()
        reps[f"{name}:hexsp"] = " ".join(val.hex()[i:i + 2] for i in range(0, len(val.hex()), 2)).encode()
        if all(32 <= c < 127 or c in (9, 10, 13) for c in val):
            reps[f"{name}:txt"] = val
            reps[f"{name}:txt_nl"] = val + b"\n"
            reps[f"{name}:txt_crlf"] = val + b"\r\n"
            reps[f"{name}:lower"] = val.lower()
            reps[f"{name}:upper"] = val.upper()
    return reps


GENESIS_HASH_DISPLAY = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
GENESIS_NEXT_HASH = "0000000000000000000297b4e50f89716e3b1f24f7c8fd4997f62ee1eeaf782b3"
GENESIS_CHAINWORK = "0000000000000000000000000000000000000000000100010001"


def jq_fields():
    """Exactly what `bitcoin-cli getblock <genesis> 1 | jq -r .<field>` prints.

    The author's toolchain names `jq`, and getblock's JSON is the natural thing to
    feed it. These are the strings such a pipeline would actually hash, so they
    are a first-class digest source rather than a re-encoding of some field.
    """
    f = genesis_views()
    return {
        "jq.hash": GENESIS_HASH_DISPLAY,
        "jq.versionHex": "00000001",
        "jq.merkleroot": f["merkle"][::-1].hex(),
        "jq.time": str(int.from_bytes(f["time"], "little")),
        "jq.bits": str(int.from_bytes(f["bits"], "little")),
        "jq.nonce": str(int.from_bytes(f["nonce"], "little")),
        "jq.difficulty": "1",
        "jq.chainwork": GENESIS_CHAINWORK,
        "jq.previousblockhash": "00" * 32,
        "jq.nextblockhash": GENESIS_NEXT_HASH,
        "jq.nTx": "1",
        "jq.size": str(len(GENESIS_RAW)),
        "jq.weight": "1140",
        "jq.height": "0",
        "jq.version": "1",
        "jq.merkleroot_up": f["merkle"][::-1].hex().upper(),
        "jq.hash_up": GENESIS_HASH_DISPLAY.upper(),
    }


def contiguous_pieces(data: bytes, minlen=1, maxlen=None):
    """Every contiguous byte range of `data` (the author's stated shape)."""
    n = len(data)
    maxlen = maxlen or n
    for i in range(n):
        for j in range(i + minlen, min(n, i + maxlen) + 1):
            yield data[i:j]


def digest_candidates(data: bytes, mode: str, minlen: int, maxlen):
    """Yield (label, bytes) digest-input candidates for one rendered field.

    mode "full"     - every contiguous range (the brute force the author expects)
    mode "semantic" - only the ranges a human would actually select with `cut`:
                      whole field, and every 8/16/32/64-char aligned window
    mode "whole"    - the entire field, no slicing
    """
    if mode == "whole":
        yield "whole", data
        return
    if mode == "full":
        yield from ((f"c{i}_{j}", data[i:j]) for i, j in _ranges(len(data), minlen, maxlen))
        return
    n = len(data)
    yield "whole", data
    for width in (8, 16, 32, 64, 128):
        for start in range(0, n - width + 1):
            yield f"w{width}_{start}", data[start:start + width]


def _ranges(n: int, minlen: int, maxlen):
    maxlen = maxlen or n
    for i in range(n):
        for j in range(i + minlen, min(n, i + maxlen) + 1):
            yield i, j


# ------------------------------------------------------------------ candidate sets
def passphrase_set(kind):
    """Passphrase is confirmed to be 'a name'. Formatting is left to brute force."""
    base = [
        "Hal Finney", "hal finney", "HAL FINNEY", "HalFinney", "halfinney",
        "Finney", "finney", "Hal", "hal", "Harold Finney",
        "Harold Thomas Finney", "Harold Thomas Finney II", "Harold T. Finney",
        "Harold Thomas Finney Jr", "Harold Thomas Finney Jr.",
        "Satoshi Nakamoto", "satoshi nakamoto", "SATOSHI NAKAMOTO", "SatoshiNakamoto",
        "satoshinakamoto", "Satoshi", "satoshi", "Nakamoto", "nakamoto",
    ]
    if kind == "basic":
        return base
    out = []
    for name in base:
        for sep in ("", " ", "-", "_", "."):
            s = name.replace(" ", sep)
            for v in (s, s.lower(), s.upper(), s.title()):
                if v not in out:
                    out.append(v)
    return out


def account_set(f, max_small=64, mode="basic"):
    """genesis_data as the BIP48 account number. Hardened index must be < 2^31.

    mode "prune" keeps only the values a human would plausibly pick from the
    Genesis block, which is what the author means by "some Genesis-block data".
    mode "all" additionally walks 4-byte windows and digest-derived values.
    """
    if mode == "prune":
        vals = {i: "small" for i in range(6)}
        vals.update({
            2009: "year", 1231006505: "time", 2083236893: "nonce",
            486604799: "bits", 47: "headline_len", 69: "text_len",
            77: "scriptsig_len", 80: "header_len", 160: "header_hex_len",
            285: "block_len", 570: "block_hex_len", 204: "tx_len",
            1032009: "date_mdy", 3012009: "date_dmy", 20090103: "date_ymd",
        })
        return vals

    vals = {i: "small" for i in range(max_small + 1)}
    vals.update({
        2009: "year", 1231006505: "time", 2083236893: "nonce", 486604799: "bits",
        1032009: "date_mdy", 3012009: "date_dmy", 20090103: "date_ymd",
        47: "headline_len", 69: "text_len", 77: "scriptsig_len",
    })
    for name, data in f.items():
        vals.setdefault(len(data), f"{name}_len")
        for endian in ("big", "little"):
            whole = int.from_bytes(data, endian)
            vals.setdefault(whole % (2 ** 31), f"{name}_{endian}_mod2^31")
            for off in range(0, len(data) - 3, 4):
                z = int.from_bytes(data[off:off + 4], endian)
                if z < 2 ** 31:
                    vals.setdefault(z, f"{name}+{off}_{endian}")
        # digest-derived accounts
        for dname, dig in (("md5", hashlib.md5(data).digest()),
                           ("sha256", hashlib.sha256(data).digest())):
            for endian in ("big", "little"):
                vals.setdefault(int.from_bytes(dig, endian) % (2 ** 31), f"{name}.{dname}_{endian}")
    return vals


# Leaf layouts. The engine derives each DISTINCT leaf path once per account and
# then compares cached pubkeys, so adding pair layouts is nearly free.
def _leaf_label(p):
    return "/".join(str(i) for i in p)


LEAF_SETS = [(_leaf_label(a) + " vs " + _leaf_label(b), a, b) for a, b in [
    ([0, 0], [0, 1]),
    ([0, 0], [1, 0]),
    ([0, 0], [0, 2]),
    ([0, 1], [0, 2]),
    ([1, 0], [1, 1]),
    ([0, 0], [2, 0]),
]]

# The two layouts a standard BIP48 multisig wallet would use, plus the degenerate
# "both keys are the account node itself" case. That last one is only meaningful
# with two independent roots, but including it costs no extra derivation.
LEAF_SETS_STD = [(_leaf_label(a) + " vs " + _leaf_label(b), a, b) for a, b in [
    ([0, 0], [0, 1]),
    ([0, 0], [1, 0]),
    ([], []),
]]


# ------------------------------------------------------------------ driver
def run(passes, accounts, leaves, digest_specs, verbose=True, indep=False, env_extra=None):
    """digest_specs: list of (label, bytes). Streams a job to the C engine."""
    buf = []
    for label, data in digest_specs:
        buf.append(f"D {len(data)} {label.replace(' ', '_')}\n".encode())
        buf.append(data.hex().encode() + b"\n")
    for p in passes:
        buf.append(f"P {p}\n".encode())
    for a, lab in accounts:
        buf.append(f"A {a} {lab.replace(' ', '_')}\n".encode())
    for lab, la, lb in leaves:
        # Labels must not contain spaces: the engine parses positionally.
        buf.append((f"L {lab.replace(' ', '_')} {len(la)} " + " ".join(map(str, la))
                    + f" {len(lb)} " + " ".join(map(str, lb)) + "\n").encode())
    buf.append(b"Q\n")
    env = dict(os.environ)
    if indep:
        env["ENGINE_INDEP"] = "1"
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run([ENGINE], input=b"".join(buf), capture_output=True,
                          cwd=HERE, env=env)
    out = proc.stdout.decode(errors="replace")
    if verbose:
        sys.stderr.write(proc.stderr.decode(errors="replace"))
    if not out.strip():
        out = f"ENGINE_NO_OUTPUT rc={proc.returncode} err={proc.stderr.decode(errors='replace')[:300]}"
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fields", default="all")
    ap.add_argument("--passphrases", default="basic")
    ap.add_argument("--accounts", default="prune", choices=("prune", "all"))
    ap.add_argument("--digest-mode", default="full",
                    choices=("full", "semantic", "whole"),
                    help="how to pick ranges within each rendered field")
    ap.add_argument("--minlen", type=int, default=1)
    ap.add_argument("--maxlen", type=int, default=0, help="0 = whole field")
    ap.add_argument("--indep", action="store_true",
                    help="independent-root model: two seeds, same BIP48 path")
    ap.add_argument("--account-only", default="",
                    help="comma-separated account numbers, overrides --accounts")
    ap.add_argument("--chunk-start", type=int, default=0)
    ap.add_argument("--chunk-size", type=int, default=0, help="0 = one chunk")
    ap.add_argument("--leaves", default="std",
                    choices=("std", "all"),
                    help="std = the two standard cosigner layouts only")
    ap.add_argument("--list-only", action="store_true")
    args = ap.parse_args()

    f = genesis_views()
    reps = representations(f)
    # The author's toolchain names jq, so getblock's JSON fields are their own
    # digest family, with and without the trailing newline a shell pipeline or a
    # copy-paste would add.
    for k, v in jq_fields().items():
        reps[k] = v.encode()
        reps[k + ":nl"] = (v + "\n").encode()
    fields = list(reps) if args.fields == "all" else args.fields.split(",")
    if args.fields == "jq":
        fields = list(jq_fields().keys())
        for k in list(fields):
            fields.append(k + ":nl")
    passes = passphrase_set(args.passphrases)
    if args.account_only:
        accounts = [(int(x), "explicit") for x in args.account_only.split(",") if x != ""]
    else:
        accounts = sorted(account_set(f, 64, args.accounts).items())
    maxlen = args.maxlen or None
    leaves = LEAF_SETS_STD if args.leaves == "std" else LEAF_SETS

    specs = []
    for name in fields:
        for sub, piece in digest_candidates(reps[name], args.digest_mode,
                                            args.minlen, maxlen):
            specs.append((f"{name}#{sub}", piece))

    # Distinct pieces only; the same bytes under two labels add no coverage.
    seen, uniq = set(), []
    for label, d in specs:
        if d in seen:
            continue
        seen.add(d)
        uniq.append((label, d))
    specs = uniq

    # Chunking so a crash or a host restart costs at most one chunk, and so the
    # digest axis can be walked in pieces with a durable record of what is done.
    if args.chunk_size:
        specs = specs[args.chunk_start:args.chunk_start + args.chunk_size]

    total = len(specs) * len(passes) * len(accounts) * len(leaves)
    if args.indep:
        total = len(specs) * len(accounts) * len(leaves) * (len(passes) * (len(passes) - 1) // 2)
    print(f"digest pieces={len(specs)} passes={len(passes)} accounts={len(accounts)} "
          f"leafsets={len(leaves)} indep={args.indep}  total script-hash checks={total:,}",
          flush=True)
    if args.list_only:
        for label, d in specs[:40]:
            print(f"  {label:32} {d[:70]!r}")
        print(f"  ... {len(specs)} total")
        return 0

    t0 = time.time()
    out = run(passes, accounts, leaves, specs, indep=args.indep)
    print(out.strip())
    print(f"elapsed {time.time() - t0:.1f}s")
    return 0 if out.lstrip().startswith("MATCH") else 1


if __name__ == "__main__":
    raise SystemExit(main())
