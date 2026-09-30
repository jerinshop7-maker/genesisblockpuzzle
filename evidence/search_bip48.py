#!/usr/bin/env python3
"""Reproducible, bounded BIP39/BIP32/BIP48 escrow search.

The script deliberately separates the search axes. It never spends or broadcasts.
"""
import argparse, hashlib, hmac, itertools, urllib.request
from coincurve import PrivateKey
from mnemonic import Mnemonic

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TARGET = bytes.fromhex("4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833")
GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
RAW_URL = "https://blockstream.info/api/block/" + GENESIS + "/raw"

def ripemd128(data):
    """Small self-contained RIPEMD-128 implementation (little-endian)."""
    r1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8, 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2]
    r2 = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2, 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14]
    s1 = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12, 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12]
    s2 = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11, 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8]
    k1 = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc]
    k2 = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0]
    def rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff
    def f(j, x, y, z):
        return [x ^ y ^ z, (x & y) | (~x & z), (x | ~y) ^ z, (x & z) | (y & ~z)][j] & 0xffffffff
    bitlen = len(data) * 8
    data += b"\x80" + b"\0" * ((55 - len(data)) % 64) + bitlen.to_bytes(8, "little")
    h0,h1,h2,h3 = 0x67452301,0xefcdab89,0x98badcfe,0x10325476
    for off in range(0, len(data), 64):
        x = [int.from_bytes(data[off+i:off+i+4], "little") for i in range(0,64,4)]
        a,b,c,d = h0,h1,h2,h3; aa,bb,cc,dd = a,b,c,d
        for j in range(64):
            q=j//16; a=rol((a+f(q,b,c,d)+x[r1[j]]+k1[q])&0xffffffff,s1[j]); a,b,c,d=d,a,b,c
            qr=j//16; aa=rol((aa+f(3-qr,bb,cc,dd)+x[r2[j]]+k2[qr])&0xffffffff,s2[j]); aa,bb,cc,dd=dd,aa,bb,cc
        t=(h1+c+dd)&0xffffffff; h1=(h2+d+aa)&0xffffffff; h2=(h3+a+bb)&0xffffffff; h3=(h0+b+cc)&0xffffffff; h0=t
    return b"".join(x.to_bytes(4,"little") for x in (h0,h1,h2,h3))

def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()

def master(seed):
    z = hmac_sha512(b"Bitcoin seed", seed)
    return int.from_bytes(z[:32], "big"), z[32:]

def pub(priv):
    return PrivateKey(priv.to_bytes(32, "big")).public_key.format(compressed=True)

def pub_uncompressed(priv):
    return PrivateKey(priv.to_bytes(32, "big")).public_key.format(compressed=False)

def child(node, index):
    priv, chain = node
    data = b"\0" + priv.to_bytes(32, "big") if index >= 2**31 else pub(priv)
    z = hmac_sha512(chain, data + index.to_bytes(4, "big"))
    k = (int.from_bytes(z[:32], "big") + priv) % N
    if int.from_bytes(z[:32], "big") >= N or k == 0:
        raise ValueError("invalid BIP32 child")
    return k, z[32:]

def derive(node, path):
    for value, hardened in path:
        node = child(node, value + (2**31 if hardened else 0))
    return node

def genesis_fields():
    raw = urllib.request.urlopen(RAW_URL, timeout=30).read()
    header, tx = raw[:80], raw[81:]  # skip the one-byte tx-count
    ss_len = tx[41]
    scriptsig = tx[42:42 + ss_len]
    text = scriptsig[8:]
    out_start = 42 + ss_len + 4  # sequence after the coinbase input
    value = tx[out_start + 1:out_start + 9]
    pk_len = tx[out_start + 9]
    pubkey = tx[out_start + 11:out_start + 11 + pk_len - 2]  # skip push opcode and CHECKSIG
    return raw, {
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
        "txid": bytes.fromhex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
        "times_full": b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
        "times_date_headline": b"03/Jan/2009 Chancellor on brink of second bailout for banks",
        "date": b"03/Jan/2009",
    }

def add_representations(fields):
    """Return byte-exact candidates including raw bytes and text encodings."""
    out = dict(fields)
    for name, value in list(fields.items()):
        if value:
            out[name + "_hexascii"] = value.hex().encode()
            out[name + "_binary_ascii"] = b"".join(f"{byte:08b}".encode() for byte in value)
            out[name + "_decimal_big"] = str(int.from_bytes(value, "big")).encode()
            out[name + "_decimal_little"] = str(int.from_bytes(value, "little")).encode()
            out[name + "_bytes_decimal"] = b"".join(str(byte).encode() for byte in value)
            out[name + "_bytes_decimal_spaces"] = b" ".join(str(byte).encode() for byte in value)
            out[name + "_bytes_decimal_commas"] = b",".join(str(byte).encode() for byte in value)
        if value and all(c in b"\t\n\r " + bytes(range(33, 127)) for c in value):
            out[name + "_nl"] = value + b"\n"
            out[name + "_crlf"] = value + b"\r\n"
            out[name + "_lower"] = value.lower()
            out[name + "_upper"] = value.upper()
    return out

def entropy_candidates(fields, field_name, digest):
    if field_name == "all":
        return sum((entropy_candidates(fields, name, digest) for name in fields), [])
    if "," in field_name:
        return sum((entropy_candidates(fields, name.strip(), digest) for name in field_name.split(",") if name.strip()), [])
    x = fields[field_name]
    if digest == "md5": return [(field_name, hashlib.md5(x).digest())]
    if digest == "md4": return [(field_name, hashlib.new("md4", x).digest())]
    if digest == "ripemd128": return [(field_name, ripemd128(x))]
    if digest == "ripemd160-first16": return [(field_name, hashlib.new("ripemd160", x).digest()[:16])]
    if digest == "ripemd160-last16": return [(field_name, hashlib.new("ripemd160", x).digest()[-16:])]
    z = hashlib.sha256(x).digest()
    if digest == "sha256-first16": return [(field_name, z[:16])]
    if digest == "sha256-last16": return [(field_name, z[-16:])]
    raise ValueError(digest)

def passphrases(kind, extra=None):
    base = ["Hal Finney", "hal finney", "HAL FINNEY", "HalFinney", "halfinney",
            "Finney", "finney", "Hal", "hal", "Harold Finney",
            "Harold Thomas Finney", "Harold Thomas Finney II", "Harold T. Finney",
            "Harold Thomas Finney Jr", "Harold Thomas Finney Jr.",
            "Harold Thomas Finney, Jr.", "Hal Finney Jr", "Hal Finney Jr.",
            "Hal Thomas Finney", "Thomas Finney", "Thomas", "Harold",
            "H Finney", "H. Finney", "H. T. Finney", "Hal T Finney", "Hal T. Finney"]
    # Secondary clue candidate: the live mempool message links a clip whose
    # title names Leslie Nielsen. Keep it explicit and separate from Hal
    # Finney rather than silently treating the meme as an answer.
    base += ["Leslie Nielsen", "leslie nielsen", "LESLIE NIELSEN", "LeslieNielsen", "leslienielsen"]
    base += ["Satoshi Nakamoto", "satoshi nakamoto", "SATOSHI NAKAMOTO", "SatoshiNakamoto", "satoshinakamoto",
             "Satoshi", "satoshi", "Nakamoto", "nakamoto"]
    if kind == "basic":
        out = base[:]
    else:
        out = []
        for name in base:
            for sep in ("", " ", "-", "_"):
                s = name.replace(" ", sep)
                for v in (s, s.lower(), s.upper(), s.title()):
                    if v not in out: out.append(v)
    if extra and extra not in out: out.append(extra)
    return out

def suffix_pairs(kind):
    if kind == "direct":
        return [((), ())]
    if kind == "one":
        return [(((0, False),), ((1, False),)), (((0, True),), ((1, True),)),
                (((0, False),), ((1, True),)), (((0, True),), ((1, False),))]
    if kind == "standard":
        # BIP48 address leaves: external branch 0, address indices 0/1;
        # also the common single-seed cosigner-branch interpretation.
        return [
            (((0, False), (0, False)), ((0, False), (1, False))),
            (((0, True), (0, True)), ((0, True), (1, True))),
            (((0, False), (0, False)), ((1, False), (0, False))),
            (((0, True), (0, True)), ((1, True), (0, True))),
            (((0, False), (0, True)), ((0, False), (1, True))),
            (((0, True), (0, False)), ((1, True), (0, False))),
        ]
    if kind == "independent":
        # In a normal multisig wallet each cosigner uses the same BIP48
        # account/change/address path on its own root.
        return [
            (((0, False), (0, False)), ((0, False), (0, False))),
            (((0, True), (0, True)), ((0, True), (0, True))),
            (((0, False), (1, False)), ((0, False), (1, False))),
        ]
    # Cosigner leaves beneath the standard BIP48 script-type node.
    out = []
    seqs = []
    for length in (1, 2, 3):
        for vals in itertools.product((0, 1), repeat=length):
            for hard in itertools.product((False, True), repeat=length):
                seqs.append(tuple(zip(vals, hard)))
    for a, b in itertools.permutations(seqs, 2):
        out.append((a, b))
    return list(dict.fromkeys(out))

def account_values(fields, max_small, windows=True):
    values = {i: "small" for i in range(max_small + 1)}
    for name, x in fields.items() if windows else []:
        sources = [(name, x), (name + "_md5", hashlib.md5(x).digest()),
                   (name + "_sha256", hashlib.sha256(x).digest())]
        for source, data in sources:
            for endian in ("big", "little"):
                whole = int.from_bytes(data, endian)
                for modulus, label in ((2**31, "mod2^31"), (2**31 - 1, "mod2^31-1")):
                    values.setdefault(whole % modulus, f"{source}_{endian}_{label}")
            # Include every aligned and boundary 4-byte window. This covers
            # the natural uint32 account interpretations without pretending a
            # full 32-byte field itself is a legal BIP32 index.
            offsets = range(0, len(data) - 3, 4)
            for offset in offsets:
                y = data[offset:offset + 4]
                for endian in ("big", "little"):
                    z = int.from_bytes(y, endian)
                    if z < 2**31:
                        values.setdefault(z, f"{source}_offset{offset}_{endian}")
                    values.setdefault(z & 0x7fffffff, f"{source}_offset{offset}_{endian}_low31")
    values.update({47: "headline_len", 69: "text_len", 77: "scriptsig_len",
                   2009: "year", 1231006505: "time", 2083236893: "nonce",
                   486604799: "bits", 1032009: "date_mmddyyyy",
                   3012009: "date_ddmmyyyy", 20090103: "date_yyyymmdd",
                   1032009: "date_mdy_digits", 3012009: "date_dmy_digits"})
    for name, data in fields.items():
        values.setdefault(len(data), f"{name}_len")
    return values

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--field", default="headline")
    ap.add_argument("--digest", choices=("md4", "md5", "ripemd128", "ripemd160-first16", "ripemd160-last16", "sha256-first16", "sha256-last16"), default="md5")
    ap.add_argument("--names", choices=("basic", "formatted"), default="basic")
    ap.add_argument("--extra-passphrase")
    ap.add_argument("--passphrase")
    ap.add_argument("--suffix", choices=("direct", "one", "standard", "independent", "all"), default="one")
    ap.add_argument("--account-max", type=int, default=0)
    ap.add_argument("--no-account-windows", action="store_true")
    ap.add_argument("--order", choices=("both", "sorted"), default="both")
    ap.add_argument("--encoding", choices=("compressed", "uncompressed", "both"), default="compressed")
    ap.add_argument("--independent", action="store_true",
                    help="derive the two public keys from separate BIP39 passphrase roots")
    ap.add_argument("--base-hardening", choices=("standard", "all"), default="standard")
    args = ap.parse_args()
    _, fields = genesis_fields()
    fields = add_representations(fields)
    accounts = account_values(fields, args.account_max, not args.no_account_windows)
    pps = [args.passphrase] if args.passphrase else passphrases(args.names, args.extra_passphrase)
    suffixes = suffix_pairs(args.suffix)
    candidates = entropy_candidates(fields, args.field, args.digest)
    print(f"field={args.field} digest={args.digest} entropy={len(candidates)} passphrases={len(pps)} accounts={len(accounts)} suffix_pairs={len(suffixes)} independent={args.independent}", flush=True)
    mn = Mnemonic("english")
    checked = 0
    hardening = [(True, True, True, True)] if args.base_hardening == "standard" else list(itertools.product((False, True), repeat=4))
    for field, entropy in candidates:
        words = mn.to_mnemonic(entropy)
        roots = [(phrase, master(mn.to_seed(words, passphrase=phrase))) for phrase in pps]
        if args.independent:
            # Cache all leaf public keys once per (passphrase, account). The
            # pairwise passphrase sweep must not redo BIP32/secp256k1 work.
            leaves = {}
            for phrase, root in roots:
                for account in accounts:
                    for flags in hardening:
                        base = derive(root, tuple((value, flag) for value, flag in zip((48, 0, account, 2), flags)))
                        leaves[(phrase, account, flags)] = tuple((left, right, pub(derive(base, left)[0])) for left, right in suffixes)
            root_pairs = ((a, b) for a in roots for b in roots)
        else:
            root_pairs = ((a, a) for a in roots)
        for (phrase_a, root_a), (phrase_b, root_b) in root_pairs:
            for account, account_label in accounts.items():
                for flags in hardening:
                    if args.independent:
                        la = leaves[(phrase_a, account, flags)]; lb = leaves[(phrase_b, account, flags)]
                        leaf_pairs = ((x[2], y[2], x[0], y[0]) for x, y in zip(la, lb))
                    else:
                        base_a = derive(root_a, tuple((value, flag) for value, flag in zip((48, 0, account, 2), flags)))
                        leaf_pairs = ((pub(derive(base_a, left)[0]), pub(derive(base_a, right)[0]), left, right) for left, right in suffixes)
                    for p1, p2, left, right in leaf_pairs:
                        encodings = ("compressed", "uncompressed") if args.encoding == "both" else (args.encoding,)
                        for encoding in encodings:
                            q1, q2 = (p1, p2) if encoding == "compressed" else (pub_uncompressed(derive(root_a, left)[0]), pub_uncompressed(derive(root_b, right)[0]))
                            orders = ((q1, q2), (q2, q1)) if args.order == "both" else ((min(q1, q2), max(q1, q2)),)
                            for first, second in orders:
                                push1, push2 = bytes([len(first)]), bytes([len(second)])
                                script = b"\x52" + push1 + first + push2 + second + b"\x52\xae"
                                if hashlib.sha256(script).digest() == TARGET:
                                    print("MATCH", field, args.digest, entropy.hex(), words, repr(phrase_a), repr(phrase_b), account, account_label, left, right, encoding, first.hex(), second.hex(), flush=True)
                                    return 0
                                checked += 1
    print("NO_MATCH", checked, flush=True)
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
