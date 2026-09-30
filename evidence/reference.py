#!/usr/bin/env python3
"""Reference BIP39/BIP32/BIP48 implementation, validated against BIP test vectors.

This is the correctness oracle for the C engine in engine.c. If the two agree on
random inputs, the fast sweep is trustworthy.
"""
import hashlib, hmac, json, sys, urllib.request

# secp256k1 has two distinct moduli that are easy to confuse:
#   P  field prime  - all point arithmetic is mod P
#   N  group order  - BIP32 child key addition is mod N
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


# ---------------------------------------------------------------- secp256k1
def inv(a):
    """Modular inverse in the secp256k1 FIELD, i.e. mod P (not the group order)."""
    return pow(a, P - 2, P)


def padd(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * inv(2 * p[1]) % P
    else:
        lam = (q[1] - p[1]) * inv(q[0] - p[0]) % P
    x = (lam * lam - p[0] - q[0]) % P
    return (x, (lam * (p[0] - x) - p[1]) % P)


def pmul(k, p=G):
    r, a = None, p
    while k:
        if k & 1:
            r = padd(r, a)
        a = padd(a, a)
        k >>= 1
    return r


def ser_p(p, compressed=True):
    x, y = p
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# ------------------------------------------------------------------- BIP32
def master(seed):
    z = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(z[:32], "big"), z[32:]


def pub(priv):
    return ser_p(pmul(priv))


def ckd(node, index):
    priv, chain = node
    if index >= 2 ** 31:
        data = b"\x00" + priv.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = pub(priv) + index.to_bytes(4, "big")
    z = hmac.new(chain, data, hashlib.sha512).digest()
    k = (int.from_bytes(z[:32], "big") + priv) % N
    if k == 0 or int.from_bytes(z[:32], "big") >= N:
        raise ValueError("invalid")
    return k, z[32:]


def derive(node, path):
    for i in path:
        node = ckd(node, i)
    return node


def fingerprint(node):
    return hashlib.new("ripemd160", hashlib.sha256(pub(node[0])).digest()).digest()[:4]


# ------------------------------------------------------------------- BIP39
def wordlist():
    url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read().decode().split()


def entropy_to_mnemonic(ent, wl):
    """BIP39: entropy bits, then CS = first len(ent)//4 bits of SHA256(ent)."""
    ent_bits = len(ent) * 8
    cs_bits = len(ent) // 4
    total = ent_bits + cs_bits
    value = (int.from_bytes(ent, "big") << cs_bits) | (hashlib.sha256(ent).digest()[0] >> (8 - cs_bits))
    out = []
    for i in range(total // 11):
        idx = (value >> (total - 11 * (i + 1))) & 0x7FF
        out.append(wl[idx])
    return " ".join(out)


def mnemonic_to_seed(mn, passphrase=""):
    return hashlib.pbkdf2_hmac("sha512", mn.encode(), ("mnemonic" + passphrase).encode(), 2048)


# ---------------------------------------------------------------- genesis
GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
RAW = ("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b2"
       "7ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c01010000000100000000"
       "0000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d010445"
       "5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f6620736"
       "5636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe554"
       "8271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df"
       "7ba0bdd8d578a4c702b6bf11d5fac00000000")


def main():
    wl = wordlist()
    assert len(wl) == 2048
    ok = []
    # Authoritative cross-check: BitcoinJS/bip32 fixtures, full ladder
    # m -> m/0' -> m/0'/1 -> ... including non-hardened steps. This is the
    # check that catches a wrong secp256k1 group order in the child-key add.
    import json
    seed_hex = "000102030405060708090a0b0c0d0e0f"
    url = "https://raw.githubusercontent.com/bitcoinjs/bip32/master/test/fixtures/index.json"
    with urllib.request.urlopen(url, timeout=60) as r:
        fx = json.load(r)["valid"]
    ent = next(e for e in fx if e["master"]["seed"] == seed_hex)
    m = master(bytes.fromhex(seed_hex))
    mm = ent["master"]
    assert m[0].to_bytes(32, "big").hex() == mm["privKey"], "master priv"
    assert pub(m[0]).hex() == mm["pubKey"], "master pub"
    assert m[1].hex() == mm["chainCode"], "master chaincode"
    nodes = {"m": m}
    for c in ent["children"]:
        parent_key = c["path"].rsplit("/", 1)[0]
        node = ckd(nodes[parent_key], c["m"] + (0x80000000 if c.get("hardened") else 0))
        nodes[c["path"]] = node
        assert node[0].to_bytes(32, "big").hex() == c["privKey"], c["path"] + " priv"
        assert pub(node[0]).hex() == c["pubKey"], c["path"] + " pub"
        assert node[1].hex() == c["chainCode"], c["path"] + " cc"
        # The fixture's `fingerprint`/`identifier` fields are not consistently
        # parent-vs-self across rows, so they are not asserted directly. The
        # xpub parent-fingerprint field IS asserted below by byte comparison
        # of the fully serialized xpub against BitcoinJS.
    ok.append(f"BitcoinJS bip32 fixtures: master + {len(ent['children'])} levels (priv/pub/cc/fp)")

    # P (field prime) and N (group order) must never be conflated.
    assert N == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    assert P == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    assert (G[1] ** 2 - (G[0] ** 3 + 7)) % P == 0, "G must satisfy y^2 = x^3+7 mod P"
    ok.append("secp256k1: N != P, G on curve over P")

    # Strongest check: serialize real xpubs and require byte equality with
    # BitcoinJS. Exercises depth, parent fingerprint, child number, chain code,
    # public key and the double-SHA256 checksum in one shot.
    _B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def _b58enc(bs: bytes) -> str:
        n = int.from_bytes(bs, "big")
        out = ""
        while n:
            n, r = divmod(n, 58)
            out = _B58[r] + out
        for c in bs:
            if c == 0:
                out = "1" + out
            else:
                break
        return out

    def _xpub(node, depth, parent_fp, child_num) -> str:
        body = bytes.fromhex("0488b21e") + bytes([depth]) + parent_fp
        body += child_num.to_bytes(4, "big") + node[1] + pub(node[0])
        return _b58enc(body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4])

    assert _xpub(m, 0, b"\x00" * 4, 0) == ent["master"]["base58"], "master xpub"
    for c in ent["children"]:
        parent_key = c["path"].rsplit("/", 1)[0]
        idx = c["m"] + (0x80000000 if c.get("hardened") else 0)
        node = nodes[c["path"]]
        pfp = hashlib.new("ripemd160", hashlib.sha256(pub(nodes[parent_key][0])).digest()).digest()[:4]
        assert _xpub(node, c["depth"], pfp, idx) == c["base58"], c["path"] + " xpub"
    ok.append(f"BitcoinJS xpubs byte-identical: master + {len(ent['children'])} nodes")

    # BIP39: all official English vectors from the trezor/python-mnemonic
    # corpus (same fixtures Ian Coleman's tool ships), not a hand-picked subset.
    with urllib.request.urlopen("https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json",
                                timeout=60) as r:
        v39 = json.load(r)["english"]
    for row in v39:
        ent, mn = row[0], row[1]
        got = entropy_to_mnemonic(bytes.fromhex(ent), wl)
        assert got == mn, f"{ent}: {got} != {mn}"
    ok.append(f"BIP39 official English vectors: {len(v39)}/{len(v39)}")

    # PBKDF2 passphrase seed, official vector.
    s = mnemonic_to_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "TREZOR")
    assert s.hex() == "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", s.hex()
    ok.append("BIP39 PBKDF2 seed with passphrase (TREZOR vector)")

    # End-to-end BIP48 sanity: m/48'/0'/0'/2' must derive deterministically, and
    # the account node must have a stable fingerprint. Exact xpub bytes for this
    # path are not asserted from memory; BIP32 correctness is already proven
    # above by byte-identical xpubs against BitcoinJS.
    m2 = master(mnemonic_to_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
    acct = derive(m2, [0x80000030, 0x80000000, 0x80000000, 0x80000002])
    leaf0 = derive(acct, [0, 0])
    assert fingerprint(acct) == hashlib.new("ripemd160", hashlib.sha256(pub(acct[0])).digest()).digest()[:4]
    assert pub(leaf0[0]) != pub(derive(acct, [0, 1])[0]), "distinct leaves"
    ok.append(f"BIP48 m/48'/0'/0'/2' derives; account fingerprint {fingerprint(acct).hex()}")

    print("REFERENCE SELFTEST OK")
    for o in ok:
        print("  -", o)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
