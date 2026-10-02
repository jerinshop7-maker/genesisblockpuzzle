# Verification log — 2026-09-30

This file records how the replacement crypto engine was proven correct, because
the previous engine in this repo was not.

## Bug 1: the previous engine conflated two different moduli

`evidence/search_bip48.py` defined a single constant:

```python
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

and used it for both secp256k1 roles. They are different numbers:

| Role | Constant |
|---|---|
| field prime `p` (point arithmetic, modular inverse) | `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F` |
| group order `n` (BIP32 child key addition) | `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` |

Only the group-order use was right. Consequences:

- All point arithmetic (`padd`, `pmul`) ran modulo the group order, so points
  were not on the curve and every derived public key was wrong.
- Hardened derivation looked plausible because it never needs the public key,
  which is why the bug hid for so long.
- Every "no match" reported by that script, and every interrupted sweep described
  in `search-log-2026-09-23.md` and `search-log-2026-09-25.md`, is void.

Sanity check that makes the distinction obvious: `G` satisfies
`y^2 = x^3 + 7 (mod p)` but **not** `(mod n)`. Verifying that one relation is
enough to catch a swapped constant.

## Bug 2: `entropy_to_mnemonic` computed the BIP39 checksum wrongly

The first implementation appended a full byte of hash instead of the top
`len(entropy)/4` bits, producing `abandon ... abandon` instead of
`abandon ... about`. Caught immediately by the official BIP39 vectors.

## How the replacement was pinned

`evidence/reference.py` is the correctness oracle. Its self-test asserts:

1. **BIP32 against BitcoinJS fixtures** — the full ladder
   `m -> m/0' -> m/0'/1 -> m/0'/1/2' -> m/0'/1/2'/2 -> m/0'/1/2'/2/1000000000`,
   comparing private key, public key, and chain code at every level. This mixes
   hardened and non-hardened steps, which is exactly what catches a wrong
   child-key addition modulus.
2. **Full xpub byte equality with BitcoinJS** — base58check serialization compared
   string-for-string for the master and all five children. This exercises depth,
   parent fingerprint, child number, chain code, public key, and the double-SHA256
   checksum simultaneously. All 6 match byte-for-byte.
3. **BIP39 official English vectors** — all 24 from the trezor/python-mnemonic
   corpus, which is the same fixture set Ian Coleman's tool ships.
4. **BIP39 PBKDF2 seed with passphrase** — the official TREZOR vector.
5. **`P != N` and `G` on curve over `P`.**

Result:

```
REFERENCE SELFTEST OK
  - BitcoinJS bip32 fixtures: master + 5 levels (priv/pub/cc/fp)
  - secp256k1: N != P, G on curve over P
  - BitcoinJS xpubs byte-identical: master + 5 nodes
  - BIP39 official English vectors: 24/24
  - BIP39 PBKDF2 seed with passphrase (TREZOR vector)
  - BIP48 m/48'/0'/0'/2' derives; account fingerprint abc63537
```

## The C engine

`evidence/engine.c` is a multithreaded C/OpenSSL implementation of the same
pipeline, used for speed. It is **not** trusted on its own.
`evidence/crossvalidate.py` tests it against the reference by planting targets:
it generates random entropy/passphrase/account/leaf combinations, computes the
expected witness-script hash with `reference.py`, recompiles the engine with that
hash as the target, and requires the engine to find it. It also runs negative
controls against the real escrow target.

```
CROSSVALIDATION OK: 12 planted targets found, 5 negative controls clean
```

Two harness bugs were found and fixed while doing this, both worth recording
because either would have faked a result:

- **Stale probe binary.** The planted-target test rewrote `TARGET_HEX` into a
  source file, but a failed substitution silently left the previous target in
  place. Now the substitution is regex-anchored, asserts exactly one match, and
  deletes the binary before rebuilding.
- **`"NO_MATCH"` contains `"MATCH"`.** The success check was
  `"MATCH" in out`, which is true for `NO_MATCH`. Now it requires the output to
  *start* with `MATCH`. Before this fix the suite reported a false positive on
  the real escrow target that was purely a test-harness artifact.

## Engine bugs found by AddressSanitizer

- **Shared `BN_CTX` and `EC_GROUP` across threads.** `BN_CTX` is not
  thread-safe; concurrent `EC_POINT_mul` segfaulted. Each worker now allocates
  its own `BN_CTX` and its own copy of the group order. `EC_GROUP` is read-only
  after setup and is still shared.
- **Uninitialized `words[256]` in `entropy_to_mnemonic`.** The function used
  `strcat` without terminating the buffer first, so it appended onto stack
  garbage. This produced a `*** buffer overflow detected ***` abort that
  initially looked like a protocol-parsing problem.
- **Unbounded `realloc` growth** when reading many digest cases. Replaced with a
  checked helper plus zeroing of the new half.

## Genesis block bytes

The hardcoded Genesis hex in the repo was malformed (290 bytes, and a corrupted
run in the coinbase pubkey). The engine now uses the 285-byte block fetched from
`https://blockstream.info/api/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f/raw`
and asserts the length. The parsed fields are self-checking: double-SHA256 of the
first 80 bytes reproduces the block hash
`000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`.
