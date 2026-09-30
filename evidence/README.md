# Search tooling

Everything here is read-only research tooling. Nothing in this directory spends,
signs, or broadcasts a transaction.

## Layout

| File | Role |
|---|---|
| `collect_opreturns.py` | Fetches the full escrow history from mempool.space, lists every OP_RETURN |
| `decode_opreturns.py` | Same, but decodes OP_RETURN pushes into readable text; writes the full transcript |
| `classify_author.py` | Attributes each payload to author reply vs. questioner question |
| `reference.py` | **Correctness oracle.** Pure-Python BIP39/BIP32/BIP48, self-tested against ground truth |
| `engine.c` | Fast C/OpenSSL search engine, two modes (same-root and independent-root) |
| `crossvalidate.py` | Proves the engine matches the reference, same-root mode |
| `crossvalidate_indep.py` | Proves the engine matches the reference, independent-root mode |
| `solve.py` | Search driver: builds the candidate axes and streams them to the engine |
| `english.txt` | BIP39 English wordlist (from `bitcoin/bips`) |
| `search_bip48.py` | **Superseded.** See "Why the old engine is void" below. Kept for history. |

## Build

```sh
cd evidence
gcc -O2 -march=native -o engine engine.c -lcrypto -lpthread
```

## Verify (do this before trusting any result)

```sh
python3 reference.py            # BIP32/BIP39 self-test against BitcoinJS + official vectors
python3 crossvalidate.py        # engine vs reference, same-root mode
python3 crossvalidate_indep.py  # engine vs reference, independent-root mode
```

`reference.py` requires network access on first run: it fetches the BitcoinJS
`bip32` fixture file, the official BIP39 vector file, and the wordlist.

Expected output:

```
REFERENCE SELFTEST OK
  - BitcoinJS bip32 fixtures: master + 5 levels (priv/pub/cc/fp)
  - secp256k1: N != P, G on curve over P
  - BitcoinJS xpubs byte-identical: master + 5 nodes
  - BIP39 official English vectors: 24/24
  - BIP39 PBKDF2 seed with passphrase (TREZOR vector)
  - BIP48 m/48'/0'/0'/2' derives; account fingerprint abc63537

CROSSVALIDATION OK: 12 planted targets found, 5 negative controls clean
INDEP CROSSVALIDATION OK: 10 planted two-root targets found, 3 negative controls clean
```

## Run a search

```sh
# Same-root model: one seed, two distinct leaf paths under the account.
python3 solve.py --fields headline:txt

# Independent-root model: two seeds (one per cosigner) at the same path.
ENGINE_INDEP=1 python3 solve.py --fields headline:txt
```

Useful flags:

- `--fields` — comma-separated list of `field:representation` candidates, or `all`
- `--passphrases basic|formatted`
- `--list-only` — show the digest pieces and the total check count without running

## Engine input protocol

The driver streams a job to the engine over stdin, one directive per line:

```
D <nbytes> <label>      followed by a line of 2*nbytes hex characters
P <passphrase>
A <account-index> <label>
L <label> <n> <idx...> <m> <idx...>
Q                       end of job
```

Hex-encoding the digest payload keeps the protocol line-oriented, so arbitrary
binary Genesis slices can be tested.

## Engine modes

- **Same-root (default).** One BIP39 seed, one `m/48'/0'/ACCOUNT'/2'` account node,
  two distinct leaf paths beneath it.
- **Independent-root (`ENGINE_INDEP=1`).** Two BIP39 seeds, both taken from the
  same name set, both derived at the *same* `m/48'/0'/ACCOUNT'/2'/leaf` path.
  This models a real 2-of-2 multisig where each cosigner has their own seed.

Both modes test both key orderings in the witness script (as-emitted and
BIP67-sorted), and both use compressed 33-byte public keys.

## Why the old engine is void

`search_bip48.py` defines one constant and uses it for two different jobs:

```python
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

That value is the secp256k1 **group order**, which is correct for the BIP32 child
key addition, but it is *not* the **field prime**. All of its point arithmetic
therefore ran modulo the wrong modulus, every derived public key was wrong, and
every "no match" it reported is meaningless. The same mistake is easy to repeat;
`reference.py` asserts `P != N` and that `G` satisfies `y^2 = x^3 + 7 (mod P)` for
exactly this reason.

Do not rerun the old sweeps and do not record their results as negative evidence.
