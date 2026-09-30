# Genesis Block Wallet Puzzle — agent handoff

Snapshot date: **2026-09-30 UTC** (chain refresh + solver rebuild)

> **Read this first.** The previous solver in this repo was cryptographically
> wrong, so every "no match" it reported is meaningless. Section
> ["The prior engine is void"](#the-prior-engine-is-void) explains why, and
> `evidence/README.md` explains how the replacement was proven. Do not reuse
> `evidence/search_bip48.py`, and do not read the 09-23 / 09-25 search logs as
> negative results.

## Current state

The escrow is:

`bc1qfkhx02v89u2qyyyljeczw6hu9sr437y44t7ae5yf09thrdukfqesnjg2wj`

Its native P2WSH witness program is:

`4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833`

No spend or broadcast was attempted by this investigation.

| Metric | 2026-09-25 | 2026-09-30 |
|---|---:|---:|
| confirmed txs | 54 | **71** |
| funded (sats) | 414,061 | **621,132** |
| spent (sats) | 0 | **0** |
| mempool txs | 0 | 0 |

Still unspent. Reproduce with `python3 evidence/decode_opreturns.py`; the full
transcript is in `evidence/OPRETURN-TRANSCRIPT-2026-09-30.md` and the new-messages
delta in `evidence/chain-2026-09-30.md`.

## The puzzle, as currently understood

```
Genesis block --contiguous range, as a tool prints it--> digest_input
digest_input --cut|jq|tr-->  hashed text
hashed text --sha256--> first 32 hex chars = 128-bit entropy
entropy --BIP39--> 12 words
words --PBKDF2-HMAC-SHA512(words, "mnemonic" + passphrase)--> seed
seed --m/48'/0'/ACCOUNT'/2'/leaf--> cosigner public key
two cosigner keys --> OP_2 <A> <B> OP_2 OP_CHECKMULTISIG
SHA256(that script) must equal 4dae67a9...b7964833
```

Open axes: **which contiguous range**, the **passphrase format**, the **account
number**, and the **two leaf paths / whether the roots are independent**.

## Confirmed directly by OP_RETURN answers

Each is a quote from the author's own transactions. Block numbers are from the
full history now stored in `evidence/OPRETURN-TRANSCRIPT-2026-09-30.md`.

### Structure

- The witness script is a multisig. (963744)
- Two keys, both required. (963768)
- Both keys use the same Genesis field, and there is no hash. (963829)
- Both keys are derived independently from Genesis. (963868)
- Derivation rule: `root -> multisig -> mainnet -> genesis_data -> script_type`. (964496)
- `root` = the master key derived from the BIP39 seed; `genesis_data` = some data
  from the Genesis block used as the BIP48 account number. (966409)

### Seed and entropy

- BIP39, 12 words, so 128 bits of entropy; passphrase is non-empty. (966576)
- The 12 words were generated from entropy. (967140)
- Passphrase is a name; the entropy is not the raw 16 bytes. (967064)
- Entropy is a 128-bit digest. (967260, 967281)
- Entropy = **first 128 bits of SHA-256 of the digest input**. (968343)

### The digest input — this is the new, decisive material

- **The digest input is a contiguous piece of the Genesis block, exactly as a
  standard tool shows it, and the author got it by copy-pasting the tool's
  output.** (968601, author)
- The tool chain was: `bitcoin-cli`, `cut`, `jq`, `tr`, `sha256sum`, then
  `iancoleman/bip39` or `entropylab`. (968768, author)
- **The `cut`/`jq`/`tr` step modified the Genesis text BEFORE it was hashed**, and
  **the 12 words come from the first 32 hex characters of the `sha256sum` output
  used as raw entropy.** (968996, answering the shape question at 968981 with
  `1) a; 2) b`)
- Genesis block is extremely small; "this will have to be uncovered via
  brute-force". (968768, author)

### What this retires

The block 967477 suggestion that the digest input might be viewed as binary, hex,
decimal, or ASCII is **no longer the primary axis**. The author says it is a
contiguous range of the tool-printed block, transformed before hashing. The
remaining work is to enumerate ranges, not to re-encode fields.

## Inferences, not yet confirmations

- "The passphrase is a name" is confirmed; the name itself is not. The standing
  hypothesis is **Hal Finney** (recipient of the first Bitcoin transaction), with
  Satoshi Nakamoto as the secondary candidate. Neither has produced a matching
  escrow script.
- The passphrase formatting is deliberately left for brute force (967383: "You'll
  have to discover the fmt through brute force. The key question greatly narrows
  the search space"). "The key question" appears to be the question at 967106,
  *"Do both cosigners use the same 12 words and the same passphrase?"*, which the
  author has never answered directly. Treat that as the highest-value unknown.
- `genesis_data` as the account number is not narrowed to a specific field.
  Candidates: nonce `2083236893`, time `1231006505`, bits `486604799`, year
  `2009`, a date integer, or a 4-byte window of some field reduced below `2^31`.
- The two leaf paths are not confirmed. The questioner at 968603 reads the
  origins as `[fingerprint/48h/0h/acct'/2h]`, i.e. depth 4 with the two keys
  distinguished beneath it. Standard candidates are the external pair `0/0` and
  `0/1`, and the cosigner-branch pair `0/0` and `1/0`.
- Whether the two keys come from one seed (two leaves) or two seeds (two
  cosigner roots) is **not** settled. Both models are now implemented.
- The 50,000-sat offer to reveal the public keys is not used. No payment, spend,
  or broadcast is authorized or attempted.

## The prior engine is void

`evidence/search_bip48.py` defines one constant and uses it for two different
secp256k1 moduli:

```python
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

That value is the secp256k1 **group order**. It is correct for the BIP32
child-key addition, but it is **not** the **field prime**, which is
`FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`. All of the
script's point arithmetic therefore ran modulo the wrong modulus, so every
derived public key was wrong and every comparison was against a hash that could
never match. Hardened-only derivation never needs the public key, which is why the
bug survived.

Therefore:

- Every "no match" in `search-log-2026-09-23.md` and `search-log-2026-09-25.md`
  is meaningless. Read them as **untested**.
- The interrupted sweeps described there should not be resumed or extended.
- The 50,000-sat / 30k / 20k offers, and the earlier completed matrix, all
  rest on that engine.

One-line check that catches the class of bug: `G` satisfies `y^2 = x^3 + 7 (mod p)`
but not `(mod n)`.

## How the replacement was proven

`evidence/reference.py` is the correctness oracle and its self-test must pass
before any sweep result is trusted:

- BIP32 against the BitcoinJS `bip32` fixtures at every level of
  `m -> m/0' -> m/0'/1 -> m/0'/1/2' -> ... -> /1000000000`
- **full xpub base58check serialization byte-identical to BitcoinJS** for the
  master and all five children
- all 24 official BIP39 English vectors, plus the official PBKDF2 passphrase vector
- an explicit assertion that the field prime and group order differ, and that `G`
  is on the curve over `P`

`evidence/engine.c` is the fast C/OpenSSL engine, proven against that oracle by
planting targets and requiring the engine to find them, plus negative controls
against the real escrow target, in both search modes.

Full write-up, including four engine bugs and two test-harness bugs that would
each have faked a result: `evidence/verification-2026-09-30.md`.

## Recovered Genesis bytes

Fetched from the public raw Genesis endpoint, 285 bytes, verified by asserting
that the double-SHA256 of the first 80 bytes reproduces the block hash:

`https://blockstream.info/api/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f/raw`

- Genesis block hash: `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`
- Merkle root: `4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b`
- Time: `1231006505` (`03/Jan/2009` in the Times text)
- Bits: `0x1d00ffff` / `486604799`
- Nonce: `2083236893`
- Coinbase scriptSig length: 77 bytes; prefix `04ffff001d010445`
- 69-byte visible text: `The Times 03/Jan/2009 Chancellor on brink of second bailout for banks`
- 47-byte headline suffix: `Chancellor on brink of second bailout for banks`
- Coinbase output pubkey: `04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac`

The hardcoded hex previously in this repo was malformed (290 bytes, and a
corrupted run in the coinbase pubkey). That is fixed and length-asserted.

Parsing detail: the coinbase transaction begins after the one-byte transaction
count. Within the transaction, the scriptSig length is at offset 41 and the
scriptSig begins at offset 42. The visible Times text begins at scriptSig byte 8,
not byte 7.

## Tooling

Build, verify, and run:

```sh
cd evidence
gcc -O2 -march=native -o engine engine.c -lcrypto -lpthread
python3 reference.py
python3 crossvalidate.py
python3 crossvalidate_indep.py
python3 solve.py --fields headline:txt            # same-root model
ENGINE_INDEP=1 python3 solve.py --fields headline:txt   # independent-root model
```

See `evidence/README.md`. Nothing in the tooling spends, signs, or broadcasts.

## Tree route for the next continuation

```text
Start
├─ 0. Guard rails
│  ├─ Rebuild and re-verify: reference.py, crossvalidate.py, crossvalidate_indep.py
│  ├─ Re-fetch the escrow; append only new txids to the transcript
│  └─ If new OP_RETURNs exist, they outrank everything below
│
├─ A. Highest-value axis: the tool-printed contiguous range
│  ├─ A1: raw_block:hex — the exact 570-char `bitcoin-cli getblock <h> 0` output
│  │     162,735 contiguous char ranges
│  ├─ A2: same, with newlines/indentation stripped, as an explorer wraps it
│  ├─ A3: header-only, coinbase-tx-only, and scriptSig-only hex
│  ├─ A4: the 69-byte Times text and the 47-byte headline, as text
│  └─ A5: order by descending prior, and stop the moment anything matches
│
├─ B. Account number (run alongside A, not after it)
│  ├─ B1: prune to the semantically meaningful values first
│  │     nonce, time, bits, year 2009, date integers, 47, 69, 77
│  ├─ B2: then the 4-byte windows of every header field, both endians
│  ├─ B3: then digest-derived values mod 2^31
│  └─ B4: keep every value below 2^31 (BIP32 hardened limit)
│
├─ C. The two keys
│  ├─ C1: same-root, leaves 0/0 and 0/1
│  ├─ C2: same-root, leaves 0/0 and 1/0
│  ├─ C3: independent-root, two seeds from the same name set, same leaf path
│  │      <- this is the model no correct engine had tested here before
│  └─ C4: both key orderings, compressed 33-byte keys
│
├─ D. Passphrase (only widen after C)
│  ├─ D1: Hal Finney formats — space, joined, case, initial, legal name
│  ├─ D2: Satoshi Nakamoto formats
│  └─ D3: note the author's "the key question" is whether both cosigners share
│         one mnemonic, so C3 is higher value than more D spellings
│
└─ E. Validate before believing
   ├─ Require exact SHA-256 equality on the witness script
   ├─ Re-derive the match independently with reference.py, not the engine
   ├─ Re-derive the BIP39 words and PBKDF2 seed by hand from the stated inputs
   └─ Never call it solved on a plausible mnemonic, a partial match, or an
       "almost" fingerprint
```

## Do not repeat blindly

- Do not rerun `search_bip48.py` or resume the sweeps in the 09-23 / 09-25 logs.
  Their results are void, not negative.
- Do not treat an interrupted run as a negative. Record a run only when it
  actually printed `MATCH` or `NO_MATCH`, and say which axes it covered.
- Do not start another all-dimensions Cartesian sweep without fixing the axes
  and logging them. Cache the BIP48 account node and the leaf pubkeys per account
  first; that alone is a ~2.7x speedup and makes extra leaf layouts nearly free.
- Do not claim a solution without exact witness-script hash equality.
