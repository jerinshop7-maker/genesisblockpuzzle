# Genesis Block Wallet Puzzle — all hints + all tests done

Target: `genesis-block-wallet-puzzle-142ksats`
Escrow: `bc1qfkhx02v89u2qyyyljeczw6hu9sr437y44t7ae5yf09thrdukfqesnjg2wj`
(P2WSH, program `4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833`)

Status **2026-09-30**: funded-unspent, 621,132 sats, 71 txs, 0 spent, 0 mempool.
No spend or broadcast was ever attempted. **No MATCH found.**

> **The results below are void, not negative.** Every test recorded in this file,
> and in `evidence/search-log-2026-09-23.md` / `-2026-09-25.md`, was produced by
> `tools/oracle.py` / `evidence/search_bip48.py`, which used the secp256k1
> **group order** for **point arithmetic**. Those are different moduli, so every
> derived public key was wrong and no search could ever have matched. See
> `Agents.md` for the full explanation. Keep the *hints* below, discard the
> *conclusions*.

Notation (retained from the original notes): T = 69B coinbase text,
J = 47B headline (T[22:]), S = 77B scriptSig, P = 65B coinbase output pubkey
(04||X||Y), X/Y = 32B coordinates.

---

## PART A — all hints, author verbatim, in block order

Announcement — 2026-08-22 19:45, block 963629, `b691de3657880d9a1eabd2783b1a9fa8c5313ced338495bf10e85727012d7a77`:

> "I made a Bitcoin puzzle using information contained in the genesis block created by Satoshi to generate the wallet. The entropy is extremely low. I didn't even need to back anything up. Everything I needed was already in the genesis block. Good luck!"

Hint channel — 2026-08-23 01:51, block 963659, `248f690de194372564baa14e1bebf08154e2f2042ed205baa6157fdc0e3f22ea`:

> "If you have a question, you can include it with a transaction sent directly to this address, and I will reply with a hint. Larger payments receive better hints. Dust transactions will be ignored."

### Q&A, blocks 963739 – 967477

| # | Block | Question asked | Author answer (verbatim) |
|---|---|---|---|
| 1 | 963744 | Is the witness script a hash lock, a multisig, or something else? | "The witness script is a multisig." |
| 2 | 963768 | How many keys, what threshold, and how are the keys derived from genesis? | "Two keys, both required. The rest is for you to derive." |
| 3 | 963829 | Are both keys from the same genesis field, and is the function a hash? | "Yes, both keys use the same Genesis field, and there is no hash." |
| 4 | 963868 | Is the second key derived from the first, or both from genesis independently? | "Both keys are derived independently from Genesis." |
| 5 | 963910 | Which genesis field, hash, merkle, nonce, time, headline, or pubkey? | "The Genesis Block is public. Which part of it matters is for you to discover." |
| 6 | 964491 | Prize address? Genesis field 32 bytes or smaller? | "Solve it to find out. Maybe both. If you can't check the Genesis block, you can also use The Times newspaper!" |
| 7 | 964496 | Can you give any hint about derivation offset/rule? | "Derivation rule: root -> multisig -> mainnet -> genesis_data -> script_type" |
| 8 | 965824 | — (author, no question) | "I can't give hints without a question. Low-value transactions get bad hints; dust will be ignored." |
| 9 | 966409 | Root = Times text as BIP32 seed? BIP39? raw key? genesis_data = BIP48 account? | "root = the master key derived from the BIP39 seed; genesis_data = some data from the genesis block used as the BIP48 account number." |
| 10 | 966576 | BIP39 entropy: genesis bytes/puzzle text/img/other? words 12/24? passphrase Y/N? | "BIP39: 12 words; Passphrase: Y; Entropy: The data needed to solve it is publicly available in the genesis block." |
| 11 | 966989 | Passphrase: genesis data or your own word? How long? What built the wallet? | "Passphrase: Who received the first transaction? That's all I've got to say. What built the wallet are the tools that support BIP32, 3/2, and 48." |
| 12 | 967064 | Passphrase sha256 first 8 hex? Entropy: raw 16B slice of Times or sha256? | "No, the passphrase is a name. The entropy isn't the raw 16 bytes." |
| 13 | 967106 | Do both cosigners use the same 12 words and the same passphrase? | **never answered** — see the note below |
| 14 | 967140 | Were the 12 words generated from entropy, or chosen directly as words? | "A Perhaps... but figuring that out is part of the puzzle. The 12 words were generated from entropy." |
| 15 | 967281 | Is the 128-bit entropy a zero-padded number, a digest, or neither? | "It's a 128-bit digest." |
| 16 | 967383 | Passphrase fmt: first/full/middle name? spaced/joined? lower/UPPER/Capitalized? | "Passphrase: You'll have to discover the fmt through brute force. The key question greatly narrows the search space." |
| 17 | 967396 | Digest input: typed text, raw block bytes, a file, or something else? | **never answered** — resolved indirectly by 968996, see below |
| 18 | 967477 | What genesis data can be viewed in binary, hex, decimal, or ASCII? | "That genesis coinbase data can be viewed in binary, hex, decimal, or ASCII. If you figure out which part is being used as the entropy, just try all four forms. Want a valuable hint? Send 50k sats and I'll reveal the public keys for this address." |
| 19 | 967558 | Is the hashed part a header field, the coinbase text, or the whole block? | **never answered** |
| 20 | 967740 | Which part + which hash gives the 128-bit entropy? | "Somewhere in genesis and brute force will be necessary to uncover it." |
| 21 | 968343 | (answer to "Which block part + which hash gives the 128-bit entropy? One line.") | "First 128 bits of SHA-256 hash of the genesis block's entropy. Encrypted pubkey: 50k sats output + 1k input." |
| 22 | 968379 | — (paid offer) | "50k+1k: please send the 2 pubkeys Electrum-encrypted to this tx's input pubkey" |
| 23 | 968435 | — (solver's process note) | "Depends. I'm going through batches of unlikely hypotheses with Claude and writing brute-force scripts with it. Though some of the alpha is mine. I'm 0xflorent. Doubted the paid-hint process at first, but I was wrong, I love it." |
| 24 | 968519 | — (solver, on private questions) | "Fair enough, I understand... my last question asked for the master fingerprint of one seed without the passphrase. Author declined as it would have been too easy to solve afterwards. Also, my previous encrypted question asked for the key origins (master fingerprints and derivation paths) of both cosigners. I'll keep that one private as it's strongly related to the 50k public keys question." |

### The decisive new hints, blocks 968561 – 968996

| Block | Who | Verbatim |
|---|---|---|
| 968561 | questioner | "Two quick shape questions. 1) Is the hashed input a contiguous piece of the genesis block exactly as a standard tool shows it (explorer, bitcoin-cli), or did you combine or edit parts yourself? 2) Did you get it by copy-pasting a tool's output, or by typing it yourself?..." |
| **968601** | **author** | **"It's a contiguous piece of the genesis block, exactly as a standard tool shows it. I got it by copy-pasting the tool's output."** |
| 968603 | questioner | Offer 20k+1k for both key origins `[fingerprint/48h/0h/acct'/2h]`, or at least both master fingerprints. |
| 968713 | questioner + author reason | "Offer 30k+1k: the master fingerprint of one cosigner's 12-word seed with an empty passphrase..." / Author: "Reason for decline: The genesis block is only 2.5E-32 of the 2^128 possibilities. Revealing the seed's master fingerprint without the passphrase is basically giving away the entropy. All the secret pieces have to be cracked at the same time." |
| **968768** | **author** | **"1) Apps/Tools used to generate the 12 words: bitcoin-cli, cut, jq, tr, sha256sum, iancoleman/bip39, OogaBoogaX/entropylab; 2) Genesis block is extremely small. This will have to be uncovered via brute-force; 3) Pasted from bitcoin-cli and also from an explorer."** |
| 968768 | questioner | "1) N; 2) N." (denying: digest input is ONLY the Times ASCII text; and that it is exactly tool copy-paste ASCII) |
| 968885 | questioner | Offer 50k+1k for `first8hex(sha256(passphrase UTF-8 noNL))` + `first8hex(sha256(12 words lowercase single-spaces))` |
| **968906** | **author** | **"Declined for the same reason as before. The puzzle wallet was built using secret components that are extremely weak on their own. Those components won't be disclosed or reduced to a searchable checksum. Revealing any one of them independently would turn part of the puzzle into an oracle for solving the others. So you'll have to recover the actual secret pieces and test them together. I won't provide any derived value that isolates any individual secret."** |
| 968981 | questioner | "Shape only, one letter each. 1) jq/cut/tr changed: a) the text before sha256sum b) only sha256sum's output (e.g. cut -c1-32). 2) Words: a) Coleman "12 words" on that text b) first 32 hex as raw entropy" |
| **968996** | **author** | **"1) a; 2) b."** |

## PART B — the pipeline, as the hints now pin it

Reading 968996 (`1) a; 2) b`) against the question at 968981, together with
968601 and 968768:

1. `cut`/`jq`/`tr` modified **the Genesis text before it was hashed** (answer "a").
   The transformation is upstream of the digest, not applied to the digest output.
2. The 12 words come from **the first 32 hex characters of the `sha256sum` output,
   used as raw entropy** (answer "b"). This corroborates 968343's "first 128 bits
   of SHA-256" rather than replacing it.

So:

```
bitcoin-cli / explorer output
  -> cut | jq | tr            (edit the contiguous Genesis text)
  -> sha256sum
  -> first 32 hex chars       (= 128-bit BIP39 entropy)
  -> iancoleman/bip39 or entropylab  (= 12 words)
  -> PBKDF2-HMAC-SHA512(words, "mnemonic" + passphrase)   (passphrase is a name)
  -> m/48'/0'/ACCOUNT'/2'/leaf  (genesis_data is the account number)
  -> two cosigner public keys
  -> OP_2 <A> <B> OP_2 OP_CHECKMULTISIG
  -> SHA256 must equal 4dae67a9...b7964833
```

**What this retires:** the block 967477 "binary / hex / decimal / ASCII" matrix is
no longer the primary axis. The input is a contiguous range of the tool-printed
block, transformed before hashing. The remaining work is enumerating ranges.

**What the tool name implies:** `bitcoin-cli getblock <hash> 0` prints the
serialized 285-byte block as one 570-character lowercase hex string, and
explorers render the same 570 characters (usually wrapped). So the realistic
digest-input space is the 570·571/2 = **162,735 contiguous character ranges** of
that string, plus the 285·286/2 = 40,755 raw-byte ranges, plus 2,415 / 1,128 for
the Times text / headline. That is the axis the author's "brute-force" comment
points at.

## PART C — why every test in the original file is void

`tools/oracle.py` and `evidence/search_bip48.py` both begin with:

```python
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

and use that single value for both secp256k1 moduli.

| Role | Correct constant |
|---|---|
| field prime `p` — point arithmetic, modular inverse | `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F` |
| group order `n` — BIP32 child key addition | `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` |

The value in the file is the group order. It is right for the BIP32 addition and
wrong for point arithmetic, so:

- every derived public key was wrong,
- every witness-script hash compared against the escrow was wrong,
- no search could ever have matched, regardless of coverage.

Hardened-only derivation never needs the public key, which is why the bug was
never caught by the tests that were run.

The original notes' "all `x214` paths" sweep, the MD5 / decimal-form sweeps, the
`P`/`X`/`Y` sweeps, and the independent-root sweep were all run through this
engine. Keep their *coverage* as a guide for what to re-test; discard their
conclusions.

Fast check that catches the whole class: `G` satisfies `y^2 = x^3 + 7 (mod p)` and
does **not** satisfy it `(mod n)`.

## PART D — replacement tooling, and its verification

`evidence/reference.py` is the new oracle. Its self-test must pass before any
sweep result is believed:

```
REFERENCE SELFTEST OK
  - BitcoinJS bip32 fixtures: master + 5 levels (priv/pub/cc/fp)
  - secp256k1: N != P, G on curve over P
  - BitcoinJS xpubs byte-identical: master + 5 nodes
  - BIP39 official English vectors: 24/24
  - BIP39 PBKDF2 seed with passphrase (TREZOR vector)
  - BIP48 m/48'/0'/0'/2' derives; account fingerprint abc63537
```

`evidence/engine.c` is the fast C/OpenSSL engine, in two modes:

- **same-root** — one seed, two distinct leaf paths under the account node;
- **independent-root** (`ENGINE_INDEP=1`) — two seeds from the same name set,
  both at the *same* `m/48'/0'/ACCOUNT'/2'/leaf`, which is what a real 2-of-2
  multisig does and what no correct engine had tested here before.

Both modes are proven against the oracle by planting targets and requiring the
engine to find them, plus negative controls on the real escrow target:

```
CROSSVALIDATION OK: 12 planted targets found, 5 negative controls clean
INDEP CROSSVALIDATION OK: 10 planted two-root targets found, 3 negative controls clean
```

Bugs found and fixed along the way are listed in
`evidence/verification-2026-09-30.md`. Two are worth flagging to anyone repeating
this, because either would have faked a pass: a stale probe binary that silently
kept a previous planted target when a source substitution failed, and the fact
that `"NO_MATCH"` contains the substring `"MATCH"`.

## PART E — what is still unknown

- **Which contiguous range.** Not narrowed. The `raw_block:hex` axis (162,735
  ranges) is the highest-value untried direction.
- **The passphrase.** Confirmed to be a name. Hint 11 points at "who received the
  first transaction", which most likely means **Hal Finney**; Satoshi Nakamoto is
  the secondary candidate. Neither has matched. The format is explicitly left for
  brute force.
- **Whether both cosigners share one mnemonic.** The question at 967106 was never
  answered, and at 967383 the author called it "the key question" that "greatly
  narrows the search space". Highest-value unknown.
- **The account number.** `genesis_data` is "some data from the genesis block",
  not narrowed to a field. Prune to nonce / time / bits / year / lengths first.
- **The two leaf paths.** Standard candidates are `0/0` + `0/1` and `0/0` + `1/0`.
- **Whether the roots are independent or shared.** Both now implemented; neither
  has matched.

Current honest status: one same-root sweep over the `headline:txt` axis was
still running with no match. That is an **incomplete run, not a negative
result**. See `evidence/search-log-2026-09-30.md`.
