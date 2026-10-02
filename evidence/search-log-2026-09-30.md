# Search status — 2026-09-30

## Completed

| Check | Result |
|---|---|
| `reference.py` self-test | **OK** — BIP32 byte-identical to BitcoinJS xpubs, 24/24 official BIP39 vectors |
| `crossvalidate.py` (same-root) | **OK** — 12 planted targets found, 5 negative controls clean |
| `crossvalidate_indep.py` (independent-root) | **OK** — 10 planted two-root targets found, 3 negative controls clean |
| Escrow re-fetch, full history | **OK** — 71 txs, 621,132 sats, 0 spent, unspent |

### Sweeps that ran to completion (all NO_MATCH)

| # | Digest axis | Mode | Accounts | Checks | Result |
|---|---|---|---:|---:|---|
| 1 | tool-plausible sub-ranges of 19 rendered fields (`--digest-mode semantic`) | same-root | 21 pruned | 10,665,648 | NO_MATCH |
| 2 | `getblock` JSON fields via `jq -r` (30 candidates, whole-value) | same-root | 370 all | 1,598,400 | NO_MATCH |
| 3 | same `jq` axis | independent-root | 370 all | 18,381,600 | NO_MATCH |

Stage 1 covers, for every rendered field, the whole value plus every 8/16/32/64/128
char aligned window — i.e. the ranges a human would actually select with `cut`.
Stage 2 and 3 cover a digest family that was **not** in the original notes: the
author's toolchain names `jq`, and `bitcoin-cli getblock <genesis> 1 | jq -r .<field>`
prints specific strings (`.nonce` -> `2083236893`, `.merkleroot` -> the hex root,
`.bits` -> `486604799`, `.chainwork`, `.nextblockhash`, ...), each also tested
with a trailing newline. Values were verified against the parsed Genesis fields.

Sweep 1 was run twice over its history: an earlier attempt covered only the
`headline:txt` axis (1,128 of the 3,527 pieces) and was killed at 34 minutes
without a result. That partial run is **not** counted as evidence either way.

## In progress

```
=== fullhex :: --fields raw_block:hex --digest-mode full
    --account-only 0,1,2,2009,2083236893,1231006505,486604799 --leaves std
digest pieces=157207 passes=24 accounts=7 leafsets=2 indep=False
total script-hash checks=52,821,552
```

Every contiguous character range of the 570-character lowercase hex string that
`bitcoin-cli getblock <genesis> 0` prints, which is the source the author's
"exactly as a standard tool shows it" answer points at. Measured throughput is
about 6,400 checks/second on 2 cores, so roughly 2h20m.

## Infrastructure fix needed to run the large axis

The first attempt at this stage died instantly. Cause: `DigestCase` held a fixed
`char digest_input[4096]`, so 157,207 cases needed ~685 MB, and the
`realloc`-doubling growth path peaked around 2 GB on a 2.2 GB box and was
OOM-killed.

Fix: digest payloads now live in a single growable byte blob, and each case keeps
only `(offset, len)` plus a 64-byte label. Both search modes were re-validated
against the reference after the change, and both passed.

## Not yet run

- `fullhex_indep`: the same 157,207 ranges in independent-root mode. This is the
  single highest-value remaining axis, because it is the model a real 2-of-2
  multisig uses and no correct engine had tested it before today.
- `raw_block:raw`, `raw_header:hex`, `raw_tx:hex`, `raw_scriptsig:hex` in
  `--digest-mode full` (every contiguous range, not just semantic windows).
- The formatted passphrase set (`--passphrases formatted`).
- The remaining 363 derived account candidates over the highest-prior digest
  candidates.

## Prior results that are void

Everything reported by `search_bip48.py` and the sweeps described in
`search-log-2026-09-23.md` / `search-log-2026-09-25.md` is **void**, because that
engine used the secp256k1 group order for point arithmetic. See
`verification-2026-09-30.md`. Those logs should be read as "untested", not as
"no match".

## Next actions, highest value first

1. `fullhex_indep` — the 157,207 contiguous hex ranges with two independent
   roots. Queued in `run_sweep.sh`.
2. If both same-root and independent-root fail on `raw_block:hex`, the digest
   source is probably not the whole-block hex, and the next thing to test is the
   explorer's **line-wrapped** rendering (newlines inside the range), which the
   `tr` in the author's toolchain would strip.
3. Widen accounts from the 7 used here to the full 370 only after the digest axis
   is exhausted at a narrow account set.
4. Re-check the escrow for new OP_RETURNs before any large run. The author said he
   would ask future questions publicly, and the last twelve messages moved the
   target substantially.

