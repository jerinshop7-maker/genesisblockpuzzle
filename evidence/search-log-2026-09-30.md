# Search status — 2026-09-30

## Completed

| Check | Result |
|---|---|
| `reference.py` self-test | **OK** — BIP32 byte-identical to BitcoinJS xpubs, 24/24 official BIP39 vectors |
| `crossvalidate.py` (same-root) | **OK** — 12 planted targets found, 5 negative controls clean |
| `crossvalidate_indep.py` (independent-root) | **OK** — 10 planted two-root targets found, 3 negative controls clean |
| Escrow re-fetch, full history | **OK** — 71 txs, 621,132 sats, 0 spent, unspent |

## In progress

A same-root sweep over the `headline:txt` digest axis was running at the time of
this snapshot:

```
digest pieces=1128 passes=24 accounts=370 leafsets=6
total script-hash checks=60,099,840
```

Measured throughput is about 10,000 checks/second on 2 cores, so roughly
100 minutes of wall clock. It had produced no match when this file was written.

**This is not a completed negative.** Do not record it as one, and do not extend
it to other fields by inference.

## Not yet run

- `coinbase_text:txt` and the other text fields
- `raw_block:hex` — the 570-character `bitcoin-cli getblock <hash> 0` output,
  which is the single most likely digest source given the author's "exactly as a
  standard tool shows it" answer. This is 162,735 contiguous ranges, about 14
  times the headline axis, so it needs the leaf cache and a narrower account set
  to finish in reasonable time.
- `raw_block:raw`, `raw_header:hex`, `raw_tx:hex`, `raw_scriptsig:hex`
- Independent-root mode across any digest axis

## Prior results that are void

Everything reported by `search_bip48.py` and the sweeps described in
`search-log-2026-09-23.md` / `search-log-2026-09-25.md` is **void**, because that
engine used the secp256k1 group order for point arithmetic. See
`verification-2026-09-30.md`. Those logs should be read as "untested", not as
"no match".

## Next actions, highest value first

1. Run the `raw_block:hex` contiguous-range axis, which is what the author's
   toolchain description actually points at. Prune the account set to the
   semantically meaningful values first (nonce, time, bits, year, the Times-text
   lengths) rather than the full 370-entry derived set, and widen it only if
   that fails.
2. Run the independent-root model on the same axis. This covers the "two
   cosigners, two seeds, same path" reading, which no correct engine has ever
   tested here.
3. Only after those, widen the passphrase axis to the formatted name set. The
   author's "the key question greatly narrows the search space" points at the
   unanswered question of whether both cosigners share one mnemonic, so
   independent-root is a higher-value axis than more passphrase spellings.
4. Re-check the escrow for new OP_RETURNs before any large run. The author said
   he would ask future questions publicly, and the last twelve messages moved the
   target substantially.
