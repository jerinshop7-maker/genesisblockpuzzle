# Genesis Block Wallet Puzzle — agent handoff

Snapshot date: 2026-09-25 UTC (chain refresh)

## Current state

The escrow is:

`bc1qfkhx02v89u2qyyyljeczw6hu9sr437y44t7ae5yf09thrdukfqesnjg2wj`

Its native P2WSH witness program is:

`4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833`

No spend or broadcast was attempted by this investigation. The latest address snapshot reports 54 confirmed transactions, 414,061 sats funded and unspent, with no mempool transactions. The endpoint returned 50 history entries (its page limit). Nine new OP_RETURNs through block 968519 are saved in [evidence/opreturn-2026-09-25.md](/home/kali/genesisblockpuzzle/evidence/opreturn-2026-09-25.md); the prior delta is in [evidence/opreturn-2026-09-24.md](/home/kali/genesisblockpuzzle/evidence/opreturn-2026-09-24.md).

The prior local notes are in [TESTS_AND_HINTS.md](/home/kali/genesisblockpuzzle/TESTS_AND_HINTS.md). They are useful context, but the status labels below are the stricter independent assessment.

## Confirmed directly by OP_RETURN answers

- The witness script is a multisig.
- It is 2-of-2: two keys and both are required.
- Both keys use the same Genesis field.
- There is no hash in the Genesis-field key derivation statement.
- The two keys are derived independently from Genesis, not by chaining key 2 from key 1.
- The author’s derivation order is: `root -> multisig -> mainnet -> genesis_data -> script_type`.
- `root` is the master key derived from a BIP39 seed.
- `genesis_data` is some Genesis-block data used as the BIP48 account number.
- BIP39 has 12 words, with a non-empty passphrase.
- The entropy is public Genesis-block data, is not the raw 16 bytes, and is a 128-bit digest.
- The passphrase is a name.
- The passphrase formatting is deliberately left for brute force.
- Block 967396 asked about the digest input but did not resolve it.
- Confirmed answer at block 967477: view Genesis data as binary, hex, decimal, or ASCII and try all four forms.
- Confirmed at block 967740: the selected source is somewhere in the Genesis block and brute force is expected.
- Confirmed at block 968343, tx `ae906bdebdf7cd2e9b2490a727d5d91eaa203c2ae68f8461ea62e07ffe3b9b1c`: “First 128 bits of SHA-256 hash of the genesis block's entropy.” This settles SHA-256 and first-16-byte truncation; the selected Genesis byte range/representation remains unresolved.
- Confirmed at block 968357: following the 50,000-sat escrow payment plus 1,000-sat delivery output, the author posted the two public keys in Electrum `BIE1` ECIES ciphertext to the payer's input pubkey. The Base64 ciphertext and linkage are recorded in the Sept. 24 evidence. It is not publicly decryptable without the payer's private key.
- Blocks 968411, 968424, 968440, 968461, and 968466 contain encrypted `BIE1` questions to different recipients; their plaintext is not public.
- Public statement at block 968519 says an earlier private question requested both cosigners' master fingerprints and derivation paths. The author withheld them as too revealing. This identifies origins/paths as a high-value unresolved axis, not their actual values; the author says future questions will be public.

## Inferences, not yet confirmations

- “Who received the first transaction?” most likely points to Hal Finney, the recipient normally identified for Bitcoin’s first ordinary transaction. Treat `Hal Finney` and its case/spacing variants as a hypothesis until a matching escrow script proves it.
- A standard BIP48 interpretation is probably `m/48'/0'/ACCOUNT'/2'`, where `0'` is mainnet and `2'` is native P2WSH. The exact two-key leaf convention is not confirmed.
- It is not confirmed that both cosigners use the same mnemonic/passphrase. The question asking this appears at block 967106, but the answer at 967140 answered a different question about generated words.
- It is not confirmed whether `genesis_data` is nonce, time, bits, a length, a 32-byte field reduced to an account integer, or another canonical Genesis value.
- It is not confirmed whether “128-bit digest” means MD5, a truncation of SHA-256, or another 128-bit digest construction.
- The 50,000-sat offer to reveal public keys is not used; no payment, spend, or broadcast is authorized or attempted.

## Recovered Genesis bytes

Fetched from the public raw Genesis endpoint:

`https://blockstream.info/api/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f/raw`

Observed raw block length: 285 bytes. Header: 80 bytes. The block contains one transaction.

- Genesis block hash: `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`
- Merkle root: `4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b`
- Time: `1231006505` (`03/Jan/2009` in the Times text)
- Bits: `0x1d00ffff` / `486604799`
- Nonce: `2083236893`
- Coinbase scriptSig length: 77 bytes
- Coinbase scriptSig prefix: `04ffff001d010445`
- 69-byte visible text: `The Times 03/Jan/2009 Chancellor on brink of second bailout for banks`
- 47-byte headline suffix: `Chancellor on brink of second bailout for banks`
- Coinbase output pubkey (65-byte uncompressed SEC key): `04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0bdd8d578a4c702b6bf11d5fac`

Important parsing detail: the coinbase transaction begins after the one-byte transaction-count field. Within the transaction, the scriptSig length is at offset 41 and the scriptSig begins at offset 42. The visible Times text begins at scriptSig byte 8, not byte 7.

## Tests already run and their result

The interrupted sweeps did not find a match. They tested combinations of:

- Genesis raw block, raw header, raw coinbase transaction, raw scriptSig, 69-byte Times text, 47-byte headline, merkle root, time, bits, nonce, block hash, and common Times-text variants.
- MD5 and first/last 16 bytes of SHA-256 for many of those inputs.
- Hal/Finney name variants including spacing, joining, case, hyphen, initials, and longer legal-name guesses.
- Explicit account candidates `0, 1, 2, 3, 47, 69, 77, 2009, 1231006505, 2083236893, 486604799`, plus selected 4-byte interpretations of Genesis fields and digest values.
- Standard-looking extra BIP48 leaf paths using child indices 0 and 1, hardened and non-hardened variants, including one-, two-, and three-level suffixes.
- Compressed public keys in `OP_2 <33-byte key> <33-byte key> OP_2 OP_CHECKMULTISIG`, hashed with SHA-256 and compared to the escrow witness program.

This is negative evidence only. The sweep was broad but not exhaustive and was stopped because it grew combinatorially; no claim of “no solution” is justified.

## Promising discovery

The live OP_RETURN sequence narrows the puzzle substantially beyond the old snapshot:

`BIP39 12 words` -> `passphrase Y` -> `passphrase is a name` -> `words generated from entropy` -> `128-bit digest` -> `discover passphrase format through brute force` -> `digest input still unknown`.

The confirmed entropy rule is `SHA256(candidate Genesis bytes)[0:16]`, then BIP39 mnemonic generation. The candidate Genesis part and its representation still require brute force. “Entropy” likely names the selected Genesis byte sequence; test candidates against the escrow hash.

The block-967477 answer gives a concrete representation matrix: binary, hex, decimal, or ASCII. The block-968343 answer confirms the first 16 bytes of SHA-256. Local tests cover common fields and representations under a Hal Finney passphrase hypothesis; the largest formatted-name run was interrupted and is not a completed negative. Details are in [evidence/search-log-2026-09-23.md](/home/kali/genesisblockpuzzle/evidence/search-log-2026-09-23.md) and the Sept. 24 chain update.

The Sept. 25 OP_RETURNs add no entropy/account value, but reveal that both cosigners' master fingerprints and derivation paths were requested privately and withheld as too revealing. This makes exact key origins the clearest information bottleneck. Watch for the promised public follow-up.

A later same-root sweep (153 representations × 41 basic passphrases × 123 accounts × six standard leaf layouts) was interrupted without a `MATCH` or `NO_MATCH`; it is not evidence either way. See [evidence/search-log-2026-09-25.md](/home/kali/genesisblockpuzzle/evidence/search-log-2026-09-25.md). Do not rerun unchanged; first cache BIP32 nodes and add progress/checkpointing.

## Tree route for the next continuation

```text
Start
├─ A. Preserve/re-fetch chain evidence
│  ├─ Latest captured public response is block 968519; re-check for follow-up OP_RETURNs.
│  ├─ Append only new txids/OP_RETURNs to the evidence snapshot.
│  └─ Re-check escrow status and witness program before any solver claim.
│
├─ B. Resolve the 128-bit entropy input (confirmed: SHA256(input)[0:16])
│  ├─ B1: Enumerate Genesis fields and contiguous byte ranges
│  ├─ B2: For each candidate, test binary/raw bytes
│  ├─ B3: Test hex text (lower/uppercase, with/without 0x)
│  ├─ B4: Test decimal integers and bytewise decimal forms
│  └─ B5: Test ASCII/text forms, including the Times text/headline
│
├─ C. Resolve BIP48 account
│  ├─ C1: Keep account-source search separate from entropy-source search
│  ├─ C2: nonce, time, bits, field lengths, year/date-derived integers
│  ├─ C3: 4-byte windows in both endian orders and legal low-31-bit mappings
│  └─ C4: preserve BIP32's 31-bit child-index limit
│
├─ D. Resolve the two independent leaves
│  ├─ D1: base/0 and base/1
│  ├─ D2: base/0' and base/1'
│  ├─ D3: base/0/0 and base/1/0
│  ├─ D4: base/0'/0' and base/1'/0'
│  ├─ D5: external/change alternatives only after D1-D4
│  └─ D6: test both pubkey orders and compressed/uncompressed serialization
│
└─ E. Validate a candidate
   ├─ Recompute BIP39 checksum and mnemonic exactly.
   ├─ Recompute PBKDF2-HMAC-SHA512 with the candidate passphrase.
   ├─ Recompute BIP32 master and both child keys independently.
   ├─ Build exact 2-of-2 witness script and SHA-256 it.
   ├─ Require exact equality to 4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833.
   └─ Only after equality call the result solved/confirmed; never infer from a plausible mnemonic alone.
```

## Do not repeat blindly

Do not start another all-dimensions Cartesian sweep without first fixing the search axes and recording them. The previous broad run demonstrated that naive combinations become expensive quickly. Continue from branch B/C/D with a small, logged matrix, and save every tested axis and result beside this handoff.
