# Search log — 2026-09-23

Target witness program: `4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833`

Search harness: [search_bip48.py](/home/kali/genesisblockpuzzle/evidence/search_bip48.py). It implements BIP39 entropy-to-words and PBKDF2 seed, BIP32 secp256k1, BIP48 account/script path, 2-of-2 script construction, optional BIP67 sorting, and compressed/uncompressed script key encodings. BIP32 derivation was cross-checked against `bip_utils`; RIPEMD-128 passed standard test vectors. No spend or broadcast was attempted.

## New clue sequence

- Block 967558, tx `679cfe1e07b15d7cdd2e0200809e37329366dd4b88d7be01f52570e87e935649`: asks whether hashed part is a header field, coinbase text, or whole block.
- Block 967740, tx `d78593ab6288e2c9792f8c5ad8d020893d1b1dd9631eb5b1ffa5765f13029cd7`: author says it is somewhere in Genesis and brute force is necessary.
- Block 968172, tx `0499b89a88b5ff98569fecf404afae878ea78b2442e7b698a4ee24409f9c0661`: asks which part and hash give the 128-bit entropy.
- Current mempool tx `ebf9978b92846bc529047d7c4849cf31fc4eef859dfbe73dd50ad007ff547d92`: “First 128 bits of SHA-256 hash of the genesis block's entropy.” This is a direct author response but remains unconfirmed until mined.

Working candidate rule: for each candidate Genesis part and representation, entropy is `SHA256(candidate_bytes)[:16]`. Block 967477 explicitly names binary, hex, decimal, and ASCII as forms to try. The selected byte range is still unknown.

## Completed negative tests

The following results did not match the escrow witness program:

- The prior broad all-field SHA-256-first16 matrix tested 153 Genesis representations, 81 explicit/account candidates, standard BIP48 receive/change layouts, sorted and unsorted key order, and Hal Finney as passphrase: 148,716 comparisons, no match. This predates the later addition of the separate coinbase pubkey/X/Y representations; those were subsequently tested in focused branches below.
- SHA-256-first16 of Times headline and 69-byte Times text in focused tests: no match.
- RIPEMD-128 for headline, 69-byte text, scriptSig, raw transaction, raw header, and whole block: no match under the tested standard key layouts. The implementation passed RIPEMD-128 vectors before these runs.
- MD5 decimal forms for 27 selected Genesis fields, including numeric header fields, hashes, pubkey coordinates, text, raw header/block/transaction/scriptSig: no match in tested standard layouts.
- MD5/SHA-256-first16/RIPEMD-128/MD4 focused derivations from coinbase pubkey and X/Y: no match in tested account/path/name subsets.
- Independent-root test with headline/MD5 and coinbase-text/MD5: each checked 4,890,336 script comparisons for the basic passphrase set and standard account candidates; no match.
- Standard same-root searches with headline/text/raw block/raw transaction/headers and basic or expanded Hal Finney variants, corrected key ordering, and tested SEC encodings: no match in the listed branches.
- YouTube clue at the live mempool payload was resolved by oEmbed as a Leslie Nielsen/Naked Gun comedy clip. Adding Leslie Nielsen as a candidate passphrase did not produce a match for headline/text MD5 or headline RIPEMD-128 in the small direct-account matrix. Treat it as secondary context, not a confirmed wallet clue.
- Decimal-text MD5 tests for Times text, headline, scriptSig, raw transaction, numeric fields, hashes, pubkey fields and bytewise decimal forms: no match in their bounded matrices.

## Interrupted test

Command:

```sh
python3 evidence/search_bip48.py --field all --digest sha256-first16 --names formatted --suffix standard --order both --encoding both --no-account-windows
```

It began with 153 generated Genesis representations, 266 name-format variants, 81 account candidates and six standard leaf layouts. It was interrupted after roughly five minutes while still computing; it produced no conclusion and must not be reported as a completed negative. Its excessive run time came from repeated derivations across the full cross product.

## Next route

1. Resolve the exact meaning of “Genesis block's entropy”: enumerate selected contiguous byte ranges/fields from the raw 285-byte block and its header/coinbase structures; then apply the explicitly requested binary, hex, decimal, and ASCII forms.
2. Use only SHA-256 and its first 16 output bytes for the BIP39 entropy unless a later mined answer changes this.
3. Keep BIP48 account candidates independent from the entropy source. Try conventional account-number mappings from the same/other Genesis field, including byte-window endian values, while staying within hardened child-index range.
4. Reduce cost by caching each mnemonic/passphrase root and each account/script node once, then derive candidate leaves. Avoid redoing PBKDF2 and secp256k1 operations inside account and ordering loops.
5. Test the two-key convention explicitly: same mnemonic root with distinct child paths; separate roots from the same entropy; and same BIP48 leaf path on separate roots. Sort public keys per BIP67 where testing a standard BIP48 wallet.
6. Require an exact witness script SHA-256 match. Validate any match independently before calling the puzzle solved.
