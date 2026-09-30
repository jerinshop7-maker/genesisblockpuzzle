# Search status — 2026-09-25 UTC

The same-root standard BIP48 sweep launched during the prior continuation was interrupted before it printed a completion result. Its initialized scope was:

- 153 recorded Genesis representations as `SHA256(input)[:16]` entropy candidates;
- 41 basic name/passphrase variants;
- 123 account candidates;
- six standard leaf-pair layouts;
- sorted pubkey order, compressed SEC keys.

There was no `MATCH` or `NO_MATCH` result. Treat the run as incomplete and do not count it as negative evidence. The expensive command should not be repeated unchanged; optimize/cache BIP32 account nodes and add progress/checkpoint output first.

New chain clue: block 968519 says the solver privately asked for both cosigners' master fingerprints and derivation paths, and the author withheld them as too revealing. This strengthens key-origin/path discovery as the next information priority but gives no actual origin values.

## Completed focused representation test

Added explicit bitstring-to-ASCII candidates (`byte -> eight ASCII 0/1 characters`) because the hint names binary separately from hex/decimal/ASCII. Tested the bitstring encodings of the raw Genesis block, 80-byte header, coinbase transaction, scriptSig, Merkle root, time, bits, nonce, full Times text, and headline. Used SHA-256 first 16 bytes as BIP39 entropy, 41 basic name/passphrase variants, 132 account candidates, six standard leaf-pair layouts, compressed keys, and sorted key order. Result: `NO_MATCH`, 324,720 script comparisons. This closes the bitstring-ASCII representation gap for those ten selected sources only; it does not test every contiguous range or every derivation convention.

## Next high-value derivation model

The disclosure of two cosigner master fingerprints makes independent cosigner roots worth testing explicitly. A single shared BIP39 entropy candidate plus distinct passphrase formats can yield distinct BIP39 seeds. Test this first for the exact Times text/headline sources and SHA-256-first-16 entropy, with same BIP48 leaf path on each root; keep this separate from the already-tested same-root/different-leaf model.
