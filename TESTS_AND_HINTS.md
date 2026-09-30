# Genesis Block Wallet Puzzle — All Hints + All Tests Done

Target: `genesis-block-wallet-puzzle-142ksats`
Escrow: `bc1qfkhx02v89u2qyyyljeczw6hu9sr437y44t7ae5yf09thrdukfqesnjg2wj` (P2WSH, program `4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833`)
Status 2026-09-12: funded-unspent, 168,779 sats, 24 txs, 0 spent. 6 new txs since 2026-09-04 (Q8/A8, Q9/A9 + dust + rule-restatement, blocks 965798-966576).
Oracle: `tools/oracle.py` SELFTEST OK. No spend/broadcast. No MATCH found.

Notation: T = 69B coinbase text, J = 47B headline (T[22:]), S = 77B scriptSig, P = 65B coinbase output pubkey (04||X||Y), X/Y = 32B coordinates (all in FIELDS; my earlier shorthand omitted P — corrected). Pass1/2 tested P raw (modn/slices), X/Y raw BE/LE comp+uncomp, P/X/Y as BIP32 seeds and zero-cc roots, all x214 paths.

---

## PART A — ALL HINTS (author, verbatim, in order)

Announcement — 2026-08-22 19:45, block 963629, `b691de3657880d9a1eabd2783b1a9fa8c5313ced338495bf10e85727012d7a77`:
> "I made a Bitcoin puzzle using information contained in the genesis block created by Satoshi to generate the wallet. The entropy is extremely low. I didn't even need to back anything up. Everything I needed was already in the genesis block. Good luck!"

Hint channel — 2026-08-23 01:51, block 963659, `248f690de194372564baa14e1bebf08154e2f2042ed205baa6157fdc0e3f22ea`:
> "If you have a question, you can include it with a transaction sent directly to this address, and I will reply with a hint. Larger payments receive better hints. Dust transactions will be ignored."

| # | Date (UTC) | Txid | Question asked | Author answer (verbatim) |
|---|---|---|---|---|
| 1 | 2026-08-23 15:43 | `0fb7a2f175dd7f9b8826cf2923ce4fcb56e4c7bfe252903e6dad1f87f177dfe3` | Is the witness script a hash lock, a multisig, or something else? | "The witness script is a multisig." |
| 2 | 2026-08-23 21:08 | `ef63243d374d8eabeac7e17e06cc4b1b672146dc61a8e5180eeac980cec07302` | How many keys, what threshold, and how are the keys derived from genesis? | "Two keys, both required. The rest is for you to derive." |
| 3 | 2026-08-24 07:13 | `82a076b02643372769ac676d260ef4d9854c6bf49370ed61875fc63b8241dcfc` | Are both keys from the same genesis field, and is the function a hash? | "Yes, both keys use the same Genesis field, and there is no hash." |
| 4 | 2026-08-24 14:32 | `ff884832e937f972c92c012ba235ff45b549cd1702dfd02691056da6bc1ff913` | Is the second key derived from the first, or both from genesis independently? | "Both keys are derived independently from Genesis." |
| 5 | 2026-08-24 21:35 | `eb609dfede7f61d3bf9fe79ae48e546c358ebd09c05b3cd64a22433cb784ea86` | Which genesis field, hash, merkle, nonce, time, headline, or pubkey? | "The Genesis Block is public. Which part of it matters is for you to discover." |
| 6 | 2026-08-28 23:15 | `6e94cfcbc1350a138242f97310dfd0280371a0020380cb32b2512337470c1077` | Prize Address? Genesis field 32 bytes or smaller? | "Solve it to find out. Maybe both. If you can't check the Genesis block, you can also use The Times newspaper!" |
| 7 | 2026-08-28 23:50 | `8be479605bc8f2facd2036fd1b7f5cfa3a3f3920eeffee75e0004a2cff4d25d6` | Can you give any hint about derivation offset/rule? | "Derivation rule: root -> multisig -> mainnet -> genesis_data -> script_type" |
| 8 | 2026-09-06 15:51, block 965798, `68e79190221d2b73089b523f7f5af2a11838339a788239f4eee30d6c1d4502e7` | "give another hint" (1,000 sats dust, asker `bc1q3csg…krkf`) | — (no answer; prompted rule-restatement #9) |
| 9 | 2026-09-06 19:41, block 965824, `64385a0cc5c4c712d1d9d8628e1e00364310d9ba50536ccd23c71b49ae66b96b` | — (author rule-restatement, spends own change `8be479…:2`) | "I can't give hints without a question. Low-value transactions get bad hints; dust will be ignored." |
| 10 | 2026-09-10 20:47, block 966402, `75daa8e824abba4fe1b1a4b12f923b50291fab98743edaa1f03ef8c50bb70552` | "Root = Times text as BIP32 seed? BIP39? raw key? genesis_data = BIP48 account?" (10,000 sats, player 3 `bc1qkjsfj…wmx`) | — (answered #11) |
| 11 | 2026-09-10 21:33, block 966409, `cb47c7a73c1aaa11bfe0edce41c2ef7c9c1fec1478efd15e40b226eb502dcc18` | — (author answer, spends own change `64385a…:2`) | "root = the master key derived from the BIP39 seed; genesis_data = some data from the genesis block used as the BIP48 account number." |
| 12 | 2026-09-11 21:25, block 966565, `6497aef4be0d5be68644296d5fcdb709c66bb20db5972f4e53f90836e27862fe` | "BIP39 entropy: genesis bytes/puzzle text/img/other? words 12/24? passphrase Y/N?" (10,000 sats, player 3) | — (answered #13) |
| 13 | 2026-09-11 23:26, block 966576, `f8f04fc04e2c4f34dc2264f85ff7944c6aa822446bc4cc082e95a52aed5c2a4c` | — (author answer, spends own change `cb47c7a…:2`) | "BIP39: 12 words; Passphrase: Y; Entropy: The data needed to solve it is publicly available in the genesis block." |

Reading: 1 fixes 2-of-2 P2WSH (`OP_2 <A><B> OP_2 CHECKMULTISIG`, both orders). 3 fixes same-field + no-hash. 4 rules out key-chaining. 6 means newspaper suffices → genesis_data must be Times-visible (counts/lengths/date/headline), and "both" = 32B + smaller. 7 is BIP48-shaped (`m/48'/0'/account'/script_type'`); literal G-account reading is killed (below).
New (2026-09-06/10/11, attribution via author-change linkage): 8 = dust ignored. 9 = author restates channel rules. 11 CONFIRMS root = BIP32-master(BIP39-seed) and genesis_data = BIP48 account number (kills raw-key, raw-BIP32-seed, hashed-root constructions as the root step). 13 CONFIRMS BIP39 12 words (= 16B entropy only), passphrase non-empty, entropy = public genesis-block data. Joint force: `m = master(PBKDF2(mnemonic(16B genesis entropy), pp != ""))`, keys = two leaves under ONE `m/48'/0'/ACC'/2'` (singular "the account" + hint 4). Open unknowns: exact 16B entropy, exact passphrase, exact ACC. Escrow 2026-09-12: 24 txs / 168,779 sats / 0 spent (still open).

---