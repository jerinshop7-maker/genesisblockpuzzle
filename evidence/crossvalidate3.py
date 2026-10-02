#!/usr/bin/env python3
"""Cross-validate engine3 against reference.py, in the same spirit as
crossvalidate.py / crossvalidate_indep.py.

We plant targets: for a chosen (substring_a, substring_b, passphrase,
account, leafcase) we compute the two cosigner pubkeys with reference.py,
build OP_2 <a> <b> OP_2 OP_CHECKMULTISIG, sha256 it, and set that as the
engine's target via ENGINE3_TARGET_HEX. The engine must MATCH. We also
run negative controls against the real escrow target: it must NOT match.
"""
import hashlib, os, random, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reference as R

def b58_decode(s): pass  # not needed

# Build the two substring styles we care about, by slicing GENESIS hex.
GENHEX = bytes.fromhex(R.RAW).hex()
assert GENHEX == bytes.fromhex(R.RAW).hex()

def sha_ent(text: bytes) -> bytes:
    return hashlib.sha256(text).digest()[:16]

def words_for(text: bytes, wl):
    return R.entropy_to_mnemonic(sha_ent(text), wl)

def key_for(text: bytes, passphrase: str, account: int, leaf, hard: bool):
    mn = words_for(text, WL)
    seed = R.mnemonic_to_seed(mn, passphrase)
    m = R.master(seed)
    node = R.derive(m, [0x80000030, 0x80000000, 0x80000000 | account, 0x80000002])
    if leaf:
        path = [(i | 0x80000000) if hard else i for i in leaf]
        node = R.derive(node, path)
    return R.pub(node[0])

def script_hash(k1, k2):
    script = b"\x52" + bytes([33]) + k1 + bytes([33]) + k2 + b"\x52\xae"
    return hashlib.sha256(script).hexdigest()

def engine_job(digests, passes, accounts, leaves):
    buf = []
    for label, data in digests:
        buf.append(f"D {len(data)} {label}\n".encode())
        buf.append(data.hex().encode() + b"\n")
    for p in passes:
        buf.append(f"P {p}\n".encode())
    for a, lab in accounts:
        buf.append(f"A {a} {lab}\n".encode())
    for lab, la, lb, hard in leaves:
        buf.append((f"L {lab} {len(la)} " + " ".join(map(str, la))
                    + f" {len(lb)} " + " ".join(map(str, lb))
                    + (" h" if hard else " nh") + "\n").encode())
    buf.append(b"Q\n")
    return b"".join(buf)

def run_engine(job, target_hex, all_len=False):
    env = dict(os.environ)
    env["ENGINE3_TARGET_HEX"] = target_hex
    if all_len:
        env["ENGINE3_ALLLEN"] = "1"
    proc = subprocess.run([os.path.join(HERE, "engine3")], input=job,
                          stdout=subprocess.PIPE, cwd=HERE, env=env,
                          stderr=subprocess.DEVNULL)
    return proc.stdout.decode(errors="replace")

WL = R.wordlist()
assert len(WL) == 2048

random.seed(7)
# Candidate substrings: even lengths 18..32 from GENHEX.
cands = []
for L in range(18, 33, 2):
    for i in range(0, len(GENHEX) - L + 1, 37):   # stride for planted tests
        cands.append(GENHEX[i:i + L])
random.shuffle(cands)

# Find pairs with EQUAL length for same-length cases.
by_len = {}
for s in cands:
    by_len.setdefault(len(s), []).append(s)

PASSES = ["Hal Finney", "satoshi nakamoto", "HalFinney"]
ACCOUNTS = [2009, 2083236893, 486604799]

planted = 0
targets_found = 0
for (L, group) in sorted(by_len.items()):
    if len(group) < 2:
        continue
    a, b = group[0], group[1]
    passphrase = PASSES[planted % len(PASSES)]
    acct = ACCOUNTS[planted % len(ACCOUNTS)]
    k1 = key_for(a.encode(), passphrase, acct, [0, 0], hard=False)
    k2 = key_for(b.encode(), passphrase, acct, [0, 0], hard=False)
    th = script_hash(k1, k2)
    job = engine_job(
        [("pl_a", a.encode()), ("pl_b", b.encode()), ("pl_other", group[-1].encode() if group[-1] not in (a, b) else b.encode())],
        PASSES,
        [(acct, "planted"), (0, "zero")],
        [("00|00", [0, 0], [0, 0], False)],
    )
    out = run_engine(job, th)
    if out.lstrip().startswith("MATCH"):
        targets_found += 1
        print(f"planted indep-root target L={L} pass={passphrase!r} acct={acct}: FOUND")
    else:
        print(f"planted indep-root target L={L} pass={passphrase!r} acct={acct}: *** MISSING ***")
        print(out[:400])
    planted += 1
    if planted >= 4:
        break

# Same-root two-leaf planted target.
if by_len:
    L = sorted(by_len)[0]
    a = by_len[L][0]
    passphrase = "Hal Finney"
    acct = 2009
    k1 = key_for(a.encode(), passphrase, acct, [0, 0], hard=False)
    k2 = key_for(a.encode(), passphrase, acct, [0, 1], hard=False)
    th = script_hash(k1, k2)
    job = engine_job(
        [("pl_a", a.encode())],
        [passphrase],
        [(acct, "planted")],
        [("00|01", [0, 0], [0, 1], False)],
    )
    out = run_engine(job, th)
    if out.lstrip().startswith("MATCH"):
        targets_found += 1
        print(f"planted same-root 0/0+0/1 target: FOUND")
    else:
        print("planted same-root 0/0+0/1 target: *** MISSING ***")
        print(out[:400])
    planted += 1

# Hardened-leaf planted target (indep, two different digests).
group = next(g for g in by_len.values() if len(g) >= 2)
a, b = group[0], group[1]
passphrase = "halfinney"
acct = 1231006505
k1 = key_for(a.encode(), passphrase, acct, [0, 0], hard=True)
k2 = key_for(b.encode(), passphrase, acct, [0, 0], hard=True)
th = script_hash(k1, k2)
job = engine_job(
    [("pl_a", a.encode()), ("pl_b", b.encode())],
    [passphrase],
    [(acct, "planted")],
    [("00h|00h", [0, 0], [0, 0], True)],
)
out = run_engine(job, th)
print(("planted hardened-leaf indep target: " + ("FOUND" if out.lstrip().startswith("MATCH") else "*** MISSING ***")))
if out.lstrip().startswith("MATCH"):
    targets_found += 1
planted += 1

# Negative control: real escrow target must NOT match on a small job.
real_target = "4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833"
job = engine_job(
    [("g0", GENHEX[100:100 + 24].encode()), ("g1", GENHEX[300:300 + 24].encode())],
    ["Hal Finney"],
    [(2009, "year")],
    [("00|00", [0, 0], [0, 0], False)],
)
out = run_engine(job, real_target)
neg_ok = out.lstrip().startswith("NO_MATCH")
print(f"negative control vs real escrow: {'clean' if neg_ok else '*** FAKE MATCH ***'}")

print(f"planted targets found: {targets_found}/{planted}")
ok = targets_found == planted and neg_ok
print("ENGINE3 CROSSVALIDATION", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
