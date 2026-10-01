#!/usr/bin/env python3
"""Validate the independent-root (two-cosigner) mode of the C engine.

Same approach as crossvalidate.py: plant a target computed by the proven
Python reference, then require the engine to find it. Targets are built from
two DIFFERENT passphrases at the SAME BIP48 path, which is the shape the
independent-root model predicts.
"""
import hashlib, os, random, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reference as R

HERE = os.path.dirname(os.path.abspath(__file__))
WORDLIST = os.path.join(HERE, "english.txt")
SRC = os.path.join(HERE, "engine.c")


def build_input(src, passes, accounts, leaves):
    out = []
    out.append(f"D {len(src)} indep\n".encode())
    out.append(src.hex().encode() + b"\n")
    for p in passes:
        out.append(f"P {p}\n".encode())
    for a, lab in accounts:
        out.append(f"A {a} {lab}\n".encode())
    for lab, la, lb in leaves:
        out.append((f"L {lab} {len(la)} " + " ".join(map(str, la))
                    + f" {len(lb)} " + " ".join(map(str, lb)) + "\n").encode())
    out.append(b"Q\n")
    return b"".join(out)


def ref_hash(src, pass_a, pass_b, account, leaf):
    """Witness-script hash for two roots, key order exactly as (a, b)."""
    ent = hashlib.sha256(src).digest()[:16]
    words = R.entropy_to_mnemonic(ent, R.wordlist())
    out = []
    for p in (pass_a, pass_b):
        seed = R.mnemonic_to_seed(words, p)
        node = R.master(seed)
        for i in (0x80000030, 0x80000000, 0x80000000 | account, 0x80000002):
            node = R.ckd(node, i)
        for i in leaf:
            node = R.ckd(node, i | 0x80000000)
        out.append(R.pub(node[0]))
    script = b"\x52\x21" + out[0] + b"\x21" + out[1] + b"\x52\xae"
    return hashlib.sha256(script).hexdigest()


def ref_keys(src, pass_a, pass_b, account, leaf):
    ent = hashlib.sha256(src).digest()[:16]
    words = R.entropy_to_mnemonic(ent, R.wordlist())
    out = []
    for p in (pass_a, pass_b):
        node = R.master(R.mnemonic_to_seed(words, p))
        for i in (0x80000030, 0x80000000, 0x80000000 | account, 0x80000002):
            node = R.ckd(node, i)
        for i in leaf:
            node = R.ckd(node, i | 0x80000000)
        out.append(R.pub(node[0]))
    return out


def run(target_hex, src, passes, accounts, leaves):
    exe = "/tmp/engine_indep"
    text = open(SRC).read()
    patched, n = re.subn(r'static const char \*TARGET_HEX = "[0-9a-fA-F]{64}";',
                         f'static const char *TARGET_HEX = "{target_hex}";', text)
    if n != 1:
        raise RuntimeError(f"TARGET_HEX matched {n} times")
    open("/tmp/engine_indep.c", "w").write(patched)
    if os.path.exists(exe):
        os.remove(exe)
    subprocess.run(["gcc", "-O2", "-o", exe, "/tmp/engine_indep.c", "-lcrypto", "-lpthread"],
                   check=True, capture_output=True)
    env = dict(os.environ, ENGINE_INDEP="1")
    p = subprocess.run([exe], input=build_input(src, passes, accounts, leaves),
                       capture_output=True, cwd=HERE, env=env)
    return p.stdout.decode(errors="replace")


def main():
    rng = random.Random(4242)
    ok = 0
    for t in range(10):
        src = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40)))
        pool = ["Hal Finney", "halfinney", "Satoshi Nakamoto", "Finney", "hal", "satoshi"]
        ia, ib = sorted(rng.sample(range(len(pool)), 2))
        pa, pb = pool[ia], pool[ib]
        account = rng.randrange(0, 1 << 18)
        # Occasionally use the degenerate zero-length leaf (both keys are the
        # account node itself), which is only meaningful with two roots.
        leaf = [] if t % 5 == 0 else [rng.randrange(0, 3)]
        # Build the target in the same key order the engine's pa<pb loop yields.
        ka, kb = ref_keys(src, pa, pb, account, leaf)
        want = ref_hash(src, pa, pb, account, leaf)
        got = run(want, src, pool, [(account, "rnd")], [("both", leaf, leaf)])
        if not got.lstrip().startswith("MATCH"):
            print(f"FAIL trial {t}: independent-root mode missed the planted target")
            print("  pass_a", pa, "pass_b", pb, "account", account, "leaf", leaf)
            print("  key_a", ka.hex(), "key_b", kb.hex())
            print("  out:", got.strip()[:300])
            return 1
        ok += 1
    # Negative control on the real target.
    for t in range(3):
        src = bytes(rng.randrange(256) for _ in range(rng.randrange(4, 30)))
        out = run("4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833",
                  src, ["Hal Finney", "halfinney"], [(0, "z")], [("b", [0], [0])])
        if out.lstrip().startswith("MATCH"):
            print("FAIL: false positive in independent-root mode")
            return 1
    print(f"INDEP CROSSVALIDATION OK: {ok} planted two-root targets found, 3 negative controls clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
