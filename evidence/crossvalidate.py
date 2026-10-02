#!/usr/bin/env python3
"""Cross-validate the C engine against the proven Python reference.

The reference in evidence/reference.py is pinned to byte-identical BitcoinJS
xpubs and the official BIP39 vectors. Here we generate random entropy/
passphrase/account/leaf combinations, compute the expected witness-script
hash with the reference, and require the C engine to agree via a planted
target. Any disagreement is a fatal engine bug.
"""
import hashlib, os, random, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reference as R

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "engine")
WORDLIST = os.path.join(HERE, "english.txt")


def build_input(entropy_src: bytes, passes, accounts, leaves):
    out = []
    out.append(f"D {len(entropy_src)} test\n".encode())
    out.append(entropy_src.hex().encode() + b"\n")
    for p in passes:
        out.append(f"P {p}\n".encode())
    for a, lab in accounts:
        out.append(f"A {a} {lab}\n".encode())
    for lab, la, lb in leaves:
        out.append((f"L {lab} {len(la)} " + " ".join(map(str, la)) + f" {len(lb)} "
                    + " ".join(map(str, lb)) + "\n").encode())
    out.append(b"Q\n")
    return b"".join(out)


def reference_script_hash(entropy_src: bytes, passphrase: str, account: int, la, lb):
    ent = hashlib.sha256(entropy_src).digest()[:16]
    words = R.entropy_to_mnemonic(ent, R.wordlist())
    seed = R.mnemonic_to_seed(words, passphrase)
    root = R.master(seed)
    acct = R.derive(root, [0x80000030, 0x80000000, 0x80000000 | account, 0x80000002])
    p1 = R.pub(R.derive(acct, [0x80000000 | i for i in la])[0])
    p2 = R.pub(R.derive(acct, [0x80000000 | i for i in lb])[0])
    script = b"\x52\x21" + p1 + b"\x21" + p2 + b"\x52\xae"
    return hashlib.sha256(script).hexdigest(), words, ent


import re


def run_with_target(target_hex, entropy_src, passes, accounts, leaves):
    """Run the engine against an arbitrary target by patching TARGET_HEX.

    The substitution is regex-based so it always matches, even if engine.c
    itself is edited between runs. A stale probe binary silently turning a
    planted target into the real one would fake a pass.
    """
    exe = os.path.join("/tmp", "engine_probe")
    src = open(os.path.join(HERE, "engine.c")).read()
    patched, nsub = re.subn(r'static const char \*TARGET_HEX = "[0-9a-fA-F]{64}";',
                            f'static const char *TARGET_HEX = "{target_hex}";', src)
    if nsub != 1:
        raise RuntimeError(f"TARGET_HEX substitution matched {nsub} times, expected 1")
    cpath = "/tmp/engine_probe.c"
    open(cpath, "w").write(patched)
    if os.path.exists(exe):
        os.remove(exe)
    subprocess.run(["gcc", "-O2", "-o", exe, cpath, "-lcrypto", "-lpthread"],
                   check=True, capture_output=True)
    p = subprocess.run([exe], input=build_input(entropy_src, passes, accounts, leaves),
                       capture_output=True, cwd=HERE)
    return p.stdout.decode()


def main():
    if not os.path.exists(ENGINE):
        print("engine binary missing; build first")
        return 1
    rng = random.Random(20260930)
    trials = 0
    for t in range(12):
        src = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 60)))
        passphrase = rng.choice(["Hal Finney", "halfinney", "Satoshi Nakamoto", "x", "a b c"])
        account = rng.randrange(0, 1 << 20)
        la = [rng.randrange(0, 4)]
        lb = [rng.randrange(0, 4)]
        leaves = [(f"t{t}", la, lb)]
        accounts = [(account, "rnd")]
        want, words, ent = reference_script_hash(src, passphrase, account, la, lb)
        got = run_with_target(want, src, [passphrase], accounts, leaves)
        trials += 1
        # "NO_MATCH" contains "MATCH", so test for a real hit explicitly.
        if not got.lstrip().startswith("MATCH"):
            print(f"FAIL trial {t}: engine missed a planted target")
            print("  expected words:", words)
            print("  engine out:", got.strip()[:400])
            return 1
    # Negative control: the real target must NOT be found on random inputs.
    for t in range(5):
        src = bytes(rng.randrange(256) for _ in range(rng.randrange(4, 40)))
        out = run_with_target("4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833",
                              src, ["Hal Finney"], [(0, "zero")], [("c", [0], [1])])
        if out.lstrip().startswith("MATCH"):
            print("FAIL: false positive on the real target")
            print("  src:", src.hex())
            print("  engine output:\n", out)
            return 1
    print(f"CROSSVALIDATION OK: {trials} planted targets found, 5 negative controls clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
