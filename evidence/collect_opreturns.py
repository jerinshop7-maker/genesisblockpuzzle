#!/usr/bin/env python3
"""Collect every OP_RETURN payload ever posted to the puzzle escrow address.

Read-only. Fetches the full address history from mempool.space, resolves each
transaction's confirmation status and extracts OP_RETURN / unknown outputs.
"""
import json, subprocess, sys, time, urllib.request

ADDR = "bc1qfkhx02v89u2qyyyljeczw6hu9sr437y44t7ae5yf09thrdukfqesnjg2wj"
API = "https://mempool.space/api"


def get(path, tries=4):
    url = path if path.startswith("http") else API + path
    for i in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=45) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001
            if i == tries - 1:
                raise
            time.sleep(1.5 * (i + 1))
    raise RuntimeError("unreachable")


def history():
    out, cursor, guard = [], None, 0
    while guard < 12:
        guard += 1
        p = f"/address/{ADDR}/txs" + (f"/chain/{cursor}" if cursor else "")
        batch = get(p)
        if not batch:
            break
        out.extend(batch)
        cursor = batch[-1]["txid"]
    seen, uniq = set(), []
    for t in out:
        if t["txid"] not in seen:
            seen.add(t["txid"])
            uniq.append(t)
    return uniq


def hex_to_text(h):
    try:
        b = bytes.fromhex(h)
    except ValueError:
        return h
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return h
    if s.isprintable() or all(c in "\t\n\r" or 32 <= ord(c) < 127 for c in s):
        return s
    return h


def main():
    txs = history()
    rows = []
    for i, t in enumerate(txs, 1):
        st = t.get("status", {})
        height = st.get("block_height")
        outs = []
        for v in t.get("vout", []):
            spk = v.get("scriptpubkey", "")
            ttype = v.get("scriptpubkey_type", "?")
            asm = v.get("scriptpubkey_asm", "")
            if ttype in ("op_return", "nulldata", "nonstandard", "multisig", "v0_p2wsh"):
                outs.append((v.get("value", 0), ttype, spk, asm))
        if not outs:
            continue
        rows.append({
            "n": i,
            "height": height,
            "txid": t["txid"],
            "date": st.get("block_time"),
            "outs": outs,
        })
        sys.stderr.write(f"\r{len(rows)} payload txs / {i} scanned   ")
        time.sleep(0.05)
    sys.stderr.write("\n")

    rows.sort(key=lambda r: (r["height"] if r["height"] else 10**12))
    for r in rows:
        print(f"\n=== #{r['n']} block {r['height']} {r['txid']} ({r['date']})")
        for value, ttype, hx, asm in r["outs"]:
            print(f"  [{ttype} {value} sats] {hex_to_text(hx)}")
            if ttype == "v0_p2wsh":
                print(f"      asm: {asm}")
    print(f"\nTOTAL payload-bearing txs: {len(rows)} / {len(txs)} scanned")
    with open("/tmp/opreturn_scan.json", "w") as f:
        json.dump({"total_txs": len(txs), "payload_txs": rows}, f, indent=1)


if __name__ == "__main__":
    main()
