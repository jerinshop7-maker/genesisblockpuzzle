#!/usr/bin/env python3
"""Classify each escrow OP_RETURN as author reply or solver question.

The author funds the escrow and answers by spending their own change, so the
author's replies are the ones that receive the escrow's own outputs. This is
an attribution heuristic for reading the transcript, not a proof of identity.
"""
import json, sys, time, urllib.request

ADDR = "bc1qfkhx02v89u2qyyyljeczw6hu9sr437y44t7ae5yf09thrdukfqesnjg2wj"
API = "https://mempool.space/api"


def get(path, tries=4):
    url = path if path.startswith("http") else API + path
    for i in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=45) as r:
                return json.load(r)
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(1.5 * (i + 1))


def history():
    out, cursor, guard = [], None, 0
    while guard < 15:
        guard += 1
        p = f"/address/{ADDR}/txs" + (f"/chain/{cursor}" if cursor else "")
        batch = get(p)
        if not batch:
            break
        out.extend(batch)
        cursor = batch[-1]["txid"]
    return out


def pushdata(hexs):
    b = bytes.fromhex(hexs)
    if not b or b[0] != 0x6A:
        return None
    i, chunks = 1, []
    while i < len(b):
        op = b[i]
        if op < 0x4C:
            ln, i = op, i + 1
        elif op == 0x4C:
            ln, i = b[i + 1], i + 2
        elif op == 0x4D:
            ln, i = int.from_bytes(b[i + 1:i + 3], "little"), i + 3
        elif op == 0x4E:
            ln, i = int.from_bytes(b[i + 1:i + 5], "little"), i + 5
        else:
            break
        chunks.append(b[i:i + ln])
        i += ln
    out = []
    for c in chunks:
        try:
            s = c.decode("utf-8")
            out.append(s if all(ch in "\t\n\r" or 32 <= ord(ch) < 127 for ch in s) else "0x" + c.hex())
        except UnicodeDecodeError:
            out.append("0x" + c.hex())
    return "\n".join(out)


def main():
    txs = history()
    rows = []
    for t in txs:
        st = t.get("status", {})
        texts = [pushdata(v["scriptpubkey"]) for v in t.get("vout", [])
                 if v.get("scriptpubkey_type") == "op_return"]
        texts = [x for x in texts if x]
        if not texts:
            continue
        ins = [vin.get("prevout", {}) or {} for vin in t.get("vin", [])]
        # A change output back to the escrow in the same tx that carries a
        # question is the author's reply pattern.
        from_escrow = sum(1 for p in ins if p.get("scriptpubkey_address") == ADDR)
        to_escrow = sum(1 for v in t.get("vout", [])
                        if v.get("scriptpubkey_address") == ADDR)
        rows.append({
            "h": st.get("block_height"), "txid": t["txid"],
            "in_escrow": from_escrow, "out_escrow": to_escrow,
            "vins": len(t.get("vin", [])),
            "text": "\n".join(texts),
        })
    rows.sort(key=lambda r: (r["h"] if r["h"] else 10**12))
    for r in rows:
        tag = "SELF-CHANGE" if r["in_escrow"] else "INCOMING  "
        print(f"\n##### {r['h']} {r['txid'][:16]} vin={r['vins']} "
              f"fromEscrow={r['in_escrow']} toEscrow={r['out_escrow']} {tag}")
        print(r["text"][:1400])


if __name__ == "__main__":
    main()
