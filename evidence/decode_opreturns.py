#!/usr/bin/env python3
"""Decode every OP_RETURN payload on the puzzle escrow, in block order.

Read-only. Uses the mempool.space address history and prints a clean,
readable transcript so the clue sequence can be re-read end to end.
"""
import binascii, json, sys, time, urllib.request

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
    seen, uniq = set(), []
    for t in out:
        if t["txid"] not in seen:
            seen.add(t["txid"])
            uniq.append(t)
    return uniq


def pushdata(hexs):
    """Best-effort decode of a scriptPubKey into readable text."""
    try:
        b = bytes.fromhex(hexs)
    except ValueError:
        return hexs, []
    if not b or b[0] != 0x6A:  # OP_RETURN
        return None, []
    i, chunks = 1, []
    while i < len(b):
        op = b[i]
        if op < 0x4C:  # direct push
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
    def show(c):
        try:
            s = c.decode("utf-8")
            if all(ch in "\t\n\r" or 32 <= ord(ch) < 127 for ch in s):
                return s
        except UnicodeDecodeError:
            pass
        return None
    texts = [show(c) for c in chunks]
    if all(t is None for t in texts):
        texts = ["0x" + c.hex() for c in chunks]
    return "\n".join(texts), chunks


def main():
    txs = history()
    rows = []
    for t in txs:
        st = t.get("status", {})
        for v in t.get("vout", []):
            if v.get("scriptpubkey_type") == "op_return":
                text, raw = pushdata(v["scriptpubkey"])
                if text is None:
                    continue
                rows.append({
                    "height": st.get("block_height"),
                    "time": st.get("block_time"),
                    "txid": t["txid"],
                    "sats": v.get("value", 0),
                    "text": text,
                    "raw": [c.hex() for c in raw],
                    "in_spent": None,
                })
        sys.stderr.write(".")
    sys.stderr.write("\n")
    rows.sort(key=lambda r: (r["height"] if r["height"] else 10**12))
    for r in rows:
        print(f"\n########## block {r['height']}  {r['txid']}  ({r['sats']} sats)")
        print(r["text"])
        if all(len(x) > 40 and all(ch in "0123456789+/=" for ch in x) for x in r["raw"]):
            print("   [base64 ciphertext, " + ",".join(str(len(x)) for x in r["raw"]) + " chars]")
    print(f"\n\nTOTAL op_return outputs: {len(rows)} over {len(txs)} txs")


if __name__ == "__main__":
    main()
