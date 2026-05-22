# racepwn

HTTP/2 single-packet attack harness for race condition exploitation, implementing Kettle’s last-byte synchronization.

## How It Works

True single-packet timing requires frame-level HTTP/2 control — high-level clients (httpx, requests) send `END_STREAM` immediately per request, producing multiple TCP packets across random time windows that lose to network jitter.

racepwn uses the raw `h2` library over a manual TLS socket:

1. Open **one** HTTP/2 connection (ALPN-negotiated)
1. Open N streams — send HEADERS + body **minus the final byte**, `END_STREAM` withheld
1. Brief pause so the server buffers all partial requests
1. Concatenate every stream’s final byte + `END_STREAM` into **one buffer**, flush with a single `sendall()`
1. All N requests complete within ~1ms server-side

`TCP_NODELAY = 1` disables Nagle’s algorithm so the final blast leaves as one tight packet.

## Install

```bash
pip install h2
```

## Usage

```bash
# Promo code redemption race
python3 racepwn.py --url https://target.com/redeem \
  --data "code=PROMO50" \
  --headers "Cookie: session=abc123" \
  --requests 30

# Custom method + stream count
python3 racepwn.py --url https://target.com/api/withdraw \
  --method POST \
  --data "amount=100" \
  --requests 50 \
  --output withdraw_race.json
```

## Output

- **Response distribution table** — groups responses by `(status, body_length)` signature
- **OUTLIER ← RACE HIT** flag on any minority response group (e.g. 29× “already used” + 1× “success”)
- **Arrival window metrics** — min/max/avg/spread timing across streams
- **Outlier body dump** — full differing response printed when a race hit is detected
- Per-request timing in JSON

## Reading Results

|Outcome                |Interpretation                                           |
|-----------------------|---------------------------------------------------------|
|All responses identical|No race window, or window too narrow — try more streams  |
|One minority response  |**Race hit** — the operation executed before state locked|
|Multiple variants      |Inconsistent backend state — investigate each            |

## Requirements

- Target **must support HTTP/2** (verified via ALPN; tool aborts if not)
- HTTPS only (single-packet sync needs TLS+ALPN)
- For HTTP/1.1-only targets, the last-byte-sync variant requires N separate connections — out of scope for this h2-focused build

## Notes

- 30 streams is a good default; flow-control windows are respected for non-trivial bodies
- Timing spread under ~2ms indicates a tight single-packet send
- Limit-overrun, double-spend, coupon reuse, and TOCTOU bugs are the classic targets

## Author

[zwanski](https://zwanski.bio) — Zwanski Tech / Tinosoft Informatique
