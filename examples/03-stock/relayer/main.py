"""
03-stock Python Relayer Service — Web2 Mock API → Solana Oracle Bridge.

Simulates traditional finance APIs:
  - Bloomberg B-PIPE / Alpaca Market Data
  - DTCC Corporate Actions
  - BNY Mellon Custody Ledger

Polls mock APIs and writes market status changes to Solana chain.

Usage:
    python relayer/main.py
    → Starts HTTP server on port 8800

Endpoints:
    GET /api/v1/stock/{ticker}/quote       — Market data + status
    GET /api/v1/corporate-actions/{ticker} — Stock splits, dividends
    GET /api/v1/custody/vault              — Proof of Reserve data
"""
import json
import time
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# ============================================================
# Simulated Market Data
# ============================================================

STOCKS = {
    "AAPL": {"ticker": "AAPL", "name": "Apple Inc.", "price": 175.42,
             "previous_close": 174.89, "total_shares": 15_750_000_000},
    "TSLA": {"ticker": "TSLA", "name": "Tesla Inc.", "price": 248.50,
             "previous_close": 250.11, "total_shares": 3_189_000_000},
}

CORPORATE_ACTIONS = [
    {"action_id": "CA-2026-0091", "ticker": "TSLA", "action_type": "STOCK_SPLIT",
     "ratio": "5:1", "effective_date": "2026-06-01"},
]

CUSTODY = {
    "custodian_bank": "Demo BNY Mellon",
    "vault_account_id": "VAULT-9921-USD",
    "total_backed_shares": 10000,
    "minted_token_supply": 10_000_000_000,
    "last_audit_timestamp": int(time.time()),
}


def get_market_status():
    """Determine market status based on simulated NYSE hours."""
    now = datetime.now(timezone.utc)
    et_hour = (now.hour - 4) % 24  # Rough ET conversion
    if 9 <= et_hour < 16:
        return "OPEN"
    elif 4 <= et_hour < 9:
        return "PRE_MARKET"
    return "CLOSED"


def get_stock_quote(ticker):
    """GET /api/v1/stock/{ticker}/quote — Bloomberg/Alpaca-style market feed."""
    stock = STOCKS.get(ticker)
    if not stock:
        return None
    # Simulate price movement
    price = stock["price"] + (__import__("random").random() - 0.5) * 2.0
    return {
        "ticker": ticker, "current_price": round(price, 2),
        "market_status": get_market_status(),
        "last_trade_timestamp": int(time.time()),
        "timezone": "America/New_York",
    }


def get_corporate_actions(ticker):
    """GET /api/v1/corporate-actions/{ticker} — DTCC-style corp actions."""
    return [a for a in CORPORATE_ACTIONS if a["ticker"] == ticker]


def get_custody():
    """GET /api/v1/custody/vault — BNY Mellon custody ledger."""
    return CUSTODY


# ============================================================
# Relayer — polls APIs and writes to Solana (simulated)
# ============================================================

class StockRelayer:
    def __init__(self):
        self.last_status = {}
        self.running = False

    def start(self):
        self.running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        print("Stock Relayer started (polling every 30s)")

    def _loop(self):
        while self.running:
            for ticker in STOCKS:
                status = get_market_status()
                if self.last_status.get(ticker) != status:
                    old = self.last_status.get(ticker, "?")
                    self.last_status[ticker] = status
                    print(f"\n{'='*50}")
                    print(f"  Market Status: {ticker}  {old} → {status}")
                    print(f"  → Would call: update_market_status({'OPEN':0,'CLOSED':1,'PRE_MARKET':2}[status])")
                    print(f"{'='*50}\n")
            time.sleep(30)

    def stop(self):
        self.running = False


# ============================================================
# HTTP Server
# ============================================================

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        data = None

        if "/stock/" in path and "/quote" in path:
            ticker = path.split("/stock/")[1].split("/quote")[0]
            data = get_stock_quote(ticker)
        elif "/corporate-actions/" in path:
            ticker = path.split("/corporate-actions/")[1]
            data = get_corporate_actions(ticker)
        elif "/custody/" in path:
            data = get_custody()
        elif path == "/health":
            data = {"status": "ok", "service": "stock-relayer"}

        if data is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error":"not found"}')
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def log_message(self, format, *args):
        print(f"[{datetime.now():%H:%M:%S}] {args[0]}")


def run(port=8800):
    print(f"\n{'='*60}")
    print(f"  03-stock Relayer API Server")
    print(f"  http://localhost:{port}")
    print(f"  Endpoints:")
    print(f"    GET /api/v1/stock/AAPL/quote")
    print(f"    GET /api/v1/corporate-actions/AAPL")
    print(f"    GET /api/v1/custody/vault")
    print(f"    GET /health")
    print(f"{'='*60}\n")

    relayer = StockRelayer()
    relayer.start()

    server = HTTPServer(("0.0.0.0", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        relayer.stop()
        server.shutdown()
        print("\nRelayer stopped.")


if __name__ == "__main__":
    run(8800)