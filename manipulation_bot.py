import time
import json
import requests
from datetime import datetime
from dateutil import parser

# Pyth Hermes Price Feed IDs
PYTH_FEED_IDS = {
    "btc": "e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43",
    "eth": "ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fc0ace",
    "sol": "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d",
    "bnb": "2f958174490c92e1f4a9e6a239e03c026b2b8539096db37603f9050d2e825026",
    "xrp": "ec5d2050841d9550325c851681a9ad2630079e14e76865657198852e26aa4d70"
}

# Minimum spot price change thresholds to trigger analysis
MIN_SPOT_DIFFS = {
    "btc": 0.50,
    "eth": 0.15,
    "sol": 0.05,
    "bnb": 0.10,
    "xrp": 0.01
}

def get_pyth_prices(feed_id, start_ts):
    """Fetches opening spot price at start_ts and live spot price from Pyth Hermes API."""
    try:
        live_url = f"https://hermes.pyth.network/v2/updates/price/latest?ids[]={feed_id}"
        r_live = requests.get(live_url, timeout=4)
        live_price = None
        if r_live.status_code == 200:
            parsed = r_live.json().get("parsed", [])
            if parsed:
                p_obj = parsed[0].get("price", {})
                live_price = int(p_obj.get("price", 0)) * (10 ** int(p_obj.get("expo", 0)))
                
        hist_url = f"https://hermes.pyth.network/v2/updates/price/{start_ts}?ids[]={feed_id}"
        r_hist = requests.get(hist_url, timeout=4)
        start_price = None
        if r_hist.status_code == 200:
            parsed = r_hist.json().get("parsed", [])
            if parsed:
                p_obj = parsed[0].get("price", {})
                start_price = int(p_obj.get("price", 0)) * (10 ** int(p_obj.get("expo", 0)))
                
        return start_price, live_price
    except Exception as e:
        print(f"[PYTH ERROR] {e}", flush=True)
        return None, None

def check_manipulation(coins=["btc"]):
    """
    Scans Polymarket 5m markets for specified coins and detects spot-odds divergence.
    Returns a list of detected anomaly dictionary objects.
    """
    now_ts = int(time.time())
    current_interval = (now_ts // 300) * 300
    detected_anomalies = []
    
    for coin in coins:
        coin_lower = coin.lower()
        feed_id = PYTH_FEED_IDS.get(coin_lower)
        if not feed_id:
            continue
            
        slug = f"{coin_lower}-updown-5m-{current_interval}"
        url = f"https://gamma-api.polymarket.com/markets?slug={slug}"
        
        try:
            r = requests.get(url, timeout=4)
            if r.status_code != 200:
                continue
            data = r.json()
            if not data or not isinstance(data, list):
                continue
                
            market = data[0]
            cond_id = market.get("conditionId")
            title = market.get("question") or f"{coin.upper()} Up or Down 5m"
            end_date_str = market.get("endDate")
            
            if not end_date_str:
                continue
                
            end_ts = int(parser.isoparse(end_date_str).timestamp())
            start_ts = end_ts - 300
            remaining_seconds = end_ts - now_ts
            
            # Scan window: 15s to 285s remaining (ignores 15s settlement window)
            if remaining_seconds < 15 or remaining_seconds > 285:
                continue
                
            start_spot, live_spot = get_pyth_prices(feed_id, start_ts)
            if start_spot is None or live_spot is None:
                continue
                
            spot_diff = live_spot - start_spot
            required_min_diff = MIN_SPOT_DIFFS.get(coin_lower, 0.50)
            if abs(spot_diff) < required_min_diff:
                continue
                
            spot_is_down = spot_diff < 0
            spot_is_up = spot_diff > 0
            
            # Map UP/DOWN to correct outcome index
            outcomes = market.get("outcomes", ["Up", "Down"])
            if isinstance(outcomes, str):
                try: outcomes = json.loads(outcomes)
                except: outcomes = ["Up", "Down"]
                
            up_idx, down_idx = 0, 1
            for i, o in enumerate(outcomes):
                if str(o).lower() == "up":
                    up_idx = i
                elif str(o).lower() == "down":
                    down_idx = i
                    
            outcome_prices_raw = market.get("outcomePrices")
            up_price, down_price = None, None
            if outcome_prices_raw:
                if isinstance(outcome_prices_raw, str):
                    try: outcome_prices = json.loads(outcome_prices_raw)
                    except: outcome_prices = []
                else:
                    outcome_prices = outcome_prices_raw
                if len(outcome_prices) >= 2:
                    try:
                        up_price = float(outcome_prices[up_idx])
                        down_price = float(outcome_prices[down_idx])
                    except Exception:
                        pass
                        
            if up_price is None or down_price is None:
                continue
                
            # Filter extreme/resolved markets (one side >= 97% or <= 3%)
            if up_price >= 0.97 or down_price >= 0.97 or up_price <= 0.03 or down_price <= 0.03:
                continue
                
            anomaly_type = None
            favored_dir = None
            
            # 1. Direct Divergence (Spot DOWN but UP token >= 48¢ OR Spot UP but DOWN token >= 48¢)
            if spot_is_down and up_price >= 0.48:
                anomaly_type = "PUMP_MANIPULATION"
                favored_dir = "UP"
            elif spot_is_up and down_price >= 0.48:
                anomaly_type = "DUMP_MANIPULATION"
                favored_dir = "DOWN"
                
            # 2. Stubborn Resistance (Spot dropped/pumped, but token refuses to drop below 45¢)
            elif spot_is_down and up_price >= 0.45:
                anomaly_type = "PUMP_RESISTANCE"
                favored_dir = "UP"
            elif spot_is_up and down_price >= 0.45:
                anomaly_type = "DUMP_RESISTANCE"
                favored_dir = "DOWN"
                
            if anomaly_type:
                anomaly_data = {
                    "timestamp": now_ts,
                    "datetime": datetime.utcnow().isoformat() + "Z",
                    "coin": coin.upper(),
                    "market_slug": slug,
                    "market_title": title,
                    "condition_id": cond_id,
                    "remaining_seconds": remaining_seconds,
                    "anomaly_type": anomaly_type,
                    "favored_direction": favored_dir,
                    "start_spot": start_spot,
                    "live_spot": live_spot,
                    "spot_diff": spot_diff,
                    "spot_status": "UP" if spot_is_up else "DOWN",
                    "up_price": up_price,
                    "down_price": down_price,
                    "favored_price_cents": int(round(up_price * 100)) if favored_dir == "UP" else int(round(down_price * 100))
                }
                detected_anomalies.append(anomaly_data)
                
        except Exception as e:
            print(f"[SCANNER ERROR] {slug}: {e}", flush=True)
            
    return detected_anomalies

def run_scanner(coins=["btc"], interval_seconds=10, signal_callback=None):
    """
    Main loop running the manipulation scanner every interval_seconds.
    signal_callback: A function that gets called whenever a signal is detected.
    """
    print(f"[INFO] 🚀 Manipulation Scanner Started for coins: {coins} (Cycle: {interval_seconds}s)", flush=True)
    alerted_keys = set()
    
    while True:
        try:
            anomalies = check_manipulation(coins=coins)
            for signal in anomalies:
                key = f"{signal['market_slug']}:{signal['anomaly_type']}"
                if key not in alerted_keys:
                    alerted_keys.add(key)
                    print(f"\n[ALERT] 🚨 {signal['anomaly_type']} | {signal['coin']} | Spot Diff: ${signal['spot_diff']:+.2f} | {signal['favored_direction']}: {signal['favored_price_cents']}¢", flush=True)
                    print(json.dumps(signal, indent=2), flush=True)
                    
                    if signal_callback:
                        try:
                            signal_callback(signal)
                        except Exception as cb_err:
                            print(f"[CALLBACK ERROR] {cb_err}", flush=True)
        except Exception as e:
            print(f"[LOOP ERROR] {e}", flush=True)
            
        time.sleep(interval_seconds)

if __name__ == "__main__":
    # Example standalone execution:
    def example_bot_handler(signal):
        print(f"--> Automated Bot Triggered: Buying {signal['favored_direction']} on {signal['market_slug']}!")
        
    run_scanner(coins=["btc"], interval_seconds=10, signal_callback=example_bot_handler)
