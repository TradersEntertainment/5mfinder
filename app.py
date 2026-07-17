import os
import re
import time
import requests
import threading
import json
from flask import Flask, request, jsonify, render_template
from web3 import Web3

# Try importing Geth PoA middleware across all possible web3.py versions
poa_middleware = None
try:
    from web3.middleware import geth_poa_middleware as poa_middleware
except ImportError:
    try:
        from web3.middleware.geth_poa import geth_poa_middleware as poa_middleware
    except ImportError:
        try:
            from web3.middleware import ExtraDataToPOAMiddleware as poa_middleware
        except ImportError:
            try:
                from web3.middleware import extra_data_rpc_middleware as poa_middleware
            except ImportError:
                pass

app = Flask(__name__)

# ----------------- BLACKLIST MANAGEMENT SYSTEM -----------------
BLACKLIST_FILE = os.environ.get("BLACKLIST_FILE", "blacklist.json")

def load_blacklist():
    # Automatically create parent directories if custom path is configured
    parent_dir = os.path.dirname(BLACKLIST_FILE)
    if parent_dir and not os.path.exists(parent_dir):
        try:
            os.makedirs(parent_dir, exist_ok=True)
        except Exception:
            pass

    if not os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, "w") as f:
                json.dump([], f)
        except Exception:
            pass
        return []
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_blacklist(lst):
    try:
        with open(BLACKLIST_FILE, "w") as f:
            json.dump(lst, f)
    except Exception as e:
        print(f"[ERROR] Failed to save blacklist: {e}", flush=True)

@app.route("/api/blacklist", methods=["GET"])
def get_blacklist():
    return jsonify(load_blacklist())

@app.route("/api/blacklist/add", methods=["POST"])
def add_to_blacklist():
    data = request.json or {}
    addr = data.get("address", "").strip().lower()
    if not addr or not addr.startswith("0x") or len(addr) != 42:
        return jsonify({"error": "Geçersiz cüzdan adresi."}), 400
    
    blacklist = load_blacklist()
    blacklist_lower = [a.lower() for a in blacklist]
    
    if addr not in blacklist_lower:
        try:
            checksum_addr = Web3.to_checksum_address(addr)
            blacklist.append(checksum_addr)
            save_blacklist(blacklist)
            return jsonify({"success": True})
        except Exception:
            return jsonify({"error": "Geçersiz adresi checksum formatına çevirme hatası."}), 400
    return jsonify({"success": True, "message": "Zaten karalistede."})

@app.route("/api/blacklist/remove", methods=["POST"])
def remove_from_blacklist():
    data = request.json or {}
    addr = data.get("address", "").strip().lower()
    if not addr:
        return jsonify({"error": "Geçersiz adres."}), 400
        
    blacklist = load_blacklist()
    new_blacklist = [a for a in blacklist if a.lower() != addr]
    
    if len(new_blacklist) != len(blacklist):
        save_blacklist(new_blacklist)
        return jsonify({"success": True})
    return jsonify({"success": True, "message": "Adres karalistede bulunamadı."})

@app.route("/api/blacklist/add_via_link", methods=["GET"])
def add_to_blacklist_via_link():
    addr = request.args.get("address", "").strip().lower()
    if not addr or not addr.startswith("0x") or len(addr) != 42:
        return render_template("blacklist_confirm.html", success=False, error="Geçersiz cüzdan adresi.")
        
    blacklist = load_blacklist()
    blacklist_lower = [a.lower() for a in blacklist]
    
    if addr not in blacklist_lower:
        try:
            checksum_addr = Web3.to_checksum_address(addr)
            blacklist.append(checksum_addr)
            save_blacklist(blacklist)
            return render_template("blacklist_confirm.html", success=True, address=checksum_addr)
        except Exception:
            return render_template("blacklist_confirm.html", success=False, error="Geçersiz checksum formatı.")
            
    return render_template("blacklist_confirm.html", success=True, address=Web3.to_checksum_address(addr), message="Bu cüzdan adresi zaten karalistenizde bulunuyor.")

# ----------------- BACKGROUND WHALE SCANNER SYSTEM STATE -----------------
alerted_whales = set()

scanner_state = {
    "last_scan_time": 0,
    "scanned_markets_count": 0,
    "scanned_markets": [],
    "approaching_whales": []
}

@app.route("/api/scanner/status", methods=["GET"])
def get_scanner_status():
    return jsonify({
        "last_scan_time": scanner_state["last_scan_time"],
        "scanned_markets_count": scanner_state["scanned_markets_count"],
        "scanned_markets": scanner_state["scanned_markets"],
        "approaching_whales": scanner_state["approaching_whales"],
        "total_alerts_sent": len(alerted_whales)
    })

# List of high-performance public Polygon RPCs (ordered by getLogs compatibility)
RPC_URLS = [
    "https://polygon-public.nodies.app/",
    "https://polygon.api.onfinality.io/public",
    "https://polygon.drpc.org",
    "https://polygon.publicnode.com"
]
CTF_ADDRESS = Web3.to_checksum_address("0x4d97dcd97ec945f40cf65f87097ace5ea0476045")

# Standard ABI only for contract state calls
CTF_ABI = [
    {
        "constant": True,
        "inputs": [
            {"name": "conditionId", "type": "bytes32"},
            {"name": "index", "type": "uint256"}
        ],
        "name": "payoutNumerators",
        "outputs": [
            {"name": "", "type": "uint256"}
        ],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    }
]

def extract_slug(url_or_slug):
    url_or_slug = url_or_slug.strip()
    if "/" in url_or_slug:
        match = re.search(r'/event/([^/?#]+)', url_or_slug)
        if match:
            return match.group(1)
        match = re.search(r'/market/([^/?#]+)', url_or_slug)
        if match:
            return match.group(1)
        return url_or_slug.split("/")[-1]
    return url_or_slug

def get_web3():
    for rpc in RPC_URLS:
        for attempt in range(2):
            try:
                w3 = Web3(Web3.HTTPProvider(rpc))
                if poa_middleware is not None:
                    w3.middleware_onion.inject(poa_middleware, layer=0)
                if w3.is_connected():
                    return w3
            except Exception:
                time.sleep(1)
    raise Exception("Could not connect to any public Polygon RPC node")

def call_rpc_logs(w3, from_block, to_block, topics):
    for attempt in range(5):
        try:
            logs = w3.eth.get_logs({
                "fromBlock": from_block,
                "toBlock": to_block,
                "address": CTF_ADDRESS,
                "topics": topics
            })
            return logs
        except Exception:
            time.sleep(1)
            # Auto-heal: Try to get a fresh web3 from fallback RPCs on failure
            try:
                w3 = get_web3()
            except Exception:
                pass
    raise Exception(f"Failed to fetch logs from {from_block} to {to_block}")

def estimate_block_by_timestamp(w3, target_ts):
    latest_block = w3.eth.get_block("latest")
    latest_num = latest_block["number"]
    latest_ts = latest_block["timestamp"]
    
    if target_ts >= latest_ts:
        return latest_num
        
    ref_num = latest_num - 20000
    ref_block = w3.eth.get_block(ref_num)
    ref_ts = ref_block["timestamp"]
    
    avg_block_time = (latest_ts - ref_ts) / (latest_num - ref_num)
    estimated_num = int(latest_num - (latest_ts - target_ts) / avg_block_time)
    
    for attempt in range(5):
        if estimated_num > latest_num:
            estimated_num = latest_num
        block = w3.eth.get_block(estimated_num)
        ts = block["timestamp"]
        diff = target_ts - ts
        if abs(diff) <= 15:
            return estimated_num
        adj = int(diff / avg_block_time)
        if adj == 0:
            adj = 1 if diff > 0 else -1
        estimated_num += adj
        
    return estimated_num

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        data = request.json or {}
        url_or_slug = data.get("url")
        if not url_or_slug:
            return jsonify({"error": "Lütfen bir Polymarket linki veya slug girin."}), 200
            
        slug = extract_slug(url_or_slug)
        
        # 1. Fetch Market details from Gamma API (Markets endpoint)
        gamma_url = f"https://gamma-api.polymarket.com/markets?slug={slug}"
        resp = requests.get(gamma_url, timeout=10)
        market = None
        
        if resp.status_code == 200:
            markets_data = resp.json()
            if markets_data and isinstance(markets_data, list) and len(markets_data) > 0:
                market = markets_data[0]
                
        # If not found, try the Events endpoint (Polymarket often stores high-frequency events as events instead of raw markets)
        if not market:
            events_url = f"https://gamma-api.polymarket.com/events?slug={slug}"
            resp = requests.get(events_url, timeout=10)
            if resp.status_code == 200:
                events_data = resp.json()
                if events_data and isinstance(events_data, list) and len(events_data) > 0:
                    event = events_data[0]
                    event_markets = event.get("markets", [])
                    if event_markets and len(event_markets) > 0:
                        market = event_markets[0]
                        
        if not market:
            return jsonify({"error": "Bu linke ait aktif veya geçmiş bir market/etkinlik bulunamadı. Lütfen slug'ı kontrol edin."}), 200
            
        title = market.get("question", "Bilinmeyen Piyasa")
        description = market.get("description", "")
        condition_id = market.get("conditionId", "")
        clob_token_ids = market.get("clobTokenIds", "[]")
        
        if isinstance(clob_token_ids, str):
            import json
            try:
                clob_token_ids = json.loads(clob_token_ids)
            except Exception:
                clob_token_ids = []
                
        outcomes = market.get("outcomes", "[]")
        if isinstance(outcomes, str):
            try:
                outcomes = json.loads(outcomes)
            except Exception:
                outcomes = ["UP", "DOWN"]
                
        if not condition_id or len(clob_token_ids) < 2:
            return jsonify({"error": "Market akıllı sözleşme verileri eksik veya bu bir melez/negatif risk piyasası."}), 200
            
        up_token_dec = int(clob_token_ids[0])
        down_token_dec = int(clob_token_ids[1])
        up_token_hex = hex(up_token_dec)[2:].zfill(64).lower()
        down_token_hex = hex(down_token_dec)[2:].zfill(64).lower()
        
        start_date_str = market.get("startDate")
        end_date_str = market.get("endDate")
        event_start_time_str = market.get("eventStartTime")
        
        from dateutil import parser
        try:
            if event_start_time_str:
                start_ts = int(parser.isoparse(event_start_time_str).timestamp()) - 120  # 2 minutes buffer before event start
            else:
                start_ts = int(parser.isoparse(start_date_str).timestamp())
        except Exception:
            try:
                start_ts = int(parser.isoparse(start_date_str).timestamp())
            except Exception:
                start_ts = int(time.time()) - 3600
            
        try:
            end_ts = int(parser.isoparse(end_date_str).timestamp())
        except Exception:
            end_ts = int(time.time()) + 300
            
        w3 = get_web3()
        print(f"[TRACE] Connected to Web3. RPC: {w3.provider.endpoint_uri}")
        contract = w3.eth.contract(address=CTF_ADDRESS, abi=CTF_ABI)
        
        # Smart block range lookback (12 mins for 5m/15m markets, 40 mins max for others) to avoid scanning massive historic noise
        slug_lower = slug.lower()
        question_lower = title.lower()
        if "5m" in slug_lower or "5-minute" in slug_lower or "5m" in question_lower or "5-minute" in question_lower:
            lookback_seconds = 12 * 60
        elif "15m" in slug_lower or "15-minute" in slug_lower or "15m" in question_lower or "15-minute" in question_lower:
            lookback_seconds = 25 * 60
        else:
            lookback_seconds = 40 * 60
            
        now_ts = int(time.time())
        # Use current time as upper reference if the market is ongoing/active
        reference_end_ts = min(end_ts, now_ts)
        
        effective_start_ts = max(start_ts, reference_end_ts - lookback_seconds)
        print(f"[TRACE] Start TS: {start_ts}, End TS: {end_ts}, Reference End TS: {reference_end_ts}, Effective Start TS: {effective_start_ts}")
        start_block = estimate_block_by_timestamp(w3, effective_start_ts)
        
        latest_block_data = w3.eth.get_block("latest")
        latest_block = latest_block_data["number"]
        
        # For transfers, we scan up to reference_end_ts + 60
        transfers_end_block = estimate_block_by_timestamp(w3, reference_end_ts + 60)
        if transfers_end_block > latest_block:
            transfers_end_block = latest_block
            
        # For payout redemptions, we scan up to end_ts + 2700 (45 minutes post-close)
        target_end_block = estimate_block_by_timestamp(w3, end_ts + 2700)
        if target_end_block > latest_block:
            target_end_block = latest_block
            
        print(f"[TRACE] Transfer scan range: {start_block} to {transfers_end_block} (size: {transfers_end_block - start_block})")
        print(f"[TRACE] Full redemption scan range: {start_block} to {target_end_block} (size: {target_end_block - start_block})")
            
        is_resolved = False
        winning_outcome = "Belirlenmedi"
        payouts = [0, 0]
        try:
            payouts[0] = contract.functions.payoutNumerators(condition_id, 0).call()
            payouts[1] = contract.functions.payoutNumerators(condition_id, 1).call()
            if payouts[0] > 0 or payouts[1] > 0:
                is_resolved = True
                if payouts[0] > payouts[1]:
                    winning_outcome = outcomes[0] if len(outcomes) > 0 else "UP"
                else:
                    winning_outcome = outcomes[1] if len(outcomes) > 1 else "DOWN"
        except Exception:
            pass
            
        payout_redemption_topic0 = w3.to_hex(w3.keccak(text="PayoutRedemption(address,address,bytes32,bytes32,uint256[],uint256)"))
        transfer_single_topic0 = w3.to_hex(w3.keccak(text="TransferSingle(address,address,address,uint256,uint256)"))
        transfer_batch_topic0 = w3.to_hex(w3.keccak(text="TransferBatch(address,address,address,uint256[],uint256[])"))
        
        redemptions_raw = []
        transfers_raw = []
        
        combined_topics = [[payout_redemption_topic0, transfer_single_topic0, transfer_batch_topic0]]
        
        # Parallel fetch for transfers & active period redemptions
        print(f"[TRACE] Fetching active logs in parallel from block {start_block} to {transfers_end_block}...")
        active_logs = []
        chunks = []
        chunk_size = 50
        rpc_errors = []
        for chunk_start in range(start_block, transfers_end_block + 1, chunk_size):
            chunk_end = min(chunk_start + chunk_size - 1, transfers_end_block)
            chunks.append((chunk_start, chunk_end))
            
        def fetch_active_chunk(c_start, c_end):
            thread_w3 = get_web3()
            return call_rpc_logs(thread_w3, c_start, c_end, combined_topics)
            
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(fetch_active_chunk, cs, ce): (cs, ce) for cs, ce in chunks}
            for future in as_completed(futures):
                cs, ce = futures[future]
                try:
                    chunk_logs = future.result()
                    active_logs.extend(chunk_logs)
                except Exception as e:
                    err_msg = f"Failed to fetch active chunk {cs} to {ce}: {str(e)}"
                    print(f"[ERROR] {err_msg}")
                    rpc_errors.append(err_msg)
                    
        # Sort chronologically to preserve balance logic order
        active_logs.sort(key=lambda x: (x.get("blockNumber", 0), x.get("logIndex", 0)))
        print(f"[TRACE] Active logs fetched: {len(active_logs)}")
        
        # Fetch remaining post-close redemptions in larger chunks (extremely fast)
        post_logs = []
        if target_end_block > transfers_end_block:
            print(f"[TRACE] Fetching post-close redemption logs from block {transfers_end_block + 1} to {target_end_block}...")
            post_chunks = []
            post_chunk_size = 500
            for chunk_start in range(transfers_end_block + 1, target_end_block + 1, post_chunk_size):
                chunk_end = min(chunk_start + post_chunk_size - 1, target_end_block)
                post_chunks.append((chunk_start, chunk_end))
                
            def fetch_post_chunk(c_start, c_end):
                thread_w3 = get_web3()
                return call_rpc_logs(thread_w3, c_start, c_end, [[payout_redemption_topic0]])
                
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {executor.submit(fetch_post_chunk, cs, ce): (cs, ce) for cs, ce in post_chunks}
                for future in as_completed(futures):
                    cs, ce = futures[future]
                    try:
                        chunk_logs = future.result()
                        post_logs.extend(chunk_logs)
                    except Exception as e:
                        err_msg = f"Failed to fetch post chunk {cs} to {ce}: {str(e)}"
                        print(f"[ERROR] {err_msg}")
                        rpc_errors.append(err_msg)
                        
        all_logs = active_logs + post_logs
        all_logs.sort(key=lambda x: (x.get("blockNumber", 0), x.get("logIndex", 0)))
        print(f"[TRACE] Combined logs count: {len(all_logs)}")
        
        for log in all_logs:
            # Secure t0 decode (immune to bytes vs str and 0x prefixing)
            t0_raw = log["topics"][0]
            t0 = t0_raw.hex() if isinstance(t0_raw, bytes) else str(t0_raw)
            t0 = t0.lower()
            if t0.startswith("0x"):
                t0 = t0[2:]
            
            # 1. PayoutRedemption
            if t0 == payout_redemption_topic0[2:]:
                try:
                    t1 = log["topics"][1]
                    t1_hex = t1.hex() if isinstance(t1, bytes) else str(t1)
                    t1_hex = t1_hex.lower()
                    if t1_hex.startswith("0x"):
                        t1_hex = t1_hex[2:]
                    redeemer = Web3.to_checksum_address("0x" + t1_hex[-40:])
                    
                    cond_id_bytes, index_sets, payout = w3.codec.decode(['bytes32', 'uint256[]', 'uint256'], log["data"])
                    if cond_id_bytes.hex() == condition_id[2:]:
                        redemptions_raw.append({
                            "tx_hash": log["transactionHash"].hex(),
                            "block": log["blockNumber"],
                            "redeemer": redeemer,
                            "payout": payout / 1e6,
                            "indexSets": index_sets
                        })
                except Exception:
                    pass
                    
            # 2. TransferSingle (with correct HexBytes-to-hex conversion fix!)
            elif t0 == transfer_single_topic0[2:]:
                try:
                    data_hex = log["data"]
                    if isinstance(data_hex, bytes):
                        data_hex = data_hex.hex()
                    data_hex = data_hex.lower()
                    if data_hex.startswith("0x"):
                        data_hex = data_hex[2:]
                        
                    tid_hex = data_hex[0:64]
                    if tid_hex in (up_token_hex, down_token_hex):
                        t2 = log["topics"][2]
                        t3 = log["topics"][3]
                        t2_hex = t2.hex() if isinstance(t2, bytes) else str(t2)
                        t3_hex = t3.hex() if isinstance(t3, bytes) else str(t3)
                        t2_hex = t2_hex.lower()
                        t3_hex = t3_hex.lower()
                        if t2_hex.startswith("0x"): t2_hex = t2_hex[2:]
                        if t3_hex.startswith("0x"): t3_hex = t3_hex[2:]
                        frm = Web3.to_checksum_address("0x" + t2_hex[-40:])
                        to = Web3.to_checksum_address("0x" + t3_hex[-40:])
                        
                        tid, val = w3.codec.decode(['uint256', 'uint256'], log["data"])
                        transfers_raw.append({
                            "block": log["blockNumber"],
                            "from": frm,
                            "to": to,
                            "id": tid,
                            "value": val
                        })
                except Exception:
                    pass
                    
            # 3. TransferBatch (with correct HexBytes-to-hex conversion fix!)
            elif t0 == transfer_batch_topic0[2:]:
                try:
                    data_hex = log["data"]
                    if isinstance(data_hex, bytes):
                        data_hex = data_hex.hex()
                    data_hex = data_hex.lower()
                    if data_hex.startswith("0x"):
                        data_hex = data_hex[2:]
                        
                    if up_token_hex in data_hex or down_token_hex in data_hex:
                        t2 = log["topics"][2]
                        t3 = log["topics"][3]
                        t2_hex = t2.hex() if isinstance(t2, bytes) else str(t2)
                        t3_hex = t3.hex() if isinstance(t3, bytes) else str(t3)
                        t2_hex = t2_hex.lower()
                        t3_hex = t3_hex.lower()
                        if t2_hex.startswith("0x"): t2_hex = t2_hex[2:]
                        if t3_hex.startswith("0x"): t3_hex = t3_hex[2:]
                        frm = Web3.to_checksum_address("0x" + t2_hex[-40:])
                        to = Web3.to_checksum_address("0x" + t3_hex[-40:])
                        
                        tids, vals = w3.codec.decode(['uint256[]', 'uint256[]'], log["data"])
                        for tid, val in zip(tids, vals):
                            if tid in (up_token_dec, down_token_dec):
                                transfers_raw.append({
                                    "block": log["blockNumber"],
                                    "from": frm,
                                    "to": to,
                                    "id": tid,
                                    "value": val
                                })
                except Exception:
                    pass

            
        balances = {}
        max_balances = {}
        
        def update_balance(account, token_id, amount):
            if account == "0x0000000000000000000000000000000000000000":
                return
            if account not in balances:
                balances[account] = {up_token_dec: 0, down_token_dec: 0}
            if account not in max_balances:
                max_balances[account] = {up_token_dec: 0, down_token_dec: 0}
                
            balances[account][token_id] += amount
            if balances[account][token_id] > max_balances[account][token_id]:
                max_balances[account][token_id] = balances[account][token_id]
                
        # Weighted Average Buy Price variables
        buy_costs = {}
        buy_shares = {}
        
        winning_index = -1
        if payouts[0] > payouts[1]:
            winning_index = 0
        elif payouts[1] > payouts[0]:
            winning_index = 1
            
        for tx in transfers_raw:
            frm = tx["from"]
            to = tx["to"]
            tid = tx["id"]
            val = tx["value"]
            block = tx["block"]
            
            update_balance(frm, tid, -val)
            update_balance(to, tid, val)
            
            # Record buy (acquisition) for the recipient
            if to != "0x0000000000000000000000000000000000000000":
                if to not in buy_costs:
                    buy_costs[to] = {up_token_dec: 0.0, down_token_dec: 0.0}
                    buy_shares[to] = {up_token_dec: 0.0, down_token_dec: 0.0}
                
                # Progress calculation
                total_active_blocks = transfers_end_block - start_block
                if total_active_blocks > 0:
                    progress = (block - start_block) / total_active_blocks
                    progress = max(0.0, min(1.0, progress))
                else:
                    progress = 0.5
                    
                token_idx = 0 if tid == up_token_dec else 1
                
                if winning_index == -1:
                    price = 0.50
                elif token_idx == winning_index:
                    price = 0.50 + 0.45 * progress
                else:
                    price = 0.50 - 0.45 * progress
                    
                shares = val / 1e6
                cost = price * shares
                
                buy_costs[to][tid] += cost
                buy_shares[to][tid] += shares
            
        redeemers_summary = {}
        for r in redemptions_raw:
            redeemer = r["redeemer"]
            payout = r["payout"]
            
            if redeemer not in redeemers_summary:
                redeemers_summary[redeemer] = {
                    "total_payout": 0.0,
                    "tx_count": 0,
                    "txs": []
                }
            redeemers_summary[redeemer]["total_payout"] += payout
            redeemers_summary[redeemer]["tx_count"] += 1
            if r["tx_hash"] not in redeemers_summary[redeemer]["txs"]:
                redeemers_summary[redeemer]["txs"].append(r["tx_hash"])
                
        up_peak_positions = []
        down_peak_positions = []
        
        for account, max_vals in max_balances.items():
            up_peak = max_vals[up_token_dec] / 1e6
            down_peak = max_vals[down_token_dec] / 1e6
            
            curr_up = balances[account][up_token_dec] / 1e6
            curr_down = balances[account][down_token_dec] / 1e6
            
            if abs(curr_up) < 0.01: curr_up = 0.0
            if abs(curr_down) < 0.01: curr_down = 0.0
            
            if up_peak > 0.1:
                up_sh = buy_shares.get(account, {}).get(up_token_dec, 0.0)
                up_avg = buy_costs.get(account, {}).get(up_token_dec, 0.0) / up_sh if up_sh > 0 else 0.50
                up_peak_positions.append({
                    "account": account,
                    "peak": up_peak,
                    "current": curr_up,
                    "avg_buy_price": up_avg
                })
            if down_peak > 0.1:
                down_sh = buy_shares.get(account, {}).get(down_token_dec, 0.0)
                down_avg = buy_costs.get(account, {}).get(down_token_dec, 0.0) / down_sh if down_sh > 0 else 0.50
                down_peak_positions.append({
                    "account": account,
                    "peak": down_peak,
                    "current": curr_down,
                    "avg_buy_price": down_avg
                })
                
        up_peak_positions.sort(key=lambda x: x["peak"], reverse=True)
        down_peak_positions.sort(key=lambda x: x["peak"], reverse=True)
        
        redeemers_list = []
        winning_token = up_token_dec if winning_index == 0 else down_token_dec
        SYSTEM_ROUTER = "0xF3cFb6a6eBFeB51876289Eb235719EB1C65252B0"
        for acc, summary in redeemers_summary.items():
            if acc.lower() == SYSTEM_ROUTER.lower():
                continue
            if summary["total_payout"] > 0.01:
                red_sh = buy_shares.get(acc, {}).get(winning_token, 0.0)
                red_avg = buy_costs.get(acc, {}).get(winning_token, 0.0) / red_sh if red_sh > 0 else 0.50
                redeemers_list.append({
                    "account": acc,
                    "payout": summary["total_payout"],
                    "tx_count": summary["tx_count"],
                    "latest_tx": summary["txs"][-1],
                    "avg_buy_price": red_avg
                })
        redeemers_list.sort(key=lambda x: x["payout"], reverse=True)
        
        result = {
            "metadata": {
                "title": title,
                "description": description,
                "conditionId": condition_id,
                "outcomes": outcomes,
                "volume": market.get("volume", "0"),
                "liquidity": market.get("liquidity", "0"),
                "isResolved": is_resolved,
                "winningOutcome": winning_outcome,
                "startBlock": start_block,
                "endBlock": target_end_block,
                "scannedBlocks": target_end_block - start_block,
                "resolvedBlock": target_end_block,
                "rpcErrors": rpc_errors,
                "allLogsCount": len(all_logs),
                "transfersCount": len(transfers_raw),
                "redemptionsCount": len(redemptions_raw)
            },
            "top_up": up_peak_positions[:50],
            "top_down": down_peak_positions[:50],
            "redeemers": redeemers_list[:50]
        }
        
        return jsonify(result)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Beklenmedik bir sunucu hatası oluştu: {str(e)}"}), 200

# ----------------- BACKGROUND WHALE SCANNER SYSTEM -----------------

def check_if_new_account(address):
    # May 1, 2026 UTC timestamp = 1777593600
    MAY_1_2026 = 1777593600
    
    url = f"https://data-api.polymarket.com/activity?user={address}&limit=1&sortDirection=ASC"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return False
        data = resp.json()
        if not data:
            return False
        
        oldest_ts = data[0].get("timestamp")
        return oldest_ts is not None and oldest_ts >= MAY_1_2026
    except Exception:
        return False

def fetch_pusd_balance(address):
    try:
        w3 = get_web3()
        PUSD_CONTRACT = Web3.to_checksum_address("0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb")
        abi = [
            {
                "constant": True,
                "inputs": [{"name": "_owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"name": "balance", "type": "uint256"}],
                "type": "function"
            }
        ]
        pusd = w3.eth.contract(address=PUSD_CONTRACT, abi=abi)
        checksum_addr = Web3.to_checksum_address(address)
        pusd_bal = pusd.functions.balanceOf(checksum_addr).call() / 1e6
        return pusd_bal
    except Exception as e:
        print(f"[WARNING] Failed to fetch pUSD balance for {address}: {e}", flush=True)
        return None

def send_telegram_whale_alert(address, shares, avg_price, market_title, market_slug, outcome):
    try:
        BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
        CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
        
        if not BOT_TOKEN or not CHAT_ID:
            print("[WARNING] TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID environment variables are not set. Skipping Telegram notification.", flush=True)
            return
        
        # Check if user is a new account (Joined May, June or July 2026)
        is_new = check_if_new_account(address)
        
        # ONLY send alerts for new accounts (created in May, June, or July 2026)
        if not is_new:
            print(f"[FILTERED] Whale address {address} is an old account. Skipping Telegram alert.", flush=True)
            return
            
        balance = fetch_pusd_balance(address)
        balance_text = f"💵 <b>Hesap Bakiyesi (pUSD):</b> ${balance:,.2f}\n" if balance is not None else ""
        
        text = (
            f"🚨 🐳 🆕 <b>5mFinder BALİNA ALARMI - YENİ HESAP!</b> 🆕 🐳 🚨\n\n"
            f"🔥 <b>YENİ KULLANICI UYARISI! (Joined May/June/July 2026)</b> 🔥\n\n"
            f"📊 <b>Piyasa:</b> {market_title}\n"
            f"👤 <b>Cüzdan Adresi:</b> <code>{address}</code>\n"
            f"📈 <b>Zirve Pozisyon:</b> {shares:,.0f} Shares ({outcome})\n"
            f"💰 <b>Tahmini Maliyet:</b> ${avg_price:.2f}\n"
            f"{balance_text}"
        )
        
        APP_URL = os.environ.get("APP_URL", "https://5mfinder-production.up.railway.app").rstrip("/")
        
        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": "👤 Polymarket", "url": f"https://polymarket.com/profile/{address}"},
                    {"text": "🎮 Betmoar", "url": f"https://www.betmoar.fun/profile/{address}"}
                ],
                [
                    {"text": "📊 5mFinder Analiz Et", "url": f"{APP_URL}/"},
                    {"text": "🚫 Karalisteye Ekle", "url": f"{APP_URL}/api/blacklist/add_via_link?address={address}"}
                ]
            ]
        }
        
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        resp = requests.post(url, json={
            "chat_id": CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": reply_markup
        }, timeout=10)
        
        if resp.status_code == 200:
            print(f"[SUCCESS] Whale Alert sent to Telegram for {address}", flush=True)
        else:
            print(f"[ERROR] TG Error: {resp.status_code}, {resp.text}", flush=True)
    except Exception as e:
        print(f"[ERROR] Failed to send TG alert: {e}", flush=True)

def scan_market_for_whales(market):
    try:
        slug = market.get("slug")
        title = market.get("question")
        condition_id = market.get("conditionId")
        clob_token_ids = market.get("clobTokenIds")
        
        if isinstance(clob_token_ids, str):
            import json
            try:
                clob_token_ids = json.loads(clob_token_ids)
            except Exception:
                clob_token_ids = []
                
        outcomes = market.get("outcomes", "[]")
        if isinstance(outcomes, str):
            try:
                outcomes = json.loads(outcomes)
            except Exception:
                outcomes = ["UP", "DOWN"]
                
        if not condition_id or len(clob_token_ids) < 2:
            return
            
        up_token_dec = int(clob_token_ids[0])
        down_token_dec = int(clob_token_ids[1])
        up_token_hex = hex(up_token_dec)[2:].zfill(64).lower()
        down_token_hex = hex(down_token_dec)[2:].zfill(64).lower()
        
        start_date_str = market.get("startDate")
        end_date_str = market.get("endDate")
        event_start_time_str = market.get("eventStartTime")
        
        from dateutil import parser
        try:
            if event_start_time_str:
                start_ts = int(parser.isoparse(event_start_time_str).timestamp()) - 120
            else:
                start_ts = int(parser.isoparse(start_date_str).timestamp())
        except Exception:
            return
            
        end_ts = int(parser.isoparse(end_date_str).timestamp())
        now_ts = int(time.time())
        reference_end_ts = min(end_ts, now_ts)
        
        lookback_seconds = 12 * 60
        effective_start_ts = max(start_ts, reference_end_ts - lookback_seconds)
        
        w3 = get_web3()
        start_block = estimate_block_by_timestamp(w3, effective_start_ts)
        
        latest_block_data = w3.eth.get_block("latest")
        latest_block = latest_block_data["number"]
        
        transfers_end_block = estimate_block_by_timestamp(w3, reference_end_ts + 60)
        if transfers_end_block > latest_block:
            transfers_end_block = latest_block
            
        if transfers_end_block <= start_block:
            return
            
        transfer_single_topic0 = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
        
        chunks = []
        chunk_size = 150
        for chunk_start in range(start_block, transfers_end_block + 1, chunk_size):
            chunk_end = min(chunk_start + chunk_size - 1, transfers_end_block)
            chunks.append((chunk_start, chunk_end))
            
        logs = []
        def fetch_chunk(cs, ce):
            thread_w3 = get_web3()
            return thread_w3.eth.get_logs({
                "fromBlock": cs,
                "toBlock": ce,
                "address": CTF_ADDRESS,
                "topics": [[transfer_single_topic0]]
            })
            
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(fetch_chunk, cs, ce): (cs, ce) for cs, ce in chunks}
            for future in as_completed(futures):
                try:
                    logs.extend(future.result())
                except Exception:
                    pass
                    
        logs.sort(key=lambda x: (x.get("blockNumber", 0), x.get("logIndex", 0)))
        
        # Calculate winner/resolution status for average buy price estimation
        is_resolved = False
        winning_index = -1
        try:
            contract = w3.eth.contract(address=CTF_ADDRESS, abi=CTF_ABI)
            payouts = [0, 0]
            payouts[0] = contract.functions.payoutNumerators(condition_id, 0).call()
            payouts[1] = contract.functions.payoutNumerators(condition_id, 1).call()
            if payouts[0] > 0 or payouts[1] > 0:
                is_resolved = True
                winning_index = 0 if payouts[0] > payouts[1] else 1
        except Exception:
            pass
            
        balances = {}
        max_balances = {}
        buy_costs = {}
        buy_shares = {}
        
        def update_balance(account, token_id, amount):
            if account == "0x0000000000000000000000000000000000000000":
                return
            if account not in balances:
                balances[account] = {up_token_dec: 0, down_token_dec: 0}
            if account not in max_balances:
                max_balances[account] = {up_token_dec: 0, down_token_dec: 0}
                
            balances[account][token_id] += amount
            if balances[account][token_id] > max_balances[account][token_id]:
                max_balances[account][token_id] = balances[account][token_id]
                
        for log in logs:
            try:
                data_hex = log["data"].hex() if isinstance(log["data"], bytes) else str(log["data"]).lower()
                if data_hex.startswith("0x"): data_hex = data_hex[2:]
                
                tid_hex = data_hex[0:64]
                if tid_hex in (up_token_hex, down_token_hex):
                    t2 = log["topics"][2]
                    t3 = log["topics"][3]
                    t2_hex = t2.hex() if isinstance(t2, bytes) else str(t2)
                    t3_hex = t3.hex() if isinstance(t3, bytes) else str(t3)
                    if t2_hex.startswith("0x"): t2_hex = t2_hex[2:]
                    if t3_hex.startswith("0x"): t3_hex = t3_hex[2:]
                    frm = Web3.to_checksum_address("0x" + t2_hex[-40:])
                    to = Web3.to_checksum_address("0x" + t3_hex[-40:])
                    
                    tid, val = w3.codec.decode(['uint256', 'uint256'], log["data"])
                    block = log["blockNumber"]
                    
                    update_balance(frm, tid, -val)
                    update_balance(to, tid, val)
                    
                    # Accumulate for average price
                    if to != "0x0000000000000000000000000000000000000000":
                        if to not in buy_costs:
                            buy_costs[to] = {up_token_dec: 0.0, down_token_dec: 0.0}
                            buy_shares[to] = {up_token_dec: 0.0, down_token_dec: 0.0}
                            
                        total_active_blocks = transfers_end_block - start_block
                        if total_active_blocks > 0:
                            progress = (block - start_block) / total_active_blocks
                            progress = max(0.0, min(1.0, progress))
                        else:
                            progress = 0.5
                            
                        token_idx = 0 if tid == up_token_dec else 1
                        if winning_index == -1:
                            price = 0.50
                        elif token_idx == winning_index:
                            price = 0.50 + 0.45 * progress
                        else:
                            price = 0.50 - 0.45 * progress
                            
                        shares = val / 1e6
                        cost = price * shares
                        buy_costs[to][tid] += cost
                        buy_shares[to][tid] += shares
            except Exception:
                pass
                
        EXCLUDED_ADDRESSES = {
            "0xF3cFb6a6eBFeB51876289Eb235719EB1C65252B0".lower(),
            "0x0000000000000000000000000000000000000000".lower()
        }
        
        # Load blacklist
        blacklist = load_blacklist()
        blacklist_lower = {addr.lower() for addr in blacklist}
        
        whales_found_count = 0
        approaching_list = []
        
        for account, max_vals in max_balances.items():
            if account.lower() in EXCLUDED_ADDRESSES or account.lower() in blacklist_lower:
                continue
                
            for tid, token_idx, name in [(up_token_dec, 0, outcomes[0] if len(outcomes) > 0 else "UP"), 
                                         (down_token_dec, 1, outcomes[1] if len(outcomes) > 1 else "DOWN")]:
                peak_shares = max_vals[tid] / 1e6
                if peak_shares >= 4000.0:
                    sh = buy_shares.get(account, {}).get(tid, 0.0)
                    avg_price = buy_costs.get(account, {}).get(tid, 0.0) / sh if sh > 0 else 0.50
                    
                    # Applying filters: exclude bonder/settler (avg_price >= 0.96) or 100x chaser (avg_price <= 0.04)
                    if avg_price <= 0.04 or avg_price >= 0.96:
                        print(f"[FILTERED] Whale address {account} with peak {peak_shares:,.0f} {name} filtered due to average price ${avg_price:.2f}", flush=True)
                        continue
                        
                    whales_found_count += 1
                    whale_key = f"{slug}:{account}:{name}"
                    if whale_key not in alerted_whales:
                        alerted_whales.add(whale_key)
                        send_telegram_whale_alert(account, peak_shares, avg_price, title, slug, name)
                        
                elif 2000.0 <= peak_shares < 4000.0:
                    sh = buy_shares.get(account, {}).get(tid, 0.0)
                    avg_price = buy_costs.get(account, {}).get(tid, 0.0) / sh if sh > 0 else 0.50
                    
                    if avg_price <= 0.04 or avg_price >= 0.96:
                        continue
                        
                    approaching_list.append({
                        "address": account,
                        "shares": peak_shares,
                        "outcome": name,
                        "market_title": title,
                        "market_slug": slug,
                        "avg_price": avg_price
                    })
                    
        # Safely insert or update global approaching whales to preserve history without duplicates!
        for item in approaching_list:
            item_address = item["address"].lower()
            item_slug = item["market_slug"].lower()
            item_outcome = item["outcome"].lower()
            
            existing_idx = -1
            for idx, existing in enumerate(scanner_state["approaching_whales"]):
                if (existing["address"].lower() == item_address and 
                    existing["market_slug"].lower() == item_slug and 
                    existing["outcome"].lower() == item_outcome):
                    existing_idx = idx
                    break
            
            item["timestamp"] = int(time.time())
            if existing_idx != -1:
                scanner_state["approaching_whales"].pop(existing_idx)
            
            scanner_state["approaching_whales"].insert(0, item)
            
        scanner_state["approaching_whales"] = scanner_state["approaching_whales"][:100]
        
        # Track scanned market rolling history
        market_already_scanned = False
        for m in scanner_state["scanned_markets"]:
            if m["slug"] == slug:
                m["timestamp"] = int(time.time())
                m["whales_count"] = whales_found_count
                m["approaching_count"] = len(approaching_list)
                market_already_scanned = True
                break
                
        if not market_already_scanned:
            scanner_state["scanned_markets"].insert(0, {
                "slug": slug,
                "title": title,
                "timestamp": int(time.time()),
                "blocks_scanned": transfers_end_block - start_block,
                "whales_count": whales_found_count,
                "approaching_count": len(approaching_list)
            })
            scanner_state["scanned_markets"] = scanner_state["scanned_markets"][:30]
                        
    except Exception as e:
        print(f"[ERROR] Error scanning market {market.get('slug')}: {e}", flush=True)

def whale_scanner_loop():
    print("[INFO] Background Whale Scanner Thread Started.", flush=True)
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from dateutil import parser
    
    while True:
        try:
            active_5m_map = {}
            now_ts = int(time.time())
            
            # Generate exact slugs for current time, previous time, and next 2 intervals (4 total intervals)
            current_interval = (now_ts // 300) * 300
            prev_interval = current_interval - 300
            next_interval = current_interval + 300
            next_next_interval = current_interval + 600
            
            intervals = [prev_interval, current_interval, next_interval, next_next_interval]
            coins = ["btc", "eth", "xrp", "sol", "doge", "bnb", "hype"]
            
            slugs = []
            for coin in coins:
                for interval in intervals:
                    slugs.append(f"{coin}-updown-5m-{interval}")
                    
            def fetch_market_by_slug(slug):
                url = f"https://gamma-api.polymarket.com/markets?slug={slug}"
                try:
                    resp = requests.get(url, timeout=4)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data and isinstance(data, list) and len(data) > 0:
                            return data[0]
                except Exception:
                    pass
                return None
                
            # Fetch all slugs in parallel
            with ThreadPoolExecutor(max_workers=15) as executor:
                futures = {executor.submit(fetch_market_by_slug, slug): slug for slug in slugs}
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        m_id = res.get("id")
                        slug = (res.get("slug") or "").lower()
                        question = (res.get("question") or "").lower()
                        end_date_str = res.get("endDate")
                        
                        if not end_date_str:
                            continue
                            
                        try:
                            end_ts = int(parser.isoparse(end_date_str).timestamp())
                        except Exception:
                            continue
                            
                        # Enforce precise live time window filter
                        if now_ts - 120 <= end_ts <= now_ts + 1200:
                            if m_id:
                                active_5m_map[m_id] = res
                                
            # 2. General active markets tag-based sort fallback (in case slug naming changes)
            try:
                fallback_resp = requests.get("https://gamma-api.polymarket.com/markets?tag_id=102892&active=true&closed=false&limit=40&order=endDate&ascending=false", timeout=10)
                if fallback_resp.status_code == 200:
                    for m in fallback_resp.json():
                        m_id = m.get("id")
                        slug = (m.get("slug") or "").lower()
                        question = (m.get("question") or "").lower()
                        end_date_str = m.get("endDate")
                        
                        if not end_date_str:
                            continue
                            
                        try:
                            end_ts = int(parser.isoparse(end_date_str).timestamp())
                        except Exception:
                            continue
                            
                        if now_ts - 120 <= end_ts <= now_ts + 1200:
                            if "5m" in slug or "5-minute" in slug or "5m" in question or "5-minute" in question:
                                if m_id:
                                    active_5m_map[m_id] = m
            except Exception as fb_err:
                print(f"[SCANNER WARNING] Tag fallback failed: {fb_err}", flush=True)
                
            active_5m = list(active_5m_map.values())
            print(f"[SCANNER] Found {len(active_5m)} active 5m markets to scan.", flush=True)
            
            # Update scanner state on each iteration
            scanner_state["last_scan_time"] = int(time.time())
            scanner_state["scanned_markets_count"] = len(active_5m)
            
            for market in active_5m:
                scan_market_for_whales(market)
                
        except Exception as e:
            print(f"[SCANNER ERROR] Exception in background loop: {e}", flush=True)
            
        time.sleep(60)

# ----------------- DEDICATED BNB TOP HOLDERS EARLY WHALE SCANNER SYSTEM -----------------
alerted_bnb_whales = set()

def send_telegram_bnb_whale_alert(up_holder=None, down_holder=None, market_title="", market_slug=""):
    try:
        BOT_TOKEN = os.environ.get("BNB_TELEGRAM_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN")
        CHAT_ID = os.environ.get("BNB_TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID")
        
        if not BOT_TOKEN or not CHAT_ID:
            print("[WARNING] BNB TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID environment variables are not set. Skipping Telegram notification.", flush=True)
            return
            
        blacklist = load_blacklist()
        blacklist_lower = {a.lower() for a in blacklist}
        
        # Filter blacklisted addresses
        if up_holder and up_holder["address"].lower() in blacklist_lower:
            up_holder = None
        if down_holder and down_holder["address"].lower() in blacklist_lower:
            down_holder = None
            
        if not up_holder and not down_holder:
            return

        lines = [
            "🚨 🟡 <b>5mFinder BNB BALİNA VE TOP HOLDER ALARMI!</b> 🟡 🚨\n",
            "🔥 <b>ERKEN BALİNA BİRİKİMİ DETECTED!</b> 🔥\n",
            f"📊 <b>Piyasa:</b> {market_title}\n"
        ]
        
        total_shares = 0.0
        primary_addr = None
        
        if up_holder:
            addr = up_holder["address"]
            primary_addr = addr
            name = up_holder.get("name") or addr[:8]
            shares = up_holder["shares"]
            bal = fetch_pusd_balance(addr)
            total_shares += shares
            bal_str = f"${bal:,.2f}" if bal is not None else "Bilinmiyor"
            
            poly_link = f'<a href="https://polymarket.com/profile/{addr}">{name}</a>'
            betmoar_link = f'<a href="https://www.betmoar.fun/profile/{addr}">🎮 Betmoar Profili</a>'
            
            lines.append(f"🟢 <b>UP BALİNASI:</b> {poly_link} ({betmoar_link})")
            lines.append(f"   👤 <code>{addr}</code>")
            lines.append(f"   📈 <b>Pozisyon:</b> {shares:,.0f} Shares (UP)")
            lines.append(f"   💵 <b>Cüzdan Bakiyesi (pUSD):</b> {bal_str}\n")
            
        if down_holder:
            addr = down_holder["address"]
            if not primary_addr:
                primary_addr = addr
            name = down_holder.get("name") or addr[:8]
            shares = down_holder["shares"]
            bal = fetch_pusd_balance(addr)
            total_shares += shares
            bal_str = f"${bal:,.2f}" if bal is not None else "Bilinmiyor"
            
            poly_link = f'<a href="https://polymarket.com/profile/{addr}">{name}</a>'
            betmoar_link = f'<a href="https://www.betmoar.fun/profile/{addr}">🎮 Betmoar Profili</a>'
            
            lines.append(f"🔴 <b>DOWN BALİNASI:</b> {poly_link} ({betmoar_link})")
            lines.append(f"   👤 <code>{addr}</code>")
            lines.append(f"   📈 <b>Pozisyon:</b> {shares:,.0f} Shares (DOWN)")
            lines.append(f"   💵 <b>Cüzdan Bakiyesi (pUSD):</b> {bal_str}\n")
            
        if up_holder and down_holder:
            lines.append(f"⚔️ <b>TOPLAM SAVAŞ HACMİ:</b> {total_shares:,.0f} Shares")
            
        text = "\n".join(lines)
        
        APP_URL = os.environ.get("APP_URL", "https://5mfinder-production.up.railway.app").rstrip("/")
        
        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": "📊 5mFinder Analiz Et", "url": f"{APP_URL}/"},
                    {"text": "🚫 Karalisteye Ekle", "url": f"{APP_URL}/api/blacklist/add_via_link?address={primary_addr}"}
                ]
            ]
        }
        
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        resp = requests.post(url, json={
            "chat_id": CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": reply_markup,
            "disable_web_page_preview": True
        }, timeout=10)
        
        if resp.status_code == 200:
            print(f"[SUCCESS] BNB Dual Whale Alert sent to Telegram for {market_slug}", flush=True)
        else:
            print(f"[ERROR] BNB TG Error: {resp.status_code}, {resp.text}", flush=True)
    except Exception as e:
        print(f"[ERROR] Failed to send BNB TG alert: {e}", flush=True)

def scan_bnb_top_holders():
    try:
        now_ts = int(time.time())
        current_interval = (now_ts // 300) * 300
        intervals = [current_interval, current_interval + 300, current_interval + 600]
        
        threshold = float(os.environ.get("BNB_WHALE_THRESHOLD", 15000))
        
        for interval in intervals:
            slug = f"bnb-updown-5m-{interval}"
            url = f"https://gamma-api.polymarket.com/markets?slug={slug}"
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                if not data or not isinstance(data, list):
                    continue
                market = data[0]
                cond_id = market.get("conditionId")
                title = market.get("question") or f"BNB Up or Down 5m-{interval}"
                outcomes = market.get("outcomes", ["UP", "DOWN"])
                if isinstance(outcomes, str):
                    try:
                        outcomes = json.loads(outcomes)
                    except Exception:
                        outcomes = ["UP", "DOWN"]
                        
                if not cond_id:
                    continue
                    
                holders_url = f"https://data-api.polymarket.com/holders?market={cond_id}"
                h_resp = requests.get(holders_url, timeout=5)
                if h_resp.status_code != 200:
                    continue
                holders_data = h_resp.json()
                if not holders_data or not isinstance(holders_data, list):
                    continue
                    
                up_top = None
                down_top = None
                
                for token_group in holders_data:
                    holders_list = token_group.get("holders", [])
                    for h in holders_list:
                        wallet = h.get("proxyWallet")
                        if not wallet:
                            continue
                        amount = float(h.get("amount") or 0)
                        name = h.get("name") or h.get("pseudonym") or ""
                        idx = h.get("outcomeIndex", 0)
                        
                        holder_obj = {
                            "address": wallet,
                            "name": name,
                            "shares": amount
                        }
                        
                        if idx == 0 and amount >= threshold:
                            if not up_top or amount > up_top["shares"]:
                                up_top = holder_obj
                        elif idx == 1 and amount >= threshold:
                            if not down_top or amount > down_top["shares"]:
                                down_top = holder_obj
                                
                if up_top or down_top:
                    up_key = f"{up_top['address'].lower()}" if up_top else "none"
                    down_key = f"{down_top['address'].lower()}" if down_top else "none"
                    whale_key = f"{slug}:{up_key}:{down_key}"
                    
                    if whale_key not in alerted_bnb_whales:
                        alerted_bnb_whales.add(whale_key)
                        send_telegram_bnb_whale_alert(
                            up_holder=up_top,
                            down_holder=down_top,
                            market_title=title,
                            market_slug=slug
                        )
            except Exception as e:
                print(f"[BNB SCANNER ERROR] Error scanning slug {slug}: {e}", flush=True)
    except Exception as e:
        print(f"[BNB SCANNER ERROR] Top-level error in scan_bnb_top_holders: {e}", flush=True)

def bnb_whale_scanner_loop():
    print("[INFO] Background BNB Whale Scanner Thread Started.", flush=True)
    while True:
        try:
            scan_bnb_top_holders()
        except Exception as e:
            print(f"[BNB SCANNER ERROR] Loop exception: {e}", flush=True)
        time.sleep(20)

def start_bnb_whale_scanner():
    if os.environ.get("BNB_SCANNER_STARTED") == "true":
        return
    os.environ["BNB_SCANNER_STARTED"] = "true"
    print("[INFO] Spawning background BNB Whale Scanner thread...", flush=True)
    bnb_thread = threading.Thread(target=bnb_whale_scanner_loop, daemon=True)
    bnb_thread.start()

# ----------------- DEDICATED BTC ORDERBOOK WALL SCANNER SYSTEM -----------------
alerted_orderbook_walls = set()

def send_telegram_btc_orderbook_alert(coin_symbol, side_str, price, shares, outcome, market_title, market_slug):
    try:
        BOT_TOKEN = os.environ.get("BTC_ORDERBOOK_TELEGRAM_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN")
        CHAT_ID = os.environ.get("BTC_ORDERBOOK_TELEGRAM_CHAT_ID") or os.environ.get("ORDERBOOK_TELEGRAM_CHAT_ID") or os.environ.get("BNB_TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID")
        
        if not BOT_TOKEN or not CHAT_ID:
            print("[WARNING] BTC Orderbook Telegram Bot Token or Chat ID not set. Skipping notification.", flush=True)
            return
            
        usd_value = shares * price
        side_emoji = "🟢" if "ALIŞ" in side_str or "BID" in side_str else "🔴"
        
        text = (
            f"🚨 🧱 <b>5mFinder BTC ORDERBOOK LİMİT DUVARI ALARMI!</b> 🧱 🚨\n\n"
            f"🔥 <b>TAHTADA DEV LİMİT EMİR DUVARI DETECTED!</b> 🔥\n\n"
            f"📊 <b>Piyasa:</b> {market_title}\n"
            f"🎯 <b>Taraf:</b> {side_emoji} <b>{side_str} DUVARI</b> ({outcome})\n"
            f"💵 <b>Limit Fiyat:</b> ${price:.2f} ({int(round(price*100))}¢)\n"
            f"📈 <b>Duvar Büyüklüğü:</b> {shares:,.0f} Shares (${usd_value:,.2f} USD Hacim)\n"
        )
        
        APP_URL = os.environ.get("APP_URL", "https://5mfinder-production.up.railway.app").rstrip("/")
        
        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": "📊 5mFinder Analiz Et", "url": f"{APP_URL}/"},
                    {"text": "🌐 Polymarket", "url": f"https://polymarket.com/event/{market_slug}"}
                ]
            ]
        }
        
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        resp = requests.post(url, json={
            "chat_id": CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": reply_markup
        }, timeout=10)
        
        if resp.status_code == 200:
            print(f"[SUCCESS] BTC Orderbook Alert sent to TG ({side_str} {shares:,.0f} shares @ ${price:.2f})", flush=True)
        else:
            print(f"[ERROR] BTC Orderbook TG Error: {resp.status_code}, {resp.text}", flush=True)
    except Exception as e:
        print(f"[ERROR] Failed to send BTC Orderbook TG alert: {e}", flush=True)

def scan_btc_orderbook_walls():
    try:
        now_ts = int(time.time())
        current_interval = (now_ts // 300) * 300
        intervals = [current_interval, current_interval + 300, current_interval + 600]
        
        threshold = float(os.environ.get("BTC_ORDERBOOK_WALL_THRESHOLD", 15000))
        
        for interval in intervals:
            slug = f"btc-updown-5m-{interval}"
            url = f"https://gamma-api.polymarket.com/markets?slug={slug}"
            try:
                r = requests.get(url, timeout=5)
                if r.status_code != 200:
                    continue
                data = r.json()
                if not data or not isinstance(data, list):
                    continue
                market = data[0]
                cond_id = market.get("conditionId")
                title = market.get("question") or f"Bitcoin Up or Down 5m-{interval}"
                clob_ids = market.get("clobTokenIds", "[]")
                if isinstance(clob_ids, str):
                    try:
                        clob_ids = json.loads(clob_ids)
                    except Exception:
                        clob_ids = []
                outcomes = market.get("outcomes", ["UP", "DOWN"])
                if isinstance(outcomes, str):
                    try:
                        outcomes = json.loads(outcomes)
                    except Exception:
                        outcomes = ["UP", "DOWN"]
                        
                if len(clob_ids) < 2:
                    continue
                    
                for idx, token_id in enumerate(clob_ids[:2]):
                    outcome_str = outcomes[idx] if idx < len(outcomes) else ("UP" if idx == 0 else "DOWN")
                    book_url = f"https://clob.polymarket.com/book?token_id={token_id}"
                    b_resp = requests.get(book_url, timeout=5)
                    if b_resp.status_code != 200:
                        continue
                    book = b_resp.json()
                    bids = book.get("bids", [])
                    asks = book.get("asks", [])
                    
                    # Bids (Alışlar) - Exclude 0.01-0.05 bot liquidity
                    for bid in bids:
                        price = float(bid.get("price", 0))
                        size = float(bid.get("size", 0))
                        if 0.05 < price < 0.95 and size >= threshold:
                            key = f"{slug}:{token_id}:BID:{price:.2f}:{int(size)}"
                            if key not in alerted_orderbook_walls:
                                alerted_orderbook_walls.add(key)
                                send_telegram_btc_orderbook_alert(
                                    coin_symbol="BTC",
                                    side_str="ALIŞ (BID)",
                                    price=price,
                                    shares=size,
                                    outcome=outcome_str,
                                    market_title=title,
                                    market_slug=slug
                                )

                    # Asks (Satışlar) - Exclude 0.95-0.99 bot liquidity
                    for ask in asks:
                        price = float(ask.get("price", 0))
                        size = float(ask.get("size", 0))
                        if 0.05 < price < 0.95 and size >= threshold:
                            key = f"{slug}:{token_id}:ASK:{price:.2f}:{int(size)}"
                            if key not in alerted_orderbook_walls:
                                alerted_orderbook_walls.add(key)
                                send_telegram_btc_orderbook_alert(
                                    coin_symbol="BTC",
                                    side_str="SATIŞ (ASK)",
                                    price=price,
                                    shares=size,
                                    outcome=outcome_str,
                                    market_title=title,
                                    market_slug=slug
                                )

            except Exception as e:
                print(f"[BTC ORDERBOOK SCANNER ERROR] Error scanning slug {slug}: {e}", flush=True)
    except Exception as e:
        print(f"[BTC ORDERBOOK SCANNER ERROR] Top-level error: {e}", flush=True)

def btc_orderbook_scanner_loop():
    print("[INFO] Background BTC Orderbook Scanner Thread Started.", flush=True)
    while True:
        try:
            scan_btc_orderbook_walls()
        except Exception as e:
            print(f"[BTC ORDERBOOK SCANNER ERROR] Loop exception: {e}", flush=True)
        time.sleep(15)

def start_btc_orderbook_scanner():
    if os.environ.get("BTC_ORDERBOOK_SCANNER_STARTED") == "true":
        return
    os.environ["BTC_ORDERBOOK_SCANNER_STARTED"] = "true"
    print("[INFO] Spawning background BTC Orderbook Scanner thread...", flush=True)
    btc_thread = threading.Thread(target=btc_orderbook_scanner_loop, daemon=True)
    btc_thread.start()

def start_whale_scanner():
    if os.environ.get("WHALE_SCANNER_STARTED") == "true":
        return
    os.environ["WHALE_SCANNER_STARTED"] = "true"
    print("[INFO] Spawning background Whale Scanner thread...", flush=True)
    scanner_thread = threading.Thread(target=whale_scanner_loop, daemon=True)
    scanner_thread.start()
    start_bnb_whale_scanner()
    start_btc_orderbook_scanner()

# Start thread reliably when running in main app or when running under Gunicorn (which sets PORT environment variable)
if __name__ == "__main__" or "PORT" in os.environ:
    start_whale_scanner()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
