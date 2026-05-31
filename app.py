import os
import re
import time
import requests
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
