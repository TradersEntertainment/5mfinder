import os
import re
import time
import requests
from flask import Flask, request, jsonify, render_template
from web3 import Web3

# Try importing Geth PoA middleware across all possible web3.py versions (v5, v6, v7, v8)
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

# Public working Polygon RPC
RPC_URL = "https://1rpc.io/matic"
CTF_ADDRESS = Web3.to_checksum_address("0x4d97dcd97ec945f40cf65f87097ace5ea0476045")

# Standard CTF ABI for payouts and event parsing
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
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "redeemer", "type": "address"},
            {"indexed": True, "name": "collateralToken", "type": "address"},
            {"indexed": True, "name": "parentCollectionId", "type": "bytes32"},
            {"indexed": False, "name": "conditionId", "type": "bytes32"},
            {"indexed": False, "name": "indexSets", "type": "uint256[]"},
            {"indexed": False, "name": "payout", "type": "uint256"}
        ],
        "name": "PayoutRedemption",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "operator", "type": "address"},
            {"indexed": True, "name": "from", "type": "address"},
            {"indexed": True, "name": "to", "type": "address"},
            {"indexed": False, "name": "id", "type": "uint256"},
            {"indexed": False, "name": "value", "type": "uint256"}
        ],
        "name": "TransferSingle",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "operator", "type": "address"},
            {"indexed": True, "name": "from", "type": "address"},
            {"indexed": True, "name": "to", "type": "address"},
            {"indexed": False, "name": "ids", "type": "uint256[]"},
            {"indexed": False, "name": "values", "type": "uint256[]"}
        ],
        "name": "TransferBatch",
        "type": "event"
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
    for attempt in range(5):
        try:
            w3 = Web3(Web3.HTTPProvider(RPC_URL))
            # Inject PoA middleware if successfully imported
            if poa_middleware is not None:
                w3.middleware_onion.inject(poa_middleware, layer=0)
            if w3.is_connected():
                return w3
        except Exception as e:
            print(f"Connection attempt {attempt} failed: {e}")
            time.sleep(2)
    raise Exception("Failed to connect to RPC")

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
            time.sleep(1.5 ** attempt + 0.5)
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
            return jsonify({"error": "Lütfen bir Polymarket linki veya slug girin."}), 400
            
        slug = extract_slug(url_or_slug)
        
        # 1. Fetch Market details from Gamma API
        gamma_url = f"https://gamma-api.polymarket.com/markets?slug={slug}"
        resp = requests.get(gamma_url, timeout=10)
        if resp.status_code != 200:
            return jsonify({"error": "Polymarket API'sine bağlanılamadı."}), 500
            
        markets_data = resp.json()
        if not markets_data or not isinstance(markets_data, list):
            return jsonify({"error": "Bu linke ait aktif bir market bulunamadı. Lütfen slug'ı kontrol edin."}), 404
            
        market = markets_data[0]
        
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
            return jsonify({"error": "Market akıllı sözleşme verileri eksik."}), 400
            
        up_token_dec = int(clob_token_ids[0])
        down_token_dec = int(clob_token_ids[1])
        
        start_date_str = market.get("startDate")
        end_date_str = market.get("endDate")
        
        from dateutil import parser
        try:
            start_ts = int(parser.isoparse(start_date_str).timestamp())
        except Exception:
            start_ts = int(time.time()) - 3600
            
        try:
            end_ts = int(parser.isoparse(end_date_str).timestamp())
        except Exception:
            end_ts = int(time.time()) + 300
            
        w3 = get_web3()
        contract = w3.eth.contract(address=CTF_ADDRESS, abi=CTF_ABI)
        
        start_block = estimate_block_by_timestamp(w3, start_ts - 600)
        
        latest_block_data = w3.eth.get_block("latest")
        latest_block = latest_block_data["number"]
        
        target_end_block = estimate_block_by_timestamp(w3, end_ts + 2700)
        if target_end_block > latest_block:
            target_end_block = latest_block
            
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
        
        chunk_size = 50
        redemptions_raw = []
        transfers_raw = []
        
        combined_topics = [[payout_redemption_topic0, transfer_single_topic0, transfer_batch_topic0]]
        
        for chunk_start in range(start_block, target_end_block + 1, chunk_size):
            chunk_end = min(chunk_start + chunk_size - 1, target_end_block)
            try:
                logs = call_rpc_logs(w3, chunk_start, chunk_end, combined_topics)
                for log in logs:
                    t0 = log["topics"][0].hex()
                    
                    if t0 == payout_redemption_topic0[2:]:
                        try:
                            decoded = contract.events.PayoutRedemption().process_log(log)
                            args = decoded["args"]
                            if args["conditionId"].hex() == condition_id[2:]:
                                redemptions_raw.append({
                                    "tx_hash": log["transactionHash"].hex(),
                                    "block": log["blockNumber"],
                                    "redeemer": args["redeemer"],
                                    "payout": args["payout"] / 1e6,
                                    "indexSets": args["indexSets"]
                                })
                        except Exception:
                            pass
                            
                    elif t0 == transfer_single_topic0[2:]:
                        try:
                            decoded = contract.events.TransferSingle().process_log(log)
                            args = decoded["args"]
                            if args["id"] in (up_token_dec, down_token_dec):
                                transfers_raw.append({
                                    "block": log["blockNumber"],
                                    "from": args["from"],
                                    "to": args["to"],
                                    "id": args["id"],
                                    "value": args["value"]
                                })
                        except Exception:
                            pass
                            
                    elif t0 == transfer_batch_topic0[2:]:
                        try:
                            decoded = contract.events.TransferBatch().process_log(log)
                            args = decoded["args"]
                            for tid, val in zip(args["ids"], args["values"]):
                                if tid in (up_token_dec, down_token_dec):
                                    transfers_raw.append({
                                        "block": log["blockNumber"],
                                        "from": args["from"],
                                        "to": args["to"],
                                        "id": tid,
                                        "value": val
                                    })
                        except Exception:
                            pass
            except Exception:
                pass
            time.sleep(0.1)
            
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
                
        for tx in transfers_raw:
            frm = tx["from"]
            to = tx["to"]
            tid = tx["id"]
            val = tx["value"]
            
            update_balance(frm, tid, -val)
            update_balance(to, tid, val)
            
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
                up_peak_positions.append({
                    "account": account,
                    "peak": up_peak,
                    "current": curr_up
                })
            if down_peak > 0.1:
                down_peak_positions.append({
                    "account": account,
                    "peak": down_peak,
                    "current": curr_down
                })
                
        up_peak_positions.sort(key=lambda x: x["peak"], reverse=True)
        down_peak_positions.sort(key=lambda x: x["peak"], reverse=True)
        
        redeemers_list = []
        for acc, summary in redeemers_summary.items():
            if summary["total_payout"] > 0.01:
                redeemers_list.append({
                    "account": acc,
                    "payout": summary["total_payout"],
                    "tx_count": summary["tx_count"],
                    "latest_tx": summary["txs"][-1]
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
                "resolvedBlock": target_end_block
            },
            "top_up": up_peak_positions[:50],
            "top_down": down_peak_positions[:50],
            "redeemers": redeemers_list[:50]
        }
        
        return jsonify(result)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Bir hata oluştu: {str(e)}"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
