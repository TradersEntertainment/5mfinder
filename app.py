import os
import re
import json
import time
import requests
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# High-performance public Polygon RPCs
RPC_URLS = [
    "https://polygon.drpc.org",
    "https://polygon.publicnode.com",
    "https://polygon-rpc.com",
    "https://1rpc.io/matic",
    "https://polygon-mainnet.public.blastapi.io"
]

CTF_ADDRESS = "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045"

# Pre-compute event topic hashes using web3 (only for keccak, NOT for ABI decoding)
try:
    from web3 import Web3
    _w3_hash = Web3()
    PAYOUT_REDEMPTION_TOPIC = "0x" + _w3_hash.keccak(text="PayoutRedemption(address,address,bytes32,bytes32,uint256[],uint256)").hex()
    TRANSFER_SINGLE_TOPIC = "0x" + _w3_hash.keccak(text="TransferSingle(address,address,address,uint256,uint256)").hex()
    TRANSFER_BATCH_TOPIC = "0x" + _w3_hash.keccak(text="TransferBatch(address,address,address,uint256[],uint256[])").hex()
except Exception:
    # Hardcoded fallback keccak256 values
    PAYOUT_REDEMPTION_TOPIC = "0x2682012a4a4f1973119f1c9b90745ac1f0ab1a2d3a40a76a7d4c3a4a9ebf3a18"
    TRANSFER_SINGLE_TOPIC = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
    TRANSFER_BATCH_TOPIC = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb"


def extract_slug(url_or_slug):
    """Extract market slug from Polymarket URL or raw slug."""
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


def rpc_call(method, params=None, rpc_url=None, retries=3):
    """Make a raw JSON-RPC call. No web3.py ABI codec = no cytoolz crash on Python 3.13."""
    if params is None:
        params = []
    urls = [rpc_url] if rpc_url else RPC_URLS

    for url in urls:
        for attempt in range(retries):
            try:
                resp = requests.post(url, json={
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params,
                    "id": 1
                }, timeout=15)
                data = resp.json()
                if "error" in data:
                    continue
                return data.get("result")
            except Exception:
                time.sleep(0.3 * (attempt + 1))
    return None


def get_latest_block():
    """Get the latest block number as int."""
    result = rpc_call("eth_blockNumber")
    if result:
        return int(result, 16)
    return None


def get_block_timestamp(block_num):
    """Get timestamp for a specific block."""
    result = rpc_call("eth_getBlockByNumber", [hex(block_num), False])
    if result and "timestamp" in result:
        return int(result["timestamp"], 16)
    return None


def estimate_block_by_timestamp(target_ts):
    """Interpolation search to find Polygon block number for a unix timestamp."""
    latest_num = get_latest_block()
    if latest_num is None:
        raise Exception("Cannot get latest block")

    latest_ts = get_block_timestamp(latest_num)
    if latest_ts is None:
        raise Exception("Cannot get latest block timestamp")

    if target_ts >= latest_ts:
        return latest_num

    ref_num = max(1, latest_num - 20000)
    ref_ts = get_block_timestamp(ref_num)
    if ref_ts is None:
        ref_ts = latest_ts - 42000

    avg_block_time = (latest_ts - ref_ts) / max(1, latest_num - ref_num)
    if avg_block_time <= 0:
        avg_block_time = 2.1

    estimated = int(latest_num - (latest_ts - target_ts) / avg_block_time)

    for _ in range(8):
        if estimated > latest_num:
            estimated = latest_num
        if estimated < 1:
            estimated = 1
        ts = get_block_timestamp(estimated)
        if ts is None:
            break
        diff = target_ts - ts
        if abs(diff) <= 15:
            return estimated
        adj = int(diff / avg_block_time)
        if adj == 0:
            adj = 1 if diff > 0 else -1
        estimated += adj

    return estimated


def fetch_logs(from_block, to_block, topics):
    """Fetch logs via raw JSON-RPC eth_getLogs. No web3.py codec needed."""
    params = [{
        "fromBlock": hex(from_block),
        "toBlock": hex(to_block),
        "address": CTF_ADDRESS,
        "topics": topics
    }]

    for url in RPC_URLS:
        try:
            result = rpc_call("eth_getLogs", params, rpc_url=url, retries=2)
            if result is not None:
                return result
        except Exception:
            continue
    return []


def hex_to_address(hex_str):
    """Extract a checksummed-style address from a 32-byte hex topic."""
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return "0x" + hex_str[-40:]


def decode_transfer_single_data(data_hex):
    """Decode TransferSingle data field: (uint256 id, uint256 value)."""
    if data_hex.startswith("0x"):
        data_hex = data_hex[2:]
    token_id = int(data_hex[0:64], 16)
    value = int(data_hex[64:128], 16)
    return token_id, value


def decode_payout_redemption_data(data_hex):
    """
    Decode PayoutRedemption event data (non-indexed):
      bytes32 conditionId, uint256[] indexSets, uint256 payout

    ABI encoding layout:
      [0:64]   bytes32 conditionId
      [64:128] offset to uint256[] indexSets (dynamic)
      [128:192] uint256 payout
      [offset..] array length + array elements
    """
    if data_hex.startswith("0x"):
        data_hex = data_hex[2:]

    condition_id = data_hex[0:64]
    payout = int(data_hex[128:192], 16)

    # Dynamic array
    array_offset = int(data_hex[64:128], 16) * 2  # byte offset to hex-char offset
    array_length = int(data_hex[array_offset:array_offset + 64], 16)
    index_sets = []
    for i in range(array_length):
        s = array_offset + 64 + (i * 64)
        index_sets.append(int(data_hex[s:s + 64], 16))

    return condition_id, index_sets, payout


def decode_transfer_batch_data(data_hex):
    """Decode TransferBatch event data: (uint256[] ids, uint256[] values)."""
    if data_hex.startswith("0x"):
        data_hex = data_hex[2:]

    ids_offset = int(data_hex[0:64], 16) * 2
    vals_offset = int(data_hex[64:128], 16) * 2

    ids_len = int(data_hex[ids_offset:ids_offset + 64], 16)
    ids = [int(data_hex[ids_offset + 64 + i * 64:ids_offset + 128 + i * 64], 16) for i in range(ids_len)]

    vals_len = int(data_hex[vals_offset:vals_offset + 64], 16)
    vals = [int(data_hex[vals_offset + 64 + i * 64:vals_offset + 128 + i * 64], 16) for i in range(vals_len)]

    return ids, vals


def check_payout_numerators(condition_id, index):
    """Call payoutNumerators(bytes32, uint256) on the CTF contract via eth_call."""
    func_selector = "0xfe14112d"
    cid = condition_id[2:] if condition_id.startswith("0x") else condition_id
    cid = cid.zfill(64)
    idx_hex = hex(index)[2:].zfill(64)
    call_data = func_selector + cid + idx_hex

    result = rpc_call("eth_call", [
        {"to": CTF_ADDRESS, "data": call_data},
        "latest"
    ])

    if result and result != "0x":
        return int(result, 16)
    return 0


# ──────────────────────────────────────────────
# Flask Routes
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        data = request.json or {}
        url_or_slug = data.get("url")
        if not url_or_slug:
            return jsonify({"error": "Lutfen bir Polymarket linki veya slug girin."}), 200

        slug = extract_slug(url_or_slug)

        # ── 1. Fetch Market from Gamma API ──
        market = None
        for endpoint in ["markets", "events"]:
            gamma_url = f"https://gamma-api.polymarket.com/{endpoint}?slug={slug}"
            try:
                resp = requests.get(gamma_url, timeout=10)
                if resp.status_code == 200:
                    payload = resp.json()
                    if payload and isinstance(payload, list) and len(payload) > 0:
                        item = payload[0]
                        if endpoint == "events":
                            event_markets = item.get("markets", [])
                            if event_markets:
                                market = event_markets[0]
                        else:
                            market = item
                    if market:
                        break
            except Exception:
                continue

        if not market:
            return jsonify({"error": "Bu linke ait aktif veya gecmis bir market bulunamadi."}), 200

        title = market.get("question", "Bilinmeyen Piyasa")
        description = market.get("description", "")
        condition_id = market.get("conditionId", "")
        clob_token_ids = market.get("clobTokenIds", "[]")

        if isinstance(clob_token_ids, str):
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
            return jsonify({"error": "Market akilli sozlesme verileri eksik."}), 200

        up_token_dec = int(clob_token_ids[0])
        down_token_dec = int(clob_token_ids[1])

        start_date_str = market.get("startDate")
        end_date_str = market.get("endDate")

        from dateutil import parser as dateparser
        try:
            start_ts = int(dateparser.isoparse(start_date_str).timestamp())
        except Exception:
            start_ts = int(time.time()) - 3600

        try:
            end_ts = int(dateparser.isoparse(end_date_str).timestamp())
        except Exception:
            end_ts = int(time.time()) + 300

        # ── 2. Estimate block range ──
        start_block = estimate_block_by_timestamp(start_ts - 600)

        latest_block = get_latest_block()
        if latest_block is None:
            return jsonify({"error": "Polygon agina baglanilamadi."}), 200

        target_end_block = estimate_block_by_timestamp(end_ts + 2700)
        if target_end_block > latest_block:
            target_end_block = latest_block

        # ── 3. Check if market resolved ──
        is_resolved = False
        winning_outcome = "Belirlenmedi"
        payouts = [0, 0]
        try:
            payouts[0] = check_payout_numerators(condition_id, 0)
            payouts[1] = check_payout_numerators(condition_id, 1)
            if payouts[0] > 0 or payouts[1] > 0:
                is_resolved = True
                if payouts[0] > payouts[1]:
                    winning_outcome = outcomes[0] if len(outcomes) > 0 else "UP"
                else:
                    winning_outcome = outcomes[1] if len(outcomes) > 1 else "DOWN"
        except Exception:
            pass

        # ── 4. Scan blockchain logs via raw JSON-RPC ──
        chunk_size = 3000
        redemptions_raw = []
        transfers_raw = []

        combined_topics = [[
            PAYOUT_REDEMPTION_TOPIC,
            TRANSFER_SINGLE_TOPIC,
            TRANSFER_BATCH_TOPIC
        ]]

        payout_hex = PAYOUT_REDEMPTION_TOPIC[2:].lower()
        tsingle_hex = TRANSFER_SINGLE_TOPIC[2:].lower()
        tbatch_hex = TRANSFER_BATCH_TOPIC[2:].lower()
        cond_id_clean = (condition_id[2:] if condition_id.startswith("0x") else condition_id).lower()

        for chunk_start in range(start_block, target_end_block + 1, chunk_size):
            chunk_end = min(chunk_start + chunk_size - 1, target_end_block)
            try:
                logs = fetch_logs(chunk_start, chunk_end, combined_topics)
                if not logs:
                    continue

                for log in logs:
                    topics = log.get("topics", [])
                    if not topics:
                        continue

                    t0 = topics[0]
                    if t0.startswith("0x"):
                        t0 = t0[2:]
                    t0 = t0.lower()

                    log_data = log.get("data", "0x")
                    block_num = int(log.get("blockNumber", "0x0"), 16) if isinstance(log.get("blockNumber"), str) else log.get("blockNumber", 0)
                    tx_hash = log.get("transactionHash", "")

                    if t0 == payout_hex:
                        try:
                            redeemer = hex_to_address(topics[1])
                            cond_decoded, index_sets, payout_val = decode_payout_redemption_data(log_data)
                            if cond_decoded.lower() == cond_id_clean:
                                redemptions_raw.append({
                                    "tx_hash": tx_hash,
                                    "block": block_num,
                                    "redeemer": redeemer,
                                    "payout": payout_val / 1e6,
                                    "indexSets": index_sets
                                })
                        except Exception:
                            pass

                    elif t0 == tsingle_hex:
                        try:
                            frm = hex_to_address(topics[2])
                            to = hex_to_address(topics[3])
                            tid, val = decode_transfer_single_data(log_data)
                            if tid in (up_token_dec, down_token_dec):
                                transfers_raw.append({"block": block_num, "from": frm, "to": to, "id": tid, "value": val})
                        except Exception:
                            pass

                    elif t0 == tbatch_hex:
                        try:
                            frm = hex_to_address(topics[2])
                            to = hex_to_address(topics[3])
                            tids, vals = decode_transfer_batch_data(log_data)
                            for tid, val in zip(tids, vals):
                                if tid in (up_token_dec, down_token_dec):
                                    transfers_raw.append({"block": block_num, "from": frm, "to": to, "id": tid, "value": val})
                        except Exception:
                            pass
            except Exception:
                pass
            time.sleep(0.1)

        # ── 5. Aggregate balances ──
        balances = {}
        max_balances = {}
        ZERO = "0x0000000000000000000000000000000000000000"

        def update_balance(account, token_id, amount):
            al = account.lower()
            if al == ZERO:
                return
            if al not in balances:
                balances[al] = {up_token_dec: 0, down_token_dec: 0}
            if al not in max_balances:
                max_balances[al] = {up_token_dec: 0, down_token_dec: 0}
            balances[al][token_id] += amount
            if balances[al][token_id] > max_balances[al][token_id]:
                max_balances[al][token_id] = balances[al][token_id]

        for tx in transfers_raw:
            update_balance(tx["from"], tx["id"], -tx["value"])
            update_balance(tx["to"], tx["id"], tx["value"])

        # ── 6. Aggregate redeemers ──
        redeemers_summary = {}
        for r in redemptions_raw:
            redeemer = r["redeemer"].lower()
            if redeemer not in redeemers_summary:
                redeemers_summary[redeemer] = {"total_payout": 0.0, "tx_count": 0, "txs": []}
            redeemers_summary[redeemer]["total_payout"] += r["payout"]
            redeemers_summary[redeemer]["tx_count"] += 1
            if r["tx_hash"] not in redeemers_summary[redeemer]["txs"]:
                redeemers_summary[redeemer]["txs"].append(r["tx_hash"])

        # ── 7. Build result ──
        up_peaks = []
        down_peaks = []
        for acct, mx in max_balances.items():
            up_p = mx[up_token_dec] / 1e6
            dn_p = mx[down_token_dec] / 1e6
            cu = balances[acct][up_token_dec] / 1e6
            cd = balances[acct][down_token_dec] / 1e6
            if abs(cu) < 0.01: cu = 0.0
            if abs(cd) < 0.01: cd = 0.0
            if up_p > 0.1:
                up_peaks.append({"account": acct, "peak": up_p, "current": cu})
            if dn_p > 0.1:
                down_peaks.append({"account": acct, "peak": dn_p, "current": cd})

        up_peaks.sort(key=lambda x: x["peak"], reverse=True)
        down_peaks.sort(key=lambda x: x["peak"], reverse=True)

        rdm_list = []
        for acc, s in redeemers_summary.items():
            if s["total_payout"] > 0.01:
                rdm_list.append({"account": acc, "payout": s["total_payout"], "tx_count": s["tx_count"], "latest_tx": s["txs"][-1]})
        rdm_list.sort(key=lambda x: x["payout"], reverse=True)

        return jsonify({
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
            "top_up": up_peaks[:50],
            "top_down": down_peaks[:50],
            "redeemers": rdm_list[:50]
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Sunucu hatasi: {str(e)}"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
