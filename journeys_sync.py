"""Journeys nightly sync.

Reads the Gmail inbox over IMAP (same app password as Newsreel / The Signal)
and folds new events into events.json:

  * Self-emails with subject  "EVENT: <title>"   -> new event
      The first date found in the subject or body becomes the event date
      (day-first parsing, so 5/9 means 5 September). Body text becomes notes.
  * Self-emails with subject  "CANCEL: <fragment>" -> hides any event whose
      title contains the fragment (works on synced and seed events alike).
  * Any email carrying a .ics calendar attachment -> events for each VEVENT
      (this is how most airline / hotel confirmations arrive).

Seed events (source == "seed") are never modified, only hidden by CANCEL.
Synced events are marked fresh for 7 days so the app shows a "New" pill.
"""

import hashlib
import imaplib
import json
import os
import re
import sys
from datetime import date, datetime, timedelta
from email import message_from_bytes
from email.header import decode_header, make_header

from base64 import b64decode, b64encode

from dateutil import parser as dateparser
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256

try:
    from icalendar import Calendar
except ImportError:  # pragma: no cover
    Calendar = None

ADDR = os.environ["GMAIL_ADDRESS"]
APP_PW = os.environ["GMAIL_APP_PASSWORD"]
KEY = os.environ["JOURNEYS_KEY"]
PATH = "events.enc"


def _derive(passphrase: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt,
                      iterations=200_000).derive(passphrase.encode())


def decrypt_file(path: str, passphrase: str) -> dict:
    with open(path) as f:
        env = json.load(f)
    key = _derive(passphrase, b64decode(env["salt"]))
    pt = AESGCM(key).decrypt(b64decode(env["iv"]), b64decode(env["data"]), None)
    return json.loads(pt)


def encrypt_file(path: str, passphrase: str, payload: dict) -> None:
    salt, iv = os.urandom(16), os.urandom(12)
    key = _derive(passphrase, salt)
    ct = AESGCM(key).encrypt(
        iv, json.dumps(payload, ensure_ascii=False).encode(), None)
    with open(path, "w") as f:
        json.dump({"v": 1, "salt": b64encode(salt).decode(),
                   "iv": b64encode(iv).decode(),
                   "data": b64encode(ct).decode()}, f)
LOOKBACK_DAYS = 21
FRESH_DAYS = 7

WD = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
MO = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def dlabel(ds: str) -> str:
    d = date.fromisoformat(ds)
    return f"{WD[d.weekday()]} {d.day} {MO[d.month - 1]}"


def hid(*parts: str) -> str:
    return hashlib.md5("|".join(parts).encode()).hexdigest()[:10]


def hdr(msg, name: str) -> str:
    raw = msg.get(name, "")
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        return raw


def body_text(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", "replace")
                except Exception:
                    continue
        return ""
    try:
        return msg.get_payload(decode=True).decode(
            msg.get_content_charset() or "utf-8", "replace")
    except Exception:
        return ""


def load() -> dict:
    try:
        return decrypt_file(PATH, KEY)
    except (OSError, json.JSONDecodeError, ValueError, Exception):
        return {"events": []}


def make_event(eid, ds, title, sub="", details=None, location=None):
    ev = {
        "id": eid, "trip": "inbox", "kind": "event",
        "date": ds, "dlabel": dlabel(ds),
        "title": title[:120], "sub": sub[:90],
        "details": details or [], "todos": [],
        "source": "mail", "added": date.today().isoformat(),
    }
    if location:
        ev["details"].append(["Where", location[:120]])
    return ev


def parse_event_mail(subject, text):
    title = subject.split(":", 1)[1].strip() or "Untitled"
    anchor = (datetime.now() + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0)
    for candidate in (subject.split(":", 1)[1], text[:400]):
        try:
            dt = dateparser.parse(candidate, fuzzy=True, dayfirst=True,
                                  default=anchor)
            break
        except (ValueError, OverflowError):
            dt = None
    if dt is None:
        return None
    ds = dt.date().isoformat()
    note = text.strip().splitlines()
    details = [["Note", " ".join(note)[:300]]] if note and note[0] else []
    when = dt.strftime("%H:%M")
    sub = "" if when == "00:00" else when
    return make_event("m-" + hid(title, ds), ds, title, sub, details)


def parse_ics(payload):
    out = []
    if Calendar is None:
        return out
    try:
        cal = Calendar.from_ical(payload)
    except Exception:
        return out
    cancelled = str(cal.get("METHOD", "")).upper() == "CANCEL"
    for comp in cal.walk("VEVENT"):
        try:
            start = comp["DTSTART"].dt
        except Exception:
            continue
        d = start.date() if isinstance(start, datetime) else start
        title = str(comp.get("SUMMARY", "Calendar event"))
        loc = str(comp.get("LOCATION", "")) or None
        sub = start.strftime("%H:%M") if isinstance(start, datetime) else ""
        uid = str(comp.get("UID", title))
        ev = make_event("i-" + hid(uid, d.isoformat()), d.isoformat(),
                        title, sub, [["Source", "calendar attachment"]], loc)
        if cancelled or str(comp.get("STATUS", "")).upper() == "CANCELLED":
            ev["hidden"] = True
        out.append(ev)
    return out


def main() -> int:
    data = load()
    by_id = {e["id"]: e for e in data["events"]}
    today = date.today()
    added, hidden = 0, 0

    box = imaplib.IMAP4_SSL("imap.gmail.com")
    box.login(ADDR, APP_PW)
    box.select("INBOX")
    since = (today - timedelta(days=LOOKBACK_DAYS)).strftime("%d-%b-%Y")
    _, ids = box.search(None, f'(SINCE "{since}")')

    for num in ids[0].split():
        _, raw = box.fetch(num, "(RFC822)")
        if not raw or not raw[0]:
            continue
        msg = message_from_bytes(raw[0][1])
        subject = hdr(msg, "Subject").strip()
        sender = hdr(msg, "From")
        is_self = ADDR.lower() in sender.lower()
        upper = subject.upper()

        if is_self and upper.startswith("EVENT:"):
            ev = parse_event_mail(subject, body_text(msg))
            if ev and ev["id"] not in by_id:
                by_id[ev["id"]] = ev
                added += 1

        elif is_self and upper.startswith("CANCEL:"):
            frag = subject.split(":", 1)[1].strip().lower()
            if frag:
                for ev in by_id.values():
                    if frag in ev["title"].lower() and not ev.get("hidden"):
                        ev["hidden"] = True
                        hidden += 1

        for part in msg.walk():
            fname = (part.get_filename() or "").lower()
            if part.get_content_type() == "text/calendar" or fname.endswith(".ics"):
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                for ev in parse_ics(payload):
                    prev = by_id.get(ev["id"])
                    if ev.get("hidden") and prev:
                        prev["hidden"] = True
                        hidden += 1
                    elif ev["id"] not in by_id and not ev.get("hidden"):
                        by_id[ev["id"]] = ev
                        added += 1
    box.logout()

    for ev in by_id.values():
        if ev.get("source") == "mail":
            age = (today - date.fromisoformat(ev.get("added", "2000-01-01"))).days
            ev["fresh"] = age <= FRESH_DAYS

    events = sorted(by_id.values(), key=lambda e: e["date"])
    if events != data.get("events"):
        payload = {"generated": datetime.utcnow().isoformat(timespec="minutes"),
                   "events": events,
                   "spans": data.get("spans", []),
                   "chiplbl": data.get("chiplbl", {})}
        encrypt_file(PATH, KEY, payload)
        print(f"events.enc updated: +{added} new, {hidden} hidden, "
              f"{len(events)} total")
    else:
        print("no changes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
