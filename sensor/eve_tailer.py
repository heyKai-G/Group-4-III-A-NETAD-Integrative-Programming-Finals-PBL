"""Follow Suricata's eve.json and store alert events in the database."""
import os
import time

from app.extensions import db
from app.models import Alert, AppSetting
from app.services.categorize import parse_eve_line

STATE_KEY = "eve_offset"


def _get_state():
    row = db.session.get(AppSetting, STATE_KEY)
    if not row or not row.value:
        return None, 0
    try:
        path, offset = row.value.rsplit("|", 1)
        return path, int(offset)
    except ValueError:
        return None, 0


def _save_state(path, offset):
    row = db.session.get(AppSetting, STATE_KEY)
    if row is None:
        row = AppSetting(key=STATE_KEY)
        db.session.add(row)
    row.value = f"{path}|{offset}"


def ingest_once(path, batch_limit=2000):
    """Read any new complete lines. Returns the number of alerts stored.

    The byte offset is saved in the database, so a restart resumes where it
    stopped and does not store the same alert twice.
    """
    try:
        size = os.stat(path).st_size
    except OSError:
        return 0
    saved_path, offset = _get_state()
    if saved_path != path or offset > size:
        # new file, or Suricata rotated/truncated it: start from the beginning
        offset = 0
    if offset == size:
        return 0
    stored = 0
    with open(path, "rb") as f:
        f.seek(offset)
        lines = 0
        while lines < batch_limit:
            start = f.tell()
            raw = f.readline()
            if not raw:
                break
            if not raw.endswith(b"\n"):       # partial line still being written
                f.seek(start)
                break
            lines += 1
            alert = parse_eve_line(raw.decode("utf-8", "replace"))
            if alert:
                db.session.add(Alert(**alert))
                stored += 1
        offset = f.tell()
    _save_state(path, offset)
    db.session.commit()
    return stored


def run(app, stop_event, interval=1.0):
    path = app.config["EVE_JSON_PATH"]
    while not stop_event.is_set():
        try:
            with app.app_context():
                ingest_once(path)
                db.session.remove()
        except Exception as exc:  # keep running; the dashboard shows status
            print(f"[eve] error: {exc!r}", flush=True)
            time.sleep(3)
        stop_event.wait(interval)
