import hashlib, json

GENESIS = "0" * 64


def _canonical(actor, action, object_id, detail, prev_hash):
    return json.dumps({"actor":actor,"action":action,"object_id":object_id,"detail":detail,"prev_hash":prev_hash}, sort_keys=True, separators=(",", ":"))


def append_audit(cur, actor: str, action: str, object_id: str | None = None, detail: dict | None = None):
    detail = detail or {}
    cur.execute("SELECT pg_advisory_xact_lock(894271)")
    cur.execute("SELECT entry_hash FROM vault_audit ORDER BY seq DESC LIMIT 1")
    row = cur.fetchone()
    prev_hash = row["entry_hash"] if row else GENESIS
    entry_hash = hashlib.sha256(_canonical(actor, action, object_id, detail, prev_hash).encode()).hexdigest()
    cur.execute("INSERT INTO vault_audit(actor,action,object_id,detail,prev_hash,entry_hash) VALUES (%s,%s,%s,%s::jsonb,%s,%s) RETURNING seq", (actor, action, object_id, json.dumps(detail), prev_hash, entry_hash))
    return cur.fetchone()["seq"]


def verify_chain(cur):
    cur.execute("SELECT seq,actor,action,object_id,detail,prev_hash,entry_hash FROM vault_audit ORDER BY seq")
    prev = GENESIS
    for r in cur.fetchall():
        expected = hashlib.sha256(_canonical(r["actor"], r["action"], r["object_id"], r["detail"], prev).encode()).hexdigest()
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return {"valid": False, "broken_at_seq": r["seq"]}
        prev = r["entry_hash"]
    return {"valid": True}
