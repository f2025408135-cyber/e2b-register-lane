"""E2B register lane - full account flow from a GitHub Actions runner IP.

Rail: catch-all domain forwarded to the anonysusarchiver Gmail inbox; codes are
read from the Gmail atom feed.
Gmail cookies: repo secret GMAIL_CK_JSON (scoped cookie jar JSON).

Flow: register (auth.e2b.dev Kratos) -> wait code (Gmail atom feed) -> verify ->
console oauth -> workspaces.me -> getCredit -> createApiKey -> api.e2b.dev test.

Run: python scripts/e2b_reg.py --email a@b.c [--password ...]
Prints: CANARY_RESULT {json}
"""
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone


UI = "https://console.e2b.dev"
AUTH = "https://auth.e2b.dev"
NAME = "Lane Kessler"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
ZW = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u034f\u00ad"), None)


def L(*a):
    line = f"[{datetime.now(timezone.utc).isoformat()}] " + " ".join(str(x) for x in a)
    print(line, flush=True)

def canary(email: str, password: str = ""):
    import curl_cffi
    from curl_cffi import requests as creq

    out = {"email": email, "started": datetime.now(timezone.utc).isoformat()}

    def new_session():
        s = creq.Session(impersonate="chrome", timeout=40)
        s.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
        return s

    def retry(fn, n=3, tag=""):
        for i in range(n):
            try:
                return fn()
            except Exception as e:
                if i == n - 1:
                    raise
                L(f"RETRY {i+1} {tag} {e}")
                time.sleep(2 + 2 * i)

    # ----- gmail rail -----
    def gmail_session():
        raw = os.environ.get("GMAIL_CK_JSON", "")
        if not raw:
            raise RuntimeError("GMAIL_CK_JSON missing")
        allc = json.loads(raw)
        scoped = [c for c in allc if c.get("domain") in ("mail.google.com", ".google.com")]
        s = creq.Session(impersonate="chrome", timeout=25)
        s.headers.update(
            {
                "Cookie": "; ".join(f"{c['name']}={c['value']}" for c in scoped),
                "Accept-Language": "en-US,en;q=0.9",
            }
        )
        return s

    def feed_entries(gs):
        r = gs.get("https://mail.google.com/mail/feed/atom", allow_redirects=False)
        if r.status_code != 200:
            return None
        entries = []
        for m in re.finditer(r"(?s)<entry>(.*?)</entry>", r.text):
            blk = m.group(1)
            th = re.search(r"tag:gmail\.google\.com,2004:(\d+)", blk)
            em = re.search(r"<email>([^<]+)</email>", blk)
            md = re.search(r"<modified>([^<]+)</modified>", blk)
            entries.append(
                {
                    "thread": th.group(1) if th else None,
                    "email": em.group(1) if em else "",
                    "modified": md.group(1) if md else "",
                }
            )
        return entries

    def thread_codes(gs, thread_id):
        r = gs.get(
            f"https://mail.google.com/mail/u/0/?ui=2&ik=0&view=pt&permthid=thread-f%3A{thread_id}&search=all",
            allow_redirects=False,
        )
        if r.status_code != 200:
            return []
        txt = re.sub(r"(?s)<[^>]+>", " ", r.text).translate(ZW).replace("\u00a0", " ")
        txt = " ".join(txt.split())
        parts = re.split(r"(\w{3}, \w{3} \d{1,2}, \d{4} at \d+:\d+ [AP]M)", txt)
        msgs = []
        for i in range(1, len(parts) - 1, 2):
            msgs.append({"date": parts[i], "codes": re.findall(r"\b\d{6}\b", parts[i + 1][:1800])[:3]})
        return msgs

    def wait_code(gs, after_iso, timeout=420):
        t0 = time.time()
        while time.time() - t0 < timeout:
            entries = retry(lambda: feed_entries(gs), 2, "feed")
            if entries is None:
                L("GMAIL FEED FAILED (cookies stale?)")
                return None
            for e in entries:
                if e["email"] == "account@mail.e2b.dev" and e["modified"] > after_iso and e["thread"]:
                    L(f"new E2B mail: thread={e['thread']} modified={e['modified']}")
                    msgs = retry(lambda: thread_codes(gs, e["thread"]), 2, "pt")
                    for m in reversed(msgs):
                        if m["codes"]:
                            L(f"codes from {m['date']}: {m['codes']}")
                            return m["codes"]
                    for m in msgs:
                        if m["codes"]:
                            L(f"codes (older msg) {m['date']}: {m['codes']}")
                            return m["codes"]
            time.sleep(12)
        L("TIMEOUT waiting for verification email")
        return None

    # ----- e2b -----
    def register(s, email, password):
        r = retry(lambda: s.get(f"{AUTH}/self-service/registration/api", headers={"Accept": "application/json"}), 3, "reg")
        flow = r.json()
        L(f"reg flow {flow.get('id')} state={flow.get('state')}")
        out["reg_flow_state"] = flow.get("state")
        action = flow["ui"]["action"]
        r2 = retry(
            lambda: s.post(
                action,
                data=json.dumps({"method": "password", "traits": {"email": email, "name": NAME}, "password": password}),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            ),
            3,
            "regpost",
        )
        L(f"register -> {r2.status_code}")
        out["register_raw"] = r2.text[:500]
        try:
            j = r2.json()
        except Exception as e:
            L("register body not json: " + r2.text[:300])
            raise
        out["register_resp"] = {k: j.get(k) for k in ("state", "session", "ui", "error") if k in j}
        fid = None
        sid = (j.get("session") or {}).get("id")
        iid = (j.get("session") or {}).get("identity", {}).get("id") or (j.get("identity") or {}).get("id")
        for c in j.get("continue_with") or []:
            if c.get("action") == "show_verification_ui":
                fid = c["flow"]["id"]
        out["reg_messages"] = (j.get("ui") or {}).get("messages") or []
        L("register messages: " + json.dumps(out["reg_messages"])[:200])
        return fid, sid, iid, j

    def verify(s, email, fid, codes):
        for code in codes:
            r = retry(
                lambda: s.post(
                    f"{AUTH}/self-service/verification?flow={fid}",
                    data=json.dumps({"method": "code", "email": email, "code": code}),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                ),
                3,
                "verify",
            )
            try:
                j = r.json()
                ok = j.get("state") == "passed_challenge"
                msg = json.dumps(j.get("ui", {}).get("messages", []))[:150]
            except Exception:
                j, ok, msg = {}, False, r.text[:150]
            L(f"verify code {code} -> {r.status_code} state={j.get('state')} {msg}")
            if ok:
                return True
        return False

    def console_login(s, email, password):
        r = retry(lambda: s.get(f"{UI}/api/auth/oauth/start?intent=signin", allow_redirects=False, headers={"Accept": "text/html"}), 3, "cl")
        url = r.headers.get("location", "")
        final = url
        html = ""
        for i in range(30):
            r = s.get(url, allow_redirects=False, headers={"Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"})
            loc = r.headers.get("location", "")
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                if loc.startswith("http"):
                    url = loc
                elif loc.startswith("/"):
                    url = re.match(r"https://[^/]+", url).group(0) + loc
                continue
            final = url
            html = r.text
            break
        m = re.search(r"flow=([0-9a-f-]{36})", final or "")
        if not m:
            L(f"console-login: no flow in {final[:120]}")
            return False
        F = m.group(1)
        mm = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        csrf1 = mm.group(1) if mm else None
        if not csrf1:
            L("no csrf1")
            return False

        def post_login(csrf, method, extra):
            body = {"csrf_token": csrf, "identifier": email, "method": method}
            body.update(extra)
            return s.post(
                f"{UI}/self-service/login?flow={F}",
                data=json.dumps(body),
                headers={"Content-Type": "application/json", "Accept": "application/json", "Origin": UI, "Referer": f"{UI}/login?flow={F}"},
                allow_redirects=False,
            )

        r3 = post_login(csrf1, "identifier_first", {})
        csrf2 = None
        try:
            for n in (r3.json().get("ui") or {}).get("nodes", []):
                a = n.get("attributes") or {}
                if a.get("name") == "csrf_token":
                    csrf2 = a.get("value")
        except Exception:
            pass
        if not csrf2:
            L("no csrf2: " + r3.text[:150])
            return False
        r4 = post_login(csrf2, "password", {"password": password})
        redir = None
        try:
            reason = (r4.json().get("error") or {}).get("reason") or ""
            mm = re.search(r"https://console\.e2b\.dev/oauth2/auth\S+", reason) or re.search(r"https://console\.e2b\.dev/oauth2/auth\S+", r4.text)
            if mm:
                redir = mm.group(0)
        except Exception:
            pass
        if not redir:
            L("no oauth redirect: " + r4.text[:150])
            return False
        url = redir
        for i in range(40):
            r = s.get(url, allow_redirects=False, headers={"Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"})
            loc = r.headers.get("location", "")
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                if loc.startswith("http"):
                    url = loc
                elif loc.startswith("/"):
                    url = re.match(r"https://[^/]+", url).group(0) + loc
                continue
            break
        have = any(c.name == "__Host-e2b_session" for c in s.cookies.jar)
        L(f"console session cookie: {have}")
        return have

    def trpc_get(s, path, inp):
        import urllib.parse

        if inp is None:
            inputjson = {"0": {"json": None, "meta": {"values": ["undefined"]}}}
        else:
            inputjson = {"0": {"json": inp}}
        url = f"{UI}/api/trpc/{path}?batch=1&input={urllib.parse.quote(json.dumps(inputjson))}"
        return s.get(url, headers={"Accept": "application/json", "Referer": f"{UI}/", "Origin": UI})

    def trpc_post(s, path, inp):
        url = f"{UI}/api/trpc/{path}?batch=1"
        return s.post(url, data=json.dumps({"0": {"json": inp}}), headers={"Content-Type": "application/json", "Accept": "application/json", "Referer": f"{UI}/", "Origin": UI})

    # ================= MAIN =================
    prefix = email.split("@")[0]
    password = password or ("E2b!" + secrets.token_urlsafe(9).replace("-", "k").replace("_", "m")[:10] + "Q7")
    out["password"] = password
    try:
        for c in creq.get("https://api.ipify.org?format=json", timeout=20).json().items():
            out[c[0]] = c[1]
    except Exception as e:
        out["ipify_err"] = str(e)[:100]
    L(f"FACTORY START email={email} ip={out.get('ip')}")

    s = new_session()
    reg_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    fid, sid, iid, jreg = register(s, email, password)
    out["fid"], out["sid"], out["iid"] = fid, sid, iid
    if sid and not fid:
        L("registration returned session directly (no verify needed)")
        out["direct_session"] = True
    elif fid:
        gs = gmail_session()
        codes = wait_code(gs, reg_start)
        out["codes"] = codes
        if not codes:
            out["result"] = "ABORT_NO_CODE"
            return json.dumps(out)
        if not verify(s, email, fid, codes):
            out["result"] = "ABORT_VERIFY_FAIL"
            return json.dumps(out)
    else:
        out["result"] = "ABORT_NO_FLOW"
        return json.dumps(out)

    if not console_login(s, email, password):
        time.sleep(3)
        if not console_login(s, email, password):
            out["result"] = "ABORT_CONSOLE_LOGIN"
            return json.dumps(out)

    r = retry(lambda: trpc_get(s, "workspaces.me", None), 2, "ws")
    j = r.json()
    ws = j[0]["result"]["data"]["json"]["workspaces"][0]
    wid = ws["id"]
    proj = (ws.get("projects") or [{}])[0]
    slug = proj.get("slug") or ws.get("slug") or ""
    out["workspace"] = {"id": wid, "public_id": ws.get("public_id"), "project": proj}
    L(f"workspace {wid} slug={slug}")

    r = retry(lambda: trpc_get(s, "workspaces.getCredit", {"workspaceId": wid}), 2, "credit")
    try:
        cred = r.json()[0]["result"]["data"]["json"]
    except Exception:
        cred = {"parse_fail": r.text[:200]}
    out["credit"] = cred
    L(f"CREDIT {json.dumps(cred)[:200]}")

    key = None
    r = retry(lambda: trpc_post(s, "teams.createApiKey", {"teamSlug": slug, "name": f"canary-{prefix}"}), 2, "key")
    try:
        key = r.json()[0]["result"]["data"]["json"]["createdApiKey"]["key"]
    except Exception:
        out["key_err"] = r.text[:200]
    out["api_key"] = key
    L(f"API KEY {key[:14] if key else None}...")

    if key:
        rt = retry(
            lambda: creq.get("https://api.e2b.dev/sandboxes", headers={"X-API-KEY": key, "User-Agent": "e2b-canary/1.0"}, impersonate="chrome", timeout=30),
            2,
            "api",
        )
        out["api_test"] = {"status": rt.status_code, "body": rt.text[:150]}
        L(f"api.e2b.dev /sandboxes -> {rt.status_code} {rt.text[:100]}")

    out["console_cookies"] = [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path, "expires": c.expires} for c in s.cookies.jar if "e2b" in (c.domain or "")]
    out["result"] = "DONE"
    out["finished"] = datetime.now(timezone.utc).isoformat()
    return json.dumps(out)


def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", default="")
    a = ap.parse_args()
    print("CANARY_RESULT " + canary(a.email, a.password))


if __name__ == "__main__":
    main()
