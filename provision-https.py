#!/usr/bin/env python3
"""Provision HTTPS for a subdomain on its own dedicated OVH DNS zone.

Pipeline (each step is idempotent, so rerunning after a failure resumes):
  0. obtain a run-limited admin consumer key via a browser validation — its
     rules cover only zone ordering, read-only checks on the target subzone,
     and the parent zone's delegation records, and its short validity (1 hour)
     lets it expire on its own soon after the run,
  1. order a DNS zone for the subdomain (product "dns", plan "zone"; free),
  2. poll until the zone is active and read its assigned nameservers,
  3. add NS delegation records to the parent zone and refresh it,
  4. wait until the delegation is visible in public DNS,
  5. obtain a consumer key limited to the new zone only (a second browser
     validation, unlimited validity — it lives on the host and serves every
     renewal),
  6. print ready-to-paste blocks for the target host — env exports, initial
     acme.sh issue, and crontab renewal entry, plus a Caddy env snippet for
     hosts running caddy-dns/ovh.

Credential model: OVH API calls are signed with an application key/secret,
which only identifies the calling program, plus a consumer key, which is what
actually grants rights. The application key pair (created once on OVH's
createApp page, then cached) is deliberately near-powerless: alone it can do
nothing but request new consumer keys, and each such request stays inert until
the account owner validates it in the browser with their OVH credentials,
where the key's path scope and validity are shown. The script receives every
consumer key directly
over the API, so nothing is copy-pasted: it opens the validation page, listens
on localhost for the post-validation redirect, and polls until the key works.
The admin key is requested per run, limited to that run's target zones, and
minted with a short validity, so no usable credential outlives the run on this
machine for long.
"""

import argparse
import hashlib
import http.server
import json
import os
import random
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

ENDPOINTS = {
    "ovh-eu": "https://eu.api.ovh.com/1.0",
    "ovh-ca": "https://ca.api.ovh.com/1.0",
    "ovh-us": "https://api.us.ovhcloud.com/1.0",
}
CREATE_APP_URL = {
    "ovh-eu": "https://eu.api.ovh.com/createApp/",
    "ovh-ca": "https://ca.api.ovh.com/createApp/",
    "ovh-us": "https://us.ovhcloud.com/createApp/",
}
CACHE_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "ovh-subdomain-provision"

ZONE_WAIT_TIMEOUT = 30 * 60      # zone activation can take 15-20 min per OVH docs
DELEGATION_WAIT_TIMEOUT = 15 * 60
CK_VALIDATION_TIMEOUT = 10 * 60


class ApiError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def log(msg):
    print(msg, flush=True)


class OvhClient:
    def __init__(self, endpoint, app_key, app_secret, consumer_key=None):
        self.endpoint = endpoint
        self.base = ENDPOINTS[endpoint]
        self.app_key = app_key
        self.app_secret = app_secret
        self.consumer_key = consumer_key
        self._time_delta = None

    def _server_time_delta(self):
        if self._time_delta is None:
            with urllib.request.urlopen(self.base + "/auth/time", timeout=30) as r:
                self._time_delta = int(r.read().decode()) - int(time.time())
        return self._time_delta

    def call(self, method, path, body=None, signed=True, consumer_key=None):
        url = self.base + path
        data = json.dumps(body) if body is not None else ""
        headers = {"X-Ovh-Application": self.app_key}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if signed:
            ck = consumer_key or self.consumer_key
            if not ck:
                raise ApiError("no consumer key available for a signed call")
            ts = str(int(time.time()) + self._server_time_delta())
            raw = "+".join([self.app_secret, ck, method, url, data, ts])
            headers["X-Ovh-Consumer"] = ck
            headers["X-Ovh-Timestamp"] = ts
            headers["X-Ovh-Signature"] = "$1$" + hashlib.sha1(raw.encode()).hexdigest()
        req = urllib.request.Request(
            url, data=data.encode() if body is not None else None,
            headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                text = r.read().decode()
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            raise ApiError(f"{method} {path} -> HTTP {e.code}: {detail}", status=e.code)
        return json.loads(text) if text else None

    def request_credential(self, access_rules, redirection=None):
        body = {"accessRules": [{"method": r["method"], "path": r["path"]}
                                for r in access_rules]}
        if redirection:
            body["redirection"] = redirection
        return self.call("POST", "/auth/credential", body, signed=False)


def rules(group, *triples):
    return [{"group": group, "method": m, "path": p, "note": n}
            for m, p, n in triples]


def print_rules(access_rules):
    dim, reset = ("\033[2m", "\033[0m") if sys.stdout.isatty() else ("", "")
    width = max(len(r["path"]) for r in access_rules)
    group = None
    for r in access_rules:
        if r["group"] != group:
            group = r["group"]
            print(f"\n  {group}:")
        print(f"    {r['method']:<7} {r['path']:<{width}}  {dim}{r['note']}{reset}")
    print()


def parent_candidates(fqdn):
    """Possible parent zones of fqdn: every suffix with at least two labels."""
    labels = fqdn.split(".")
    return [".".join(labels[i:]) for i in range(1, len(labels) - 1)]


def run_rules(zone):
    """Admin rules for one `new` run: order zones, edit the target subzone,
    and add/read delegation records in whichever candidate is the parent."""
    r = rules(
        "account",
        ("GET", "/me",
         "read account country, needed for the zone order"),
    ) + rules(
        "zone order",
        ("GET", "/me/order",
         "list recent orders -- only used if placing the order fails"),
        ("GET", "/me/order/*",
         "find the already-placed zone order and track its delivery status"),
        ("POST", "/order/cart",
         "create an order cart"),
        ("GET", "/order/cart/*",
         "read the zone offer, verify the order costs 0 before checkout"),
        ("POST", "/order/cart/*",
         "order the new DNS zone"),
    ) + rules(
        f"new zone {zone} (read-only)",
        ("GET", f"/domain/zone/{zone}",
         "see when the new zone becomes active, read its nameservers"),
        ("GET", f"/domain/zone/{zone}/record",
         "fallback for reading the assigned nameservers"),
        ("GET", f"/domain/zone/{zone}/record/*",
         "read those records' details"),
    )
    for cand in parent_candidates(zone):
        r += rules(
            f"parent zone candidate {cand} (delegation)",
            ("GET", f"/domain/zone/{cand}",
             "detect the parent zone"),
            ("GET", f"/domain/zone/{cand}/record",
             "check which NS records already exist"),
            ("GET", f"/domain/zone/{cand}/record/*",
             "read those NS records"),
            ("POST", f"/domain/zone/{cand}/record",
             "add the NS delegation records"),
            ("POST", f"/domain/zone/{cand}/refresh",
             "publish the parent zone change"),
        )
    return r


def status_rules(zone):
    return rules(
        "read-only checks",
        ("GET", "/me",
         "verify the key works"),
        ("GET", f"/domain/zone/{zone}",
         "check the zone is active, read its nameservers"),
        ("GET", f"/domain/zone/{zone}/record",
         "fallback for reading the assigned nameservers"),
        ("GET", f"/domain/zone/{zone}/record/*",
         "read those records' details"),
    )


def limited_rules(zone):
    return rules(
        f"DNS-01 challenges in {zone}",
        ("GET", f"/domain/zone/{zone}",
         "let acme.sh/Caddy detect the zone"),
        ("GET", f"/domain/zone/{zone}/record",
         "list the ACME TXT challenge records"),
        ("GET", f"/domain/zone/{zone}/record/*",
         "read those records' details"),
        ("POST", f"/domain/zone/{zone}/record",
         "create the ACME TXT challenge record"),
        ("POST", f"/domain/zone/{zone}/refresh",
         "publish zone changes"),
        ("DELETE", f"/domain/zone/{zone}/record/*",
         "remove the TXT challenge after each validation"),
    )


def open_browser(url):
    opener = shutil.which("xdg-open") or shutil.which("open")
    if opener:
        try:
            subprocess.Popen([opener, url], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            return
        except OSError:
            pass
    try:
        webbrowser.open(url)
    except Exception:
        pass


def start_redirect_listener():
    """Catch the browser redirect after validation; returns (server, event, url)."""
    done = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            done.set()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<p>Key validated - you can close this tab "
                             b"and return to the terminal.</p>")

        def log_message(self, *args):
            pass

    try:
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    except OSError:
        return None, done, None
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, done, f"http://127.0.0.1:{server.server_port}/"


def obtain_consumer_key(client, access_rules, probe, purpose, validity_hint):
    """Request a consumer key and wait for the user to validate it in the browser."""
    server, done, redirect = start_redirect_listener()
    cred = client.request_credential(access_rules, redirection=redirect)
    ck = cred["consumerKey"]
    open_browser(cred["validationUrl"])
    validity, validity_why = validity_hint
    print(f"\nBrowser validation needed for the {purpose} consumer key.")
    print("\n🔗 Link (already opened in your browser):")
    print(f"    {cred['validationUrl']}")
    print("\n📋 Requested access rules:")
    print_rules(access_rules)
    print(f"👉 Validity to pick: {validity}")
    print(f"    ({validity_why})")
    print("\n⏳ Waiting for the approval in the browser...")
    try:
        deadline = time.time() + CK_VALIDATION_TIMEOUT
        while time.time() < deadline:
            done.wait(4)
            try:
                probe(ck)
                print(f"\n✓ {purpose} consumer key validated")
                return ck
            except ApiError as e:
                if e.status not in (401, 403):
                    print()
                    raise
            print(".", end="", flush=True)
            if done.is_set():
                done.clear()  # redirect fired but the key is not usable yet; recheck
        print()
        raise ApiError(f"consumer key not validated within "
                       f"{CK_VALIDATION_TIMEOUT // 60} minutes")
    finally:
        if server:
            server.shutdown()


def app_key_cache(endpoint):
    return CACHE_DIR / f"app_keys.{endpoint}.json"


def cache_write(path, content):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o600)


def get_app_keys(args):
    ak = args.ak or os.environ.get("OVH_AK")
    as_ = args.as_ or os.environ.get("OVH_AS")
    cache = app_key_cache(args.endpoint)
    if ak and as_:
        cache_write(cache, json.dumps({"ak": ak, "as": as_}) + "\n")
        return ak, as_
    if cache.exists():
        keys = json.loads(cache.read_text())
        return keys["ak"], keys["as"]
    open_browser(CREATE_APP_URL[args.endpoint])
    print("No application key known yet. Register one (once) at:")
    print(f"  {CREATE_APP_URL[args.endpoint]}")
    print("The pair only identifies this script; on its own it can merely request")
    print("consumer keys, each of which you must validate in the browser with")
    print("your OVH credentials.")
    ak = input("👉 application key: ").strip()
    as_ = input("👉 application secret: ").strip()
    if not (ak and as_):
        raise ApiError("both application key and secret are required")
    cache_write(cache, json.dumps({"ak": ak, "as": as_}) + "\n")
    return ak, as_


def make_run_client(args, access_rules, purpose, validity_hint):
    ak, as_ = get_app_keys(args)
    client = OvhClient(args.endpoint, ak, as_)
    client.consumer_key = obtain_consumer_key(
        client, access_rules,
        probe=lambda ck: client.call("GET", "/me", consumer_key=ck),
        purpose=purpose,
        validity_hint=validity_hint)
    return client


def issue_limited_key(client, zone):
    return obtain_consumer_key(
        client, limited_rules(zone),
        probe=lambda ck: client.call("GET", f"/domain/zone/{zone}", consumer_key=ck),
        purpose=f"{zone}-limited",
        validity_hint=("Unlimited",
                       "acme.sh/Caddy will use this key for every renewal"))


def pick_zone_price(prices):
    """Choose the offer price entry to order with: prefer one with the
    'renew' capacity, and never one with an empty/zero duration (the
    installation entry, which checkout rejects with 'Invalid duration 0')."""
    def valid_duration(p):
        return p.get("duration") not in (None, 0, "0", "P0D")
    price = (next((p for p in prices
                   if "renew" in (p.get("capacities") or []) and valid_duration(p)),
                  None)
             or next((p for p in prices if valid_duration(p)), None))
    if price is None:
        raise ApiError("no price entry with a usable duration in the zone offer "
                       f"(got: {json.dumps(prices)[:400]})")
    return price


def find_pending_zone_order(client, zone):
    """Search the last two days of orders for one that delivers this zone."""
    since = time.strftime("%Y-%m-%dT%H:%M:%S+00:00",
                          time.gmtime(time.time() - 2 * 86400))
    q = urllib.parse.urlencode({"date.from": since})
    try:
        order_ids = client.call("GET", f"/me/order?{q}") or []
    except ApiError:
        return None
    for oid in sorted(order_ids, reverse=True)[:20]:
        try:
            for did in client.call("GET", f"/me/order/{oid}/details") or []:
                detail = client.call("GET", f"/me/order/{oid}/details/{did}")
                if zone in f"{detail.get('domain', '')} {detail.get('description', '')}":
                    return oid
        except ApiError:
            continue
    return None


def zone_exists(client, zone):
    try:
        return client.call("GET", f"/domain/zone/{zone}")
    except ApiError as e:
        if e.status in (403, 404):
            return None
        raise


def find_parent_zone(client, fqdn):
    for cand in parent_candidates(fqdn):
        if zone_exists(client, cand):
            return cand
    raise ApiError(f"no zone on this account is a parent of {fqdn} "
                   f"(tried: {', '.join(parent_candidates(fqdn))})")


def order_zone(client, zone, template):
    me = client.call("GET", "/me")
    cart = client.call("POST", "/order/cart", {"ovhSubsidiary": me["ovhSubsidiary"]})
    cart_id = cart["cartId"]
    client.call("POST", f"/order/cart/{cart_id}/assign")
    offers = client.call("GET", f"/order/cart/{cart_id}/dns")
    offer = next((o for o in offers if o.get("planCode") == "zone"), None)
    if offer is None:
        raise ApiError(f"no 'zone' plan offered in cart (got: {json.dumps(offers)[:300]})")
    price = pick_zone_price(offer.get("prices") or [])
    item = client.call("POST", f"/order/cart/{cart_id}/dns", {
        "planCode": "zone", "duration": price["duration"],
        "pricingMode": price["pricingMode"], "quantity": 1})
    item_id = item["itemId"]
    for label, value in (("zone", zone), ("template", template)):
        client.call("POST", f"/order/cart/{cart_id}/item/{item_id}/configuration",
                    {"label": label, "value": value})
    summary = client.call("GET", f"/order/cart/{cart_id}/checkout")
    total = summary.get("prices", {}).get("withTax", {}).get("value", 0)
    if total:
        raise ApiError(f"expected a free zone order but checkout totals {total}; "
                       "aborting — order it from the control panel instead")
    order = client.call("POST", f"/order/cart/{cart_id}/checkout",
                        {"autoPayWithPreferredPaymentMethod": True,
                         "waiveRetractationPeriod": True})
    order_id = order.get("orderId", "?")
    log(f"✓ zone order placed (order #{order_id})")
    return order_id


def wait_for_zone(client, zone, order_id=None):
    deadline = time.time() + ZONE_WAIT_TIMEOUT
    log("⏳ waiting for the zone to become active (OVH says 15-20 min is normal)...")
    stuck_since = None
    while time.time() < deadline:
        info = zone_exists(client, zone)
        if info:
            print()
            return info
        if order_id:
            try:
                status = client.call("GET", f"/me/order/{order_id}/status")
            except ApiError:
                status = None
            # a fresh order shows notPaid briefly while the 0-cost payment is
            # processed, so only a persistent bad status means it is stuck
            if status in ("notPaid", "documentsRequested"):
                stuck_since = stuck_since or time.time()
                if time.time() - stuck_since > 5 * 60:
                    print()
                    raise ApiError(
                        f"order #{order_id} has been in status '{status}' for "
                        "5 minutes; resolve it in the OVH control panel, then "
                        "rerun")
            else:
                stuck_since = None
        print(".", end="", flush=True)
        time.sleep(20)
    print()
    raise ApiError(f"zone {zone} still not active after {ZONE_WAIT_TIMEOUT // 60} minutes")


def zone_nameservers(client, zone, info):
    ns = (info or {}).get("nameServers")
    if ns:
        return ns
    ids = client.call("GET", f"/domain/zone/{zone}/record?fieldType=NS&subDomain=")
    ns = [client.call("GET", f"/domain/zone/{zone}/record/{i}")["target"].rstrip(".")
          for i in ids]
    if not ns:
        raise ApiError(f"could not determine nameservers of {zone}")
    return ns


def ensure_delegation(client, parent, zone, nameservers):
    label = zone[: -(len(parent) + 1)]
    q = urllib.parse.urlencode({"fieldType": "NS", "subDomain": label})
    ids = client.call("GET", f"/domain/zone/{parent}/record?{q}")
    existing = {client.call("GET", f"/domain/zone/{parent}/record/{i}")["target"].rstrip(".")
                for i in ids}
    added = False
    for ns in nameservers:
        ns = ns.rstrip(".")
        if ns not in existing:
            client.call("POST", f"/domain/zone/{parent}/record",
                        {"fieldType": "NS", "subDomain": label, "target": ns + ".",
                         "ttl": 3600})
            log(f"✓ added NS {label} -> {ns} to parent zone {parent}")
            added = True
    if added:
        client.call("POST", f"/domain/zone/{parent}/refresh")
        log(f"✓ refreshed {parent}")
    else:
        log("✓ NS delegation already present in parent zone")


def resolve_ns(name):
    q = urllib.parse.urlencode({"name": name, "type": "NS"})
    req = urllib.request.Request(
        f"https://cloudflare-dns.com/dns-query?{q}",
        headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.load(r)
    return {a["data"].rstrip(".").lower()
            for a in data.get("Answer", []) if a.get("type") == 2}


def wait_for_delegation(client, zone, nameservers):
    expected = {ns.rstrip(".").lower() for ns in nameservers}
    deadline = time.time() + DELEGATION_WAIT_TIMEOUT
    log("⏳ waiting for the delegation to be visible in public DNS...")
    while time.time() < deadline:
        try:
            if resolve_ns(zone) & expected:
                print()
                log("✓ delegation is live")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(15)
    print()
    log(f"⚠ delegation not visible after {DELEGATION_WAIT_TIMEOUT // 60} min; "
        "continuing anyway — issuance may fail until it propagates, rerun later if so")
    return False


def print_host_commands(zone, client, limited_ck, server):
    cron_time = f"{random.randrange(60)} {random.randrange(24)}"
    print(f"""
# --- run on the host serving {zone} (as the user that owns acme.sh) ---
export OVH_END_POINT={client.endpoint}
export OVH_AK={shlex.quote(client.app_key)}
export OVH_AS={shlex.quote(client.app_secret)}
export OVH_CK={shlex.quote(limited_ck)}

# initial issue; acme.sh stores the OVH credentials for future renewals
ACME="$HOME/.acme.sh/acme.sh"; [ -x "$ACME" ] || ACME="$(command -v acme.sh)"
"$ACME" --issue -d {shlex.quote(zone)} --dns dns_ovh --server {server}

# renewal cron entry with the full acme.sh path (skipped if one already exists)
crontab -l 2>/dev/null | grep -q -- '--cron' || \\
  ( crontab -l 2>/dev/null; echo "{cron_time} * * * $ACME --cron >/dev/null" ) | crontab -

# copy the cert where your service reads it (do not point the service at
# ~/.acme.sh -- its layout is internal to acme.sh); acme.sh re-runs this copy
# and the reload command after every renewal. Adjust paths and reload command:
# "$ACME" --install-cert -d {shlex.quote(zone)} --ecc \\
#   --fullchain-file /etc/ssl/{zone}/fullchain.pem \\
#   --key-file      /etc/ssl/{zone}/key.pem \\
#   --reloadcmd     "rc-service nginx reload"
# most apps only read the cert at startup; if yours has no graceful reload,
# use e.g. "podman restart <container>" -- a brief downtime at each ~60-day
# renewal""")


def print_caddy_snippet(zone, client, limited_ck):
    print(f"""
# --- OR, if the host runs Caddy in Docker instead of acme.sh ---
# --- docker-compose service (image: caddy + the caddy-dns/ovh module) ---
services:
  caddy:
    image: ghcr.io/wrobelda/caddy-ovh:latest
    restart: unless-stopped
    ports:
      - "443:443"
      # - "80:80"  # only if you want Caddy's HTTP -> HTTPS redirect
    environment:
      OVH_ENDPOINT: {client.endpoint}
      OVH_APPLICATION_KEY: {client.app_key}
      OVH_APPLICATION_SECRET: {client.app_secret}
      OVH_CONSUMER_KEY: {limited_ck}
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config

volumes:
  caddy_data:
  caddy_config:

# --- Caddyfile ---
{{
    # if you publish "80:80" in docker-compose.yml, remove this to get the
    # HTTP -> HTTPS redirect
    auto_https disable_redirects
}}

{zone} {{
    tls {{
        dns ovh {{
            endpoint {{env.OVH_ENDPOINT}}
            application_key {{env.OVH_APPLICATION_KEY}}
            application_secret {{env.OVH_APPLICATION_SECRET}}
            consumer_key {{env.OVH_CONSUMER_KEY}}
        }}
    }}
    reverse_proxy localhost:8080  # point at the actual service
}}""")


def cmd_new(args):
    zone = args.domain.strip(".").lower()
    if not parent_candidates(zone):
        raise ApiError(f"{zone} is not a subdomain of anything; "
                       "pass a FQDN like subdomain.example.com")
    client = make_run_client(
        args, run_rules(zone), "run-admin",
        validity_hint=("1 hour",
                       "the run waits 15-20 minutes for zone activation; "
                       "the key expires on its own afterwards"))
    parent = find_parent_zone(client, zone)
    log(f"parent zone: {parent}")

    info = zone_exists(client, zone)
    if info:
        log(f"✓ zone {zone} already exists, skipping order")
    else:
        try:
            order_id = order_zone(client, zone, args.template)
        except ApiError as e:
            log(f"⚠ zone order failed ({e})")
            order_id = find_pending_zone_order(client, zone)
            if order_id is None:
                raise
            log(f"✓ found an existing order #{order_id} for {zone}, "
                "waiting for its delivery instead")
        info = wait_for_zone(client, zone, order_id=order_id)
        log(f"✓ zone {zone} is active")

    nameservers = zone_nameservers(client, zone, info)
    log(f"assigned nameservers: {', '.join(nameservers)}")
    ensure_delegation(client, parent, zone, nameservers)

    if not args.no_wait_delegation:
        wait_for_delegation(client, zone, nameservers)

    limited_ck = issue_limited_key(client, zone)

    print("\n👉 Paste the matching block on the target host:")
    print_host_commands(zone, client, limited_ck, args.server)
    print_caddy_snippet(zone, client, limited_ck)
    log("\n✓ done")


def cmd_status(args):
    zone = args.domain.strip(".").lower()
    client = make_run_client(
        args, status_rules(zone), "status (read-only)",
        validity_hint=("5 minutes",
                       "just enough for this check; the key expires on its own"))
    info = zone_exists(client, zone)
    if not info:
        log(f"⚠ zone {zone}: NOT active yet (or not ordered)")
        return
    nameservers = zone_nameservers(client, zone, info)
    log(f"✓ zone {zone}: active, nameservers: {', '.join(nameservers)}")
    try:
        seen = resolve_ns(zone)
    except Exception as e:
        seen = set()
        log(f"⚠ public DNS check failed: {e}")
    if seen & {ns.lower() for ns in nameservers}:
        log("✓ delegation visible in public DNS")
    else:
        log(f"⚠ delegation NOT visible in public DNS yet "
            f"(saw: {', '.join(sorted(seen)) or 'nothing'})")


def main():
    p = argparse.ArgumentParser(
        description="Provision HTTPS for a subdomain on its own dedicated OVH DNS zone.")
    p.add_argument("--endpoint", choices=sorted(ENDPOINTS), default="ovh-eu",
                   help="OVH API endpoint (default: ovh-eu)")
    p.add_argument("--ak", metavar="KEY",
                   help="application key (or env OVH_AK; cached after first use)")
    p.add_argument("--as", dest="as_", metavar="SECRET",
                   help="application secret (or env OVH_AS; cached after first use)")
    sub = p.add_subparsers(dest="cmd", required=True)

    n = sub.add_parser("new", help="create zone, delegate, issue limited key, deploy")
    n.add_argument("domain", help="subdomain FQDN, e.g. subdomain.example.com")
    n.add_argument("--template", default="minimized",
                   choices=["minimized", "basic", "redirect"],
                   help="OVH zone template (default: minimized)")
    n.add_argument("--server", default="letsencrypt",
                   help="ACME server passed to acme.sh (default: letsencrypt)")
    n.add_argument("--no-wait-delegation", action="store_true",
                   help="do not wait for the delegation to appear in public DNS")
    n.set_defaults(func=cmd_new)

    s = sub.add_parser("status", help="show zone/delegation state")
    s.add_argument("domain", help="subdomain FQDN, e.g. subdomain.example.com")
    s.set_defaults(func=cmd_status)

    args = p.parse_args()
    try:
        args.func(args)
    except ApiError as e:
        sys.exit(f"error: {e}")
    except (KeyboardInterrupt, EOFError):
        sys.exit("\ninterrupted")


if __name__ == "__main__":
    main()
