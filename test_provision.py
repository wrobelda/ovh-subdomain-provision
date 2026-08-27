#!/usr/bin/env python3
"""Unit tests for the network-free logic of provision-https.py.

Run with: python3 -m unittest test_provision -v
"""

import importlib.util
import io
import json
import os
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "provision", Path(__file__).parent / "provision-https.py")
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


class FakeClient:
    """Stands in for OvhClient: answers calls from a {(method, path): value}
    map, where a value that is an Exception instance is raised instead."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def call(self, method, path, body=None, **kwargs):
        self.calls.append((method, path))
        result = self.responses[(method, path)]
        if isinstance(result, Exception):
            raise result
        return result


class ParentCandidatesTest(unittest.TestCase):
    def test_single_level(self):
        self.assertEqual(provision.parent_candidates("tool.example.com"),
                         ["example.com"])

    def test_deeper_subdomain_longest_first(self):
        self.assertEqual(provision.parent_candidates("a.b.example.com"),
                         ["b.example.com", "example.com"])

    def test_bare_domain_has_no_candidates(self):
        self.assertEqual(provision.parent_candidates("example.com"), [])


class RulesTest(unittest.TestCase):
    def test_run_rules_grant_no_writes_on_the_new_zone(self):
        for rule in provision.run_rules("tool.example.com"):
            if rule["path"].startswith("/domain/zone/tool.example.com"):
                self.assertEqual(rule["method"], "GET", rule)

    def test_run_rules_cover_every_parent_candidate(self):
        paths = [r["path"] for r in provision.run_rules("a.b.example.com")]
        for cand in ("b.example.com", "example.com"):
            self.assertIn(f"/domain/zone/{cand}/record", paths)
            self.assertIn(f"/domain/zone/{cand}/refresh", paths)

    def test_run_rules_have_no_wildcard_zone_access(self):
        for rule in provision.run_rules("tool.example.com"):
            self.assertNotIn(rule["path"], ("/domain/zone/*", "/me/*"))

    def test_limited_rules_stay_inside_the_zone(self):
        for rule in provision.limited_rules("tool.example.com"):
            self.assertTrue(
                rule["path"].startswith("/domain/zone/tool.example.com"), rule)

    def test_every_rule_carries_a_note(self):
        for rule in (provision.run_rules("t.example.com")
                     + provision.status_rules("t.example.com")
                     + provision.limited_rules("t.example.com")):
            self.assertTrue(rule["note"])


class PickZonePriceTest(unittest.TestCase):
    def test_prefers_renew_capacity(self):
        prices = [
            {"capacities": ["installation"], "duration": "P1M", "pricingMode": "a"},
            {"capacities": ["renew"], "duration": "P1M", "pricingMode": "b"},
        ]
        self.assertEqual(provision.pick_zone_price(prices)["pricingMode"], "b")

    def test_skips_zero_duration_entries(self):
        prices = [
            {"capacities": ["renew"], "duration": 0, "pricingMode": "bad"},
            {"capacities": ["installation"], "duration": "P1M", "pricingMode": "ok"},
        ]
        self.assertEqual(provision.pick_zone_price(prices)["pricingMode"], "ok")

    def test_rejects_offer_with_no_usable_entry(self):
        with self.assertRaises(provision.ApiError):
            provision.pick_zone_price([{"duration": "P0D"}, {"duration": None}])
        with self.assertRaises(provision.ApiError):
            provision.pick_zone_price([])


class FindPendingZoneOrderTest(unittest.TestCase):
    def _client(self, orders):
        responses = {}
        ids = list(orders)
        for oid, details in orders.items():
            responses[("GET", f"/me/order/{oid}/details")] = list(range(len(details)))
            for i, d in enumerate(details):
                responses[("GET", f"/me/order/{oid}/details/{i}")] = d
        client = FakeClient(responses)
        real_call = client.call

        def call(method, path, **kw):
            if method == "GET" and path.startswith("/me/order?"):
                return ids
            return real_call(method, path, **kw)
        client.call = call
        return client

    def test_finds_order_by_detail_domain(self):
        client = self._client({
            10: [{"domain": "other.example.com", "description": "DNS zone"}],
            11: [{"domain": "tool.example.com", "description": "DNS zone"}],
        })
        self.assertEqual(
            provision.find_pending_zone_order(client, "tool.example.com"), 11)

    def test_finds_order_by_description(self):
        client = self._client({
            12: [{"description": "Zone DNS - tool.example.com"}],
        })
        self.assertEqual(
            provision.find_pending_zone_order(client, "tool.example.com"), 12)

    def test_returns_none_when_nothing_matches(self):
        client = self._client({
            13: [{"domain": "other.example.com", "description": ""}],
        })
        self.assertIsNone(
            provision.find_pending_zone_order(client, "tool.example.com"))

    def test_survives_listing_failure(self):
        client = FakeClient({})
        client.call = lambda *a, **k: (_ for _ in ()).throw(
            provision.ApiError("boom", status=403))
        self.assertIsNone(
            provision.find_pending_zone_order(client, "tool.example.com"))


class OutputTest(unittest.TestCase):
    def _host_block(self):
        client = provision.OvhClient("ovh-eu", "AK", "AS")
        out = io.StringIO()
        with redirect_stdout(out):
            provision.print_host_commands("tool.example.com", client, "CK",
                                          "letsencrypt")
        return out.getvalue()

    def test_cron_entry_is_within_valid_ranges(self):
        for _ in range(50):
            line = next(l for l in self._host_block().splitlines()
                        if "--cron >" in l)
            minute, hour = line.split('echo "')[1].split()[:2]
            self.assertIn(int(minute), range(60))
            self.assertIn(int(hour), range(24))

    def test_host_block_contains_credentials_and_domain(self):
        block = self._host_block()
        for needle in ("OVH_END_POINT=ovh-eu", "OVH_AK=AK", "OVH_AS=AS",
                       "OVH_CK=CK", "--issue -d tool.example.com",
                       "--install-cert", "--ecc"):
            self.assertIn(needle, block)

    def test_caddy_block_contains_image_and_zone(self):
        client = provision.OvhClient("ovh-eu", "AK", "AS")
        out = io.StringIO()
        with redirect_stdout(out):
            provision.print_caddy_snippet("tool.example.com", client, "CK")
        block = out.getvalue()
        self.assertIn("ghcr.io/wrobelda/caddy-ovh:latest", block)
        self.assertIn("tool.example.com {", block)
        self.assertIn("OVH_CONSUMER_KEY: CK", block)


@unittest.skipUnless(os.environ.get("OVH_SCHEMA_TESTS"),
                     "network test; set OVH_SCHEMA_TESTS=1 to run")
class ApiSchemaTest(unittest.TestCase):
    """Validate every endpoint the script calls against OVH's published API
    schema (https://eu.api.ovh.com/1.0/{section}.json)."""

    BASE = "https://eu.api.ovh.com/1.0"

    # (method, concrete path) for every client.call() the script can make
    USED_ENDPOINTS = [
        ("POST", "/auth/credential"),
        ("GET", "/me"),
        ("GET", "/me/order"),
        ("GET", "/me/order/1/details"),
        ("GET", "/me/order/1/details/2"),
        ("GET", "/me/order/1/status"),
        ("POST", "/order/cart"),
        ("POST", "/order/cart/abc/assign"),
        ("GET", "/order/cart/abc/dns"),
        ("POST", "/order/cart/abc/dns"),
        ("POST", "/order/cart/abc/item/1/configuration"),
        ("GET", "/order/cart/abc/checkout"),
        ("POST", "/order/cart/abc/checkout"),
        ("GET", "/domain/zone/z.example.com"),
        ("GET", "/domain/zone/z.example.com/record"),
        ("GET", "/domain/zone/z.example.com/record/1"),
        ("POST", "/domain/zone/z.example.com/record"),
        ("POST", "/domain/zone/z.example.com/refresh"),
        ("DELETE", "/domain/zone/z.example.com/record/1"),
    ]

    @classmethod
    def setUpClass(cls):
        import urllib.request

        def fetch(url):
            with urllib.request.urlopen(url, timeout=30) as r:
                return json.loads(r.read().decode())

        cls.templates = {}  # (method, compiled-regex) -> template path
        for section in ("auth", "me", "order", "domain"):
            schema = fetch(f"{cls.BASE}/{section}.json")
            for api in schema.get("apis", []):
                pattern = re.compile(
                    "^" + re.sub(r"\{[^}]+\}", "[^/]+", api["path"]) + "$")
                for op in api.get("operations", []):
                    cls.templates.setdefault(
                        op["httpMethod"], []).append((pattern, api["path"]))

    def test_every_used_endpoint_exists_in_the_schema(self):
        for method, path in self.USED_ENDPOINTS:
            with self.subTest(f"{method} {path}"):
                matches = [t for (rx, t) in self.templates.get(method, [])
                           if rx.match(path)]
                self.assertTrue(matches,
                                f"{method} {path} not found in OVH schema")


if __name__ == "__main__":
    unittest.main()
