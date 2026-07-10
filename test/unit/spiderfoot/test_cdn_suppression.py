# test_cdn_suppression.py
"""Tests for CDN false-positive suppression.

Covers:
  * SpiderFootHelpers.isKnownCDNIP() with the added CDN ranges.
  * SpiderFootPlugin._cdnHostIsFalsePositive() hostname resolution + caching.
  * Persistence of the false_positive flag and its exclusion from the
    scan exposure score.
"""
import os
import tempfile
import unittest

from spiderfoot import SpiderFootDb, SpiderFootEvent
from spiderfoot.helpers import SpiderFootHelpers
from spiderfoot.plugin import SpiderFootPlugin


class FakeSf:
    """Minimal stand-in for the SpiderFoot object used by a plugin."""

    def __init__(self, resolves=None):
        self._resolves = resolves or {}
        self.resolve_calls = 0

    def validIP(self, s):
        try:
            parts = s.split(".")
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except (ValueError, AttributeError):
            return False

    def resolveHost(self, host):
        self.resolve_calls += 1
        return self._resolves.get(host, [])


class FakeTarget:
    def __init__(self, value, ttype="INTERNET_NAME"):
        self.targetValue = value
        self.targetType = ttype


class TestCDNSuppression(unittest.TestCase):

    def test_isKnownCDNIP_new_ranges(self):
        expected = {
            "185.199.110.22": True,   # GitHub Pages
            "185.199.108.0": True,    # GitHub Pages edge
            "185.199.112.0": False,   # just outside /22
            "76.76.21.21": True,      # Vercel
            "75.2.60.5": True,        # Netlify
            "99.83.190.102": True,    # Netlify
            "104.16.0.1": True,       # Cloudflare (pre-existing)
            "8.8.8.8": False,         # not a CDN
            "notanip": False,
        }
        for ip, want in expected.items():
            with self.subTest(ip=ip):
                self.assertEqual(SpiderFootHelpers.isKnownCDNIP(ip), want)

    def test_cdnHost_resolves_into_cdn(self):
        p = SpiderFootPlugin()
        p.sf = FakeSf(resolves={"cohost.example": ["185.199.110.5"]})
        self.assertTrue(p._cdnHostIsFalsePositive("cohost.example"))

    def test_cdnHost_not_on_cdn(self):
        p = SpiderFootPlugin()
        p.sf = FakeSf(resolves={"real.example": ["203.0.113.10"]})
        self.assertFalse(p._cdnHostIsFalsePositive("real.example"))

    def test_cdnHost_bare_ip(self):
        p = SpiderFootPlugin()
        p.sf = FakeSf()
        self.assertTrue(p._cdnHostIsFalsePositive("76.76.21.21"))
        self.assertFalse(p._cdnHostIsFalsePositive("8.8.8.8"))

    def test_cdnHost_cache_avoids_repeat_dns(self):
        sf = FakeSf(resolves={"cohost.example": ["185.199.110.5"]})
        p = SpiderFootPlugin()
        p.sf = sf
        p._cdnHostIsFalsePositive("cohost.example")
        p._cdnHostIsFalsePositive("cohost.example")
        p._cdnHostIsFalsePositive("cohost.example")
        self.assertEqual(sf.resolve_calls, 1)

    def _plugin(self, resolves=None):
        p = SpiderFootPlugin()
        p.sf = FakeSf(resolves=resolves or {})
        return p

    def test_mark_ip_event_feed_format(self):
        # MALICIOUS_IPADDR data is "Feed [ip]"; source carries the IP too.
        p = self._plugin()
        root = SpiderFootEvent("ROOT", "example.com", "", None)
        src = SpiderFootEvent("IP_ADDRESS", "185.199.110.22", "sfp_dns", root)
        evt = SpiderFootEvent("MALICIOUS_IPADDR", "BadFeed [185.199.110.22]",
                              "sfp_x", src)
        p._markCDNFalsePositive(evt)
        self.assertEqual(evt.false_positive, 1)

    def test_mark_cohost_on_github_pages(self):
        # This is the exact shape that regressed: data="Feed [host]",
        # source is CO_HOSTED_SITE with the bare hostname.
        p = self._plugin(resolves={"lumiere-mulagwa.github.io": ["185.199.110.153"]})
        root = SpiderFootEvent("ROOT", "cinecastpro.com", "", None)
        src = SpiderFootEvent("CO_HOSTED_SITE", "lumiere-mulagwa.github.io",
                              "sfp_cohost", root)
        evt = SpiderFootEvent("MALICIOUS_COHOST",
                              "CloudFlare - Malware [lumiere-mulagwa.github.io]",
                              "sfp_x", src)
        p._markCDNFalsePositive(evt)
        self.assertEqual(evt.false_positive, 1)

    def test_mark_affiliate_nameserver_not_flagged(self):
        # A blacklisted affiliate that is a nameserver, not on a CDN -> kept.
        p = self._plugin(resolves={"dns2.registrar-servers.com": ["156.154.132.200"]})
        root = SpiderFootEvent("ROOT", "cinecastpro.com", "", None)
        src = SpiderFootEvent("AFFILIATE_INTERNET_NAME",
                              "dns2.registrar-servers.com", "sfp_dns", root)
        evt = SpiderFootEvent("MALICIOUS_AFFILIATE_INTERNET_NAME",
                              "Quad9 [dns2.registrar-servers.com]", "sfp_x", src)
        p._markCDNFalsePositive(evt)
        self.assertEqual(evt.false_positive, 0)

    def test_mark_target_internet_name_on_cdn(self):
        p = self._plugin(resolves={"cinecastpro.com": ["185.199.110.22"]})
        root = SpiderFootEvent("ROOT", "cinecastpro.com", "", None)
        src = SpiderFootEvent("INTERNET_NAME", "cinecastpro.com", "sfp_dns", root)
        evt = SpiderFootEvent("MALICIOUS_INTERNET_NAME",
                              "Comodo Secure DNS [cinecastpro.com]", "sfp_x", src)
        p._markCDNFalsePositive(evt)
        self.assertEqual(evt.false_positive, 1)

    def test_mark_non_risk_event_untouched(self):
        p = self._plugin(resolves={"cinecastpro.com": ["185.199.110.22"]})
        root = SpiderFootEvent("ROOT", "cinecastpro.com", "", None)
        evt = SpiderFootEvent("INTERNET_NAME", "cinecastpro.com", "sfp_dns", root)
        p._markCDNFalsePositive(evt)
        self.assertEqual(evt.false_positive, 0)

    def test_cohost_suppressed_via_target_on_cdn_even_if_cohost_unresolvable(self):
        # Target is on GitHub Pages; the co-host no longer resolves (empty).
        # The co-host must still be suppressed via the target-IP signal.
        p = self._plugin(resolves={"cinecastpro.com": ["185.199.110.22"]})
        p._currentTarget = FakeTarget("cinecastpro.com")
        root = SpiderFootEvent("ROOT", "cinecastpro.com", "", None)
        src = SpiderFootEvent("CO_HOSTED_SITE", "gone.example", "sfp_cohost", root)
        evt = SpiderFootEvent("MALICIOUS_COHOST", "Feed [gone.example]",
                              "sfp_x", src)
        p._markCDNFalsePositive(evt)
        self.assertEqual(evt.false_positive, 1)

    def test_cohost_not_suppressed_when_target_off_cdn(self):
        # Target not on a CDN and co-host not on a CDN -> genuine, keep it.
        p = self._plugin(resolves={"real-target.com": ["203.0.113.5"],
                                    "badcohost.example": ["198.51.100.9"]})
        p._currentTarget = FakeTarget("real-target.com")
        root = SpiderFootEvent("ROOT", "real-target.com", "", None)
        src = SpiderFootEvent("CO_HOSTED_SITE", "badcohost.example",
                              "sfp_cohost", root)
        evt = SpiderFootEvent("MALICIOUS_COHOST", "Feed [badcohost.example]",
                              "sfp_x", src)
        p._markCDNFalsePositive(evt)
        self.assertEqual(evt.false_positive, 0)

    def test_cohost_ip_target(self):
        # Target given directly as a CDN IP (no DNS needed).
        p = self._plugin()
        p._currentTarget = FakeTarget("185.199.110.22", ttype="IP_ADDRESS")
        root = SpiderFootEvent("ROOT", "185.199.110.22", "", None)
        src = SpiderFootEvent("CO_HOSTED_SITE", "x.example", "sfp_cohost", root)
        evt = SpiderFootEvent("BLACKLISTED_COHOST", "Feed [x.example]",
                              "sfp_x", src)
        p._markCDNFalsePositive(evt)
        self.assertEqual(evt.false_positive, 1)

    def test_targetOnCDN_cached(self):
        sf = FakeSf(resolves={"cinecastpro.com": ["185.199.110.22"]})
        p = SpiderFootPlugin()
        p.sf = sf
        p._currentTarget = FakeTarget("cinecastpro.com")
        self.assertTrue(p._targetOnCDN())
        self.assertTrue(p._targetOnCDN())
        self.assertTrue(p._targetOnCDN())
        self.assertEqual(sf.resolve_calls, 1)

    def test_false_positive_excluded_from_exposure_score(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(path)  # let SpiderFootDb create it fresh
        try:
            opts = {"__database": path, "__dbtype": "sqlite"}
            db = SpiderFootDb(opts, init=True)
            scan_id = "CDNTEST01"
            db.scanInstanceCreate(scan_id, "cdn-test", "example.com")

            root = SpiderFootEvent("ROOT", "example.com", "", None)

            # A genuine malicious IP (weight 90) -> should count.
            real = SpiderFootEvent("MALICIOUS_IPADDR", "bad [203.0.113.9]",
                                   "sfp_test", root)
            real.confidence = 100

            # A CDN false positive (weight 90) -> flagged, must NOT count.
            cdn = SpiderFootEvent("MALICIOUS_IPADDR", "bad [185.199.110.22]",
                                  "sfp_test", root)
            cdn.confidence = 100
            cdn.false_positive = 1

            db.scanEventStore(scan_id, root)
            db.scanEventStore(scan_id, real)
            db.scanEventStore(scan_id, cdn)

            # Score with only the genuine finding: weight 90 * (100/100) = 90.
            score = db.scanExposureScore(scan_id)
            self.assertEqual(score, 90)

            # Sanity: the fp row is stored but marked.
            db.dbh.execute(
                "SELECT false_positive FROM tbl_scan_results "
                "WHERE scan_instance_id = ? AND data LIKE '%185.199.110.22%'",
                [scan_id])
            self.assertEqual(db.dbh.fetchone()[0], 1)
        finally:
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    unittest.main()
