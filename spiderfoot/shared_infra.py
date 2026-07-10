# -*- coding: utf-8 -*-
"""Shared-infrastructure false-positive suppression constants.

A target on shared/CDN infrastructure (many unrelated tenants behind the same
IP) collects threat-intel flags that are about *other* tenants, not the target.
The list-free signal for "this IP is shared" is co-host cardinality: a dedicated
host resolves ~1 site, while shared/CDN infra fronts many. This mirrors the
co-host modules' own ``maxcohost`` heuristic ("...as it would likely indicate
web hosting").

These constants are shared between the live suppression in
``SpiderFootPlugin.notifyListeners`` and the end-of-scan re-evaluation in
``SpiderFootDb.scanFinalizeSharedInfra`` so the threshold is defined once.
"""

# Minimum number of distinct co-hosted sites on the target's IP for it to be
# treated as shared/CDN infrastructure. Set conservatively high so it only fires
# on a strong signal and never suppresses a genuinely dedicated target.
COHOST_SHARED_THRESHOLD = 20

# Risk event types tied to the *target's own IP* that become false positives
# when that IP is shared infrastructure. Affiliate IP types are excluded: they
# concern a different entity's IP, for which the target's co-host count says
# nothing.
SHARED_INFRA_TARGET_IP_RISK_TYPES = (
    "MALICIOUS_COHOST",
    "BLACKLISTED_COHOST",
    "MALICIOUS_IPADDR",
    "BLACKLISTED_IPADDR",
)
