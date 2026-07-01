# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_stor_db
# Purpose:      SpiderFoot plug-in for storing events to the local SpiderFoot
#               SQLite database.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     14/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     MIT
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootPlugin


class sfp__stor_db(SpiderFootPlugin):

    meta = {
        'name': "Storage",
        'summary': "Stores scan results into the back-end SpiderFoot database. You will need this."
    }

    _priority = 0

    # Default options
    opts = {
        'maxstorage': 1024,  # max bytes for any piece of info stored (0 = unlimited)
        '_store': True
    }

    # Option descriptions
    optdescs = {
        'maxstorage': "Maximum bytes to store for any piece of information retrieved (0 = unlimited.)"
    }

    # Event types whose content legitimately differs per source — never deduplicate.
    _DEDUP_EXCLUDED_PREFIXES = ("RAW_",)

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        # Maps (eventType, normalized_data) -> hash of first stored event.
        # Populated per scan to suppress duplicate findings from multiple modules.
        self._seen = {}

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # Because this is a storage plugin, we are interested in everything so we
    # can store all events for later analysis.
    def watchedEvents(self):
        return ["*"]

    def _dedup_key(self, sfEvent):
        """Return a normalised dedup key, or None if this event type is excluded."""
        etype = sfEvent.eventType
        if etype == "ROOT" or any(etype.startswith(p) for p in self._DEDUP_EXCLUDED_PREFIXES):
            return None
        # Normalise: strip whitespace, lowercase, cap at 512 chars to keep the
        # dict lean for very long data payloads.
        norm = sfEvent.data.strip().lower()[:512]
        return (etype, norm)

    # Handle events sent to this module
    def handleEvent(self, sfEvent):
        if not self.opts['_store']:
            return

        key = self._dedup_key(sfEvent)
        if key is not None:
            if key in self._seen:
                # Already stored from a different module — corroborate rather than duplicate.
                self.debug(f"Dedup hit for {sfEvent.eventType} from {sfEvent.module}; boosting confidence")
                self.__sfdb__.scanEventUpdateConfidence(
                    self.getScanId(), self._seen[key], confidenceDelta=5
                )
                return
            # First time seeing this (type, data) pair — fall through to store it.
            self._seen[key] = sfEvent.hash

        if self.opts['maxstorage'] != 0 and len(sfEvent.data) > self.opts['maxstorage']:
            self.debug("Storing an event: " + sfEvent.eventType)
            self.__sfdb__.scanEventStore(self.getScanId(), sfEvent, self.opts['maxstorage'])
            return

        self.debug("Storing an event: " + sfEvent.eventType)
        self.__sfdb__.scanEventStore(self.getScanId(), sfEvent)

# End of sfp__stor_db class
