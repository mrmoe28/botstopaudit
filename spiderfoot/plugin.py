from contextlib import suppress
import io
import logging
import os
import queue
import re
import sys
import threading
from time import sleep
import traceback

from .shared_infra import COHOST_SHARED_THRESHOLD
from .threadpool import SpiderFootThreadPool

# begin logging overrides
# these are copied from the python logging module
# https://github.com/python/cpython/blob/main/Lib/logging/__init__.py

if hasattr(sys, 'frozen'):  # support for py2exe
    _srcfile = f"logging{os.sep}__init__{__file__[-4:]}"
elif __file__[-4:].lower() in ['.pyc', '.pyo']:
    _srcfile = __file__[:-4] + '.py'
else:
    _srcfile = __file__
_srcfile = os.path.normcase(_srcfile)


class SpiderFootPluginLogger(logging.Logger):
    """Used only in SpiderFootPlugin to prevent modules
    from having to initialize their own loggers.

    Preserves filename, module, line numbers, etc. from the caller.
    """

    def findCaller(self, stack_info: bool = False, stacklevel: int = 1) -> tuple:
        """Find the stack frame of the caller so that we can note the source
        file name, line number and function name.

        Args:
            stack_info (bool): TBD
            stacklevel (int): TBD

        Returns:
            tuple: filename, line number, module name, and stack trace
        """
        f = logging.currentframe()
        # On some versions of IronPython, currentframe() returns None if
        # IronPython isn't run with -X:Frames.
        if f is not None:
            f = f.f_back
        orig_f = f
        while f and stacklevel > 1:
            f = f.f_back
            stacklevel -= 1
        if not f:
            f = orig_f
        rv = "(unknown file)", 0, "(unknown function)", None
        while hasattr(f, "f_code"):
            co = f.f_code
            filename = os.path.normcase(co.co_filename)
            if filename in (logging._srcfile, _srcfile):  # This is the only change
                f = f.f_back
                continue
            sinfo = None
            if stack_info:
                sio = io.StringIO()
                sio.write('Stack (most recent call last):\n')
                traceback.print_stack(f, file=sio)
                sinfo = sio.getvalue()
                if sinfo[-1] == '\n':
                    sinfo = sinfo[:-1]
                sio.close()
            rv = (co.co_filename, f.f_lineno, co.co_name, sinfo)
            break
        return rv  # noqa R504

# end of logging overrides


class SpiderFootPlugin():
    """SpiderFootPlugin module object

    Attributes:
        _stopScanning (bool): Will be set to True by the controller if the user aborts scanning
        listenerModules (list): Modules that will be notified when this module produces events
        _currentEvent (SpiderFootEvent): Current event being processed
        _currentTarget (str): Target currently being acted against
        _name_: Name of this module, set at startup time
        __sfdb__: Direct handle to the database - not to be directly used
                  by modules except the sfp__stor_db module.
        __scanId__: ID of the scan the module is running against
        __datasource__: (Unused) tracking of data sources
        __outputFilter: If set, events not matching this list are dropped
        _priority (int): Priority, smaller numbers should run first
        errorState (bool): error state of the module
        socksProxy (str): SOCKS proxy
    """

    # Will be set to True by the controller if the user aborts scanning
    _stopScanning = False
    # Modules that will be notified when this module produces events
    _listenerModules = list()
    # Current event being processed
    _currentEvent = None
    # Target currently being acted against
    _currentTarget = None
    # Name of this module, set at startup time
    __name__ = "module_name_not_set!"
    # Direct handle to the database - not to be directly used
    # by modules except the sfp__stor_db module.
    __sfdb__ = None
    # ID of the scan the module is running against
    __scanId__ = None
    # (only used in SpiderFoot HX) tracking of data sources
    __dataSource__ = None
    # If set, events not matching this list are dropped
    __outputFilter__ = None
    # Priority, smaller numbers should run first
    _priority = 1
    # Plugin meta information
    meta = None
    # Error state of the module
    errorState = False
    # SOCKS proxy
    socksProxy = None
    # Queue for incoming events
    incomingEventQueue = None
    # Queue for produced events
    outgoingEventQueue = None
    # SpiderFoot object, set in each module's setup() function
    sf = None
    # Configuration, set in each module's setup() function
    opts = dict()
    # Maximum threads
    maxThreads = 1

    # CDN false-positive suppression (see notifyListeners). IP-typed events
    # whose IP is in a known CDN range, and hostname-typed events that resolve
    # into a known CDN range, are marked as false positives.
    _CDN_FP_IP_TYPES = frozenset((
        "MALICIOUS_IPADDR", "MALICIOUS_AFFILIATE_IPADDR",
        "BLACKLISTED_IPADDR", "BLACKLISTED_AFFILIATE_IPADDR",
    ))
    # Co-host findings are derived from another site sharing the *target's* IP,
    # so on shared-CDN infrastructure the relationship itself is bogus: the
    # decisive signal is whether the target sits on a CDN, not the co-host.
    _CDN_FP_COHOST_TYPES = frozenset((
        "MALICIOUS_COHOST", "BLACKLISTED_COHOST",
    ))
    # List-free shared-hosting signal: if the target's IP hosts at least this
    # many distinct co-hosted sites, it is shared/CDN infrastructure (a dedicated
    # host has ~1), so co-host findings are noise regardless of provider. This
    # mirrors the co-host modules' own "maxcohost" heuristic ("...as it would
    # likely indicate web hosting"). Set conservatively high so it only fires on
    # a strong shared-infra signal and never suppresses a genuinely dedicated
    # target's findings. Threshold is shared with the end-of-scan re-evaluation.
    _COHOST_SHARED_THRESHOLD = COHOST_SHARED_THRESHOLD
    # Name findings are about the named host itself; judge them by that host's
    # own resolution.
    _CDN_FP_NAME_TYPES = frozenset((
        "MALICIOUS_INTERNET_NAME", "BLACKLISTED_INTERNET_NAME",
        "MALICIOUS_AFFILIATE_INTERNET_NAME", "BLACKLISTED_AFFILIATE_INTERNET_NAME",
    ))

    def __init__(self) -> None:
        # Holds the thread object when module threading is enabled
        self.thread = None
        # logging overrides
        self._log = None
        # Shared thread pool for all modules
        self.sharedThreadPool = None
        # Per-module cache of hostname -> bool (resolves into a known CDN range),
        # used by CDN false-positive suppression to avoid repeated DNS lookups.
        self._cdnHostCache = {}
        # Cached per-module answer to "does the scan target sit on a CDN?"
        # (None = not yet computed). The target doesn't change during a scan.
        self._targetOnCDNCache = None
        # Cached set of the scan's DNS/mail provider hostnames (None = not yet
        # loaded, empty set = loaded-but-none-stored-yet, so keep retrying).
        self._providerHostCache = None
        # Cached "target IP is shared (hosts many co-hosts)" flag. Monotonic:
        # once True it stays True (co-host count only grows during a scan).
        self._targetSharedByCohostsCache = False

    @property
    def log(self):
        if self._log is None:
            logging.setLoggerClass(SpiderFootPluginLogger)  # temporarily set logger class
            self._log = logging.getLogger(f"spiderfoot.{self.__name__}")  # init SpiderFootPluginLogger
            logging.setLoggerClass(logging.Logger)  # reset logger class to default
        return self._log

    def _updateSocket(self, socksProxy: str) -> None:
        """Hack to override module's use of socket, replacing it with
        one that uses the supplied SOCKS server.

        Args:
            socksProxy (str): SOCKS proxy
        """
        self.socksProxy = socksProxy

    def clearListeners(self) -> None:
        """Used to clear any listener relationships, etc. This is needed because
        Python seems to cache local variables even between threads."""

        self._listenerModules = list()
        self._stopScanning = False

    def setup(self, sf, userOpts: dict = {}) -> None:
        """Will always be overriden by the implementer.

        Args:
            sf (SpiderFoot): SpiderFoot object
            userOpts (dict): TBD
        """
        pass

    def debug(self, *args, **kwargs) -> None:
        """For logging.
        A wrapper around logging.debug() that adds the scanId to LogRecord

        Args:
            *args: passed through to logging.debug()
            *kwargs: passed through to logging.debug()
        """
        self.log.debug(*args, extra={'scanId': self.__scanId__}, **kwargs)

    def info(self, *args, **kwargs) -> None:
        """For logging.
        A wrapper around logging.info() that adds the scanId to LogRecord

        Args:
            *args: passed through to logging.info()
            *kwargs: passed through to logging.info()
        """
        self.log.info(*args, extra={'scanId': self.__scanId__}, **kwargs)

    def error(self, *args, **kwargs) -> None:
        """For logging.
        A wrapper around logging.error() that adds the scanId to LogRecord

        Args:
            *args: passed through to logging.error()
            *kwargs: passed through to logging.error()
        """
        self.log.error(*args, extra={'scanId': self.__scanId__}, **kwargs)

    def enrichTarget(self, target: str) -> None:
        """Find aliases for a target.

        Note: rarely used in special cases

        Args:
            target (str): TBD
        """
        pass

    def setTarget(self, target) -> None:
        """Assigns the current target this module is acting against.

        Args:
            target (SpiderFootTarget): target

        Raises:
            TypeError: target argument was invalid type
        """
        from spiderfoot import SpiderFootTarget

        if not isinstance(target, SpiderFootTarget):
            raise TypeError(f"target is {type(target)}; expected SpiderFootTarget")

        self._currentTarget = target

    def setDbh(self, dbh) -> None:
        """Used to set the database handle, which is only to be used
        by modules in very rare/exceptional cases (e.g. sfp__stor_db)

        Args:
            dbh (SpiderFootDb): database handle
        """
        self.__sfdb__ = dbh

    def setScanId(self, scanId: str) -> None:
        """Set the scan ID.

        Args:
            scanId (str): scan instance ID

        Raises:
            TypeError: scanId argument was invalid type
        """
        if not isinstance(scanId, str):
            raise TypeError(f"scanId is {type(scanId)}; expected str")

        self.__scanId__ = scanId

    def getScanId(self) -> str:
        """Get the scan ID.

        Returns:
            str: scan ID

        Raises:
            TypeError: Module called getScanId() but no scanId is set.
        """
        if not self.__scanId__:
            raise TypeError("Module called getScanId() but no scanId is set.")

        return self.__scanId__

    def getTarget(self) -> str:
        """Gets the current target this module is acting against.

        Returns:
            str: current target

        Raises:
            TypeError: Module called getTarget() but no target is set.
        """
        if not self._currentTarget:
            raise TypeError("Module called getTarget() but no target is set.")

        return self._currentTarget

    def registerListener(self, listener) -> None:
        """Listener modules which will get notified once we have data for them to
        work with.

        Args:
            listener: TBD
        """

        self._listenerModules.append(listener)

    def setOutputFilter(self, types) -> None:
        self.__outputFilter__ = types

    def tempStorage(self) -> dict:
        """For future use. Module temporary storage.

        A dictionary used to persist state (in memory) for a module.

        Todo:
            Move all module state to use this, which then would enable a scan to be paused/resumed.

        Note:
            Required for SpiderFoot HX compatibility of modules.

        Returns:
            dict: module temporary state data
        """
        return dict()

    def _cdnHostIsFalsePositive(self, host: str) -> bool:
        """Return True if a hostname resolves into a known CDN/edge range.

        Used by CDN false-positive suppression for co-host and internet-name
        findings: on shared CDN infrastructure the co-hosting/affiliate
        relationship is meaningless, so a malicious/blacklisted flag on such a
        host is almost always about another tenant, not the target.

        Results are cached per module instance to avoid repeated DNS lookups.

        Args:
            host (str): hostname to check

        Returns:
            bool: True if the host resolves into a known CDN range
        """
        from spiderfoot.helpers import SpiderFootHelpers

        if not host:
            return False

        cached = self._cdnHostCache.get(host)
        if cached is not None:
            return cached

        result = False
        try:
            # If the value is already a bare IP, check it directly.
            if self.sf is not None and self.sf.validIP(host):
                result = SpiderFootHelpers.isKnownCDNIP(host)
            elif self.sf is not None:
                for ip in self.sf.resolveHost(host):
                    if SpiderFootHelpers.isKnownCDNIP(ip):
                        result = True
                        break
        except Exception:
            result = False

        self._cdnHostCache[host] = result
        return result

    def _targetOnCDN(self) -> bool:
        """Return True if the current scan target resolves onto a known CDN range.

        Co-host findings exist because another site shares the target's IP; when
        that IP is CDN/edge infrastructure the co-hosting relationship is
        meaningless. Computed once per module instance (the target is fixed for
        a scan) and cached.

        Returns:
            bool: True if the scan target sits on a known CDN range
        """
        from spiderfoot.helpers import SpiderFootHelpers

        if self._targetOnCDNCache is not None:
            return self._targetOnCDNCache

        result = False
        try:
            target = self.getTarget()
        except Exception:
            target = None

        if target is not None and self.sf is not None:
            value = (target.targetValue or "").strip()
            ips = []
            if target.targetType in ("IP_ADDRESS", "IPV6_ADDRESS"):
                ips = [value]
            elif value:
                ips = self.sf.resolveHost(value)
            for ip in ips:
                if SpiderFootHelpers.isKnownCDNIP(ip):
                    result = True
                    break

        self._targetOnCDNCache = result
        return result

    def _loadProviderHosts(self) -> set:
        """Load the scan's DNS/mail provider hostnames from the database.

        Returns:
            set: lowercased PROVIDER_DNS / PROVIDER_MAIL hostnames (possibly
                empty if none have been stored yet).
        """
        hosts = set()
        with suppress(Exception):
            if self.__sfdb__ is not None and self.__scanId__:
                for etype in ("PROVIDER_DNS", "PROVIDER_MAIL"):
                    for row in self.__sfdb__.scanResultEventUnique(
                            self.__scanId__, etype):
                        if row and row[0]:
                            hosts.add(row[0].strip().lower())
        return hosts

    def _isProviderInfra(self, host: str) -> bool:
        """Return True if host is one of the target's DNS/mail providers.

        A blacklist/malicious flag on the target's own nameserver or
        mail-forwarder is shared-infrastructure noise (that infra serves many
        unrelated domains), not a threat to the target. The provider set is
        cached per module; while it is still empty it is reloaded on demand,
        since provider events may not be stored when the first flag fires.

        Args:
            host (str): hostname to check

        Returns:
            bool: True if host is a known DNS/mail provider for this scan
        """
        if not host:
            return False
        if not self._providerHostCache:
            self._providerHostCache = self._loadProviderHosts()
        return host in self._providerHostCache

    def _targetIsSharedByCohosts(self) -> bool:
        """Return True if the target's IP hosts many distinct co-hosted sites.

        A list-free shared-hosting signal: a dedicated host resolves ~1 site,
        while shared/CDN infrastructure fronts many unrelated domains. When the
        scan has found at least _COHOST_SHARED_THRESHOLD distinct co-hosts, the
        co-host relationship is meaningless and co-host findings are noise. This
        generalizes to any shared host without maintaining CDN lists.

        The result is monotonic (co-host count only grows during a scan), so it
        is cached once True; while False it is recomputed cheaply on demand,
        since co-host events accrue as the scan progresses.

        Returns:
            bool: True if the target IP is shared by many co-hosts
        """
        if self._targetSharedByCohostsCache:
            return True
        with suppress(Exception):
            if self.__sfdb__ is not None and self.__scanId__:
                rows = self.__sfdb__.scanResultEventUnique(
                    self.__scanId__, "CO_HOSTED_SITE")
                if len(rows) >= self._COHOST_SHARED_THRESHOLD:
                    self._targetSharedByCohostsCache = True
        return self._targetSharedByCohostsCache

    def _markSharedInfraFalsePositive(self, sfEvent) -> None:
        """Flag shared-infrastructure false positives on a malicious event.

        Two shared-infrastructure patterns are suppressed:

        1. CDN/edge IPs (Cloudflare, Fastly, Akamai, CloudFront, GitHub Pages,
           Vercel, Netlify): threat-intel feeds flag them because of *other*
           tenants, and on shared IPs the co-host/affiliate relationship is
           meaningless.
        2. The target's own DNS/mail providers (nameservers, mail forwarders):
           blocklists routinely flag shared registrar/mail infrastructure that
           serves many unrelated domains.

        Setting false_positive=1 excludes the finding from the exposure score
        and hides it in the UI.

        For IP-typed events the IP is taken from the source (or own) data.
        Co-host events are judged by the *target's* IP (the co-host relationship
        is derived from sharing it), while name events are judged by the named
        host's own resolution. In both host cases the source event data holds
        the bare hostname (e.g. a CO_HOSTED_SITE) while the event's own data is
        "Feed [host]"; prefer the source, falling back to bracket extraction.

        Args:
            sfEvent (SpiderFootEvent): event to inspect and possibly flag
        """
        from spiderfoot.helpers import SpiderFootHelpers

        etype = sfEvent.eventType
        src = sfEvent.sourceEvent

        if etype in self._CDN_FP_IP_TYPES:
            ip_candidate = src.data if src is not None else sfEvent.data
            # ip_candidate may be "FeedName [1.2.3.4]\n..." — extract bare IP
            m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', ip_candidate)
            raw_ip = m.group(1) if m else ip_candidate.strip()
            if SpiderFootHelpers.isKnownCDNIP(raw_ip):
                sfEvent.false_positive = 1
        elif etype in self._CDN_FP_COHOST_TYPES:
            # Suppress when the co-host relationship is meaningless: the target
            # is on a known CDN, OR (list-free) its IP hosts many distinct
            # co-hosts (shared/CDN infra), OR the co-host itself resolves onto a
            # known CDN. The cardinality signal generalizes to any shared host.
            if (self._targetOnCDN()
                    or self._targetIsSharedByCohosts()
                    or self._cdnHostIsFalsePositive(self._extractHost(sfEvent))):
                sfEvent.false_positive = 1
        elif etype in self._CDN_FP_NAME_TYPES:
            host = self._extractHost(sfEvent)
            if (self._cdnHostIsFalsePositive(host)
                    or self._isProviderInfra(host)
                    or SpiderFootHelpers.isSharedInfraHost(host)):
                sfEvent.false_positive = 1
        elif (etype == "WEBSERVER_BANNER"
                and SpiderFootHelpers.isCdnServerBanner(sfEvent.data)):
            # A Server header that is just a CDN/proxy name (e.g. "cloudflare")
            # discloses no software version, so it is not a version-disclosure
            # risk — treat it as a false positive.
            sfEvent.false_positive = 1

    @staticmethod
    def _extractHost(sfEvent) -> str:
        """Extract the bare hostname from a malicious/blacklisted host event.

        The source event carries the bare hostname; the event's own data is
        "FeedName [host]". Prefer the source, falling back to bracket extraction.

        Args:
            sfEvent (SpiderFootEvent): event to extract the hostname from

        Returns:
            str: the bare hostname
        """
        src = sfEvent.sourceEvent
        candidate = src.data if src is not None else sfEvent.data
        m = re.search(r'\[([^\]]+)\]', candidate)
        host = (m.group(1) if m else candidate).strip().lower()
        # Guard against multi-line / URL-suffixed values.
        return host.split()[0] if host.split() else host

    def notifyListeners(self, sfEvent) -> None:
        """Call the handleEvent() method of every other plug-in listening for
        events from this plug-in. Remember that those plug-ins will be called
        within the same execution context of this thread, not on their own.

        Args:
            sfEvent (SpiderFootEvent): event

        Raises:
            TypeError: sfEvent argument was invalid type
        """

        from spiderfoot import SpiderFootEvent
        from spiderfoot.module_confidence import MODULE_CONFIDENCE

        if not isinstance(sfEvent, SpiderFootEvent):
            raise TypeError(f"sfEvent is {type(sfEvent)}; expected SpiderFootEvent")

        # Apply module-level confidence if the event still has the default (100).
        # Modules that explicitly set evt.confidence before calling notifyListeners
        # keep their value; this only fills in the default.
        if sfEvent.confidence == 100 and sfEvent.eventType != "ROOT":
            module_conf = MODULE_CONFIDENCE.get(self.__name__, 100)
            if module_conf != 100:
                sfEvent.confidence = module_conf

        self._markSharedInfraFalsePositive(sfEvent)

        eventName = sfEvent.eventType
        eventData = sfEvent.data

        # Be strict about what events to pass on, unless they are
        # the ROOT event or the event type of the target.
        if self.__outputFilter__ and eventName not in ['ROOT', self.getTarget().targetType, self.__outputFilter__]:
            return

        storeOnly = False  # Under some conditions, only store and don't notify

        if not eventData:
            return

        if self.checkForStop():
            return

        # Look back to ensure the original notification for an element
        # is what's linked to children. For instance, sfp_dns may find
        # xyz.abc.com, and then sfp_ripe obtains some raw data for the
        # same, and then sfp_dns finds xyz.abc.com in there, we should
        # suppress the notification of that to other modules, as the
        # original xyz.abc.com notification from sfp_dns will trigger
        # those modules anyway. This also avoids messy iterations that
        # traverse many many levels.

        # storeOnly is used in this case so that the source to dest
        # relationship is made, but no further events are triggered
        # from dest, as we are already operating on dest's original
        # notification from one of the upstream events.

        prevEvent = sfEvent.sourceEvent
        while prevEvent is not None:
            if prevEvent.sourceEvent is not None and prevEvent.sourceEvent.eventType == sfEvent.eventType and prevEvent.sourceEvent.data.lower() == eventData.lower():
                storeOnly = True
                break
            prevEvent = prevEvent.sourceEvent

        # output to queue if applicable
        if self.outgoingEventQueue is not None:
            self.outgoingEventQueue.put(sfEvent)
        # otherwise, call other modules directly
        else:
            self._listenerModules.sort(key=lambda m: m._priority)

            for listener in self._listenerModules:
                if eventName not in listener.watchedEvents() and '*' not in listener.watchedEvents():
                    continue

                if storeOnly and "__stor" not in listener.__module__:
                    continue

                listener._currentEvent = sfEvent

                # Check if we've been asked to stop in the meantime, so that
                # notifications stop triggering module activity.
                if self.checkForStop():
                    return

                try:
                    listener.handleEvent(sfEvent)
                except Exception as e:
                    self.sf.error(f"Module ({listener.__module__}) encountered an error: {e}")
                    # set errorState
                    self.errorState = True
                    # clear incoming queue
                    if self.incomingEventQueue:
                        with suppress(queue.Empty):
                            while 1:
                                self.incomingEventQueue.get_nowait()

    def checkForStop(self) -> bool:
        """For modules to use to check for when they should give back control.

        Returns:
            bool: True if scan should stop
        """
        # Stop if module is in error state.
        if self.errorState:
            return True

        # If threading is enabled, check the _stopScanning attribute instead.
        # This is to prevent each thread needing its own sqlite db handle.
        if self.outgoingEventQueue is not None and self.incomingEventQueue is not None:
            return self._stopScanning

        if not self.__scanId__:
            return False

        scanstatus = self.__sfdb__.scanInstanceGet(self.__scanId__)

        if not scanstatus:
            return False

        if scanstatus[5] == "ABORT-REQUESTED":
            self._stopScanning = True
            return True

        return False

    @property
    def running(self) -> bool:
        """Indicates whether the module is currently processing data.
        Modules that process data in pools/batches typically override this method.

        Returns:
            bool: True if the module is currently processing data.
        """
        return self.sharedThreadPool.countQueuedTasks(f"{self.__name__}_threadWorker") > 0

    def watchedEvents(self) -> list:
        """What events is this module interested in for input. The format is a list
        of event types that are applied to event types that this module wants to
        be notified of, or * if it wants everything.
        Will usually be overriden by the implementer, unless it is interested
        in all events (default behavior).

        Returns:
            list: list of events this modules watches
        """

        return ['*']

    def producedEvents(self) -> list:
        """What events this module produces
        This is to support the end user in selecting modules based on events
        produced.

        Returns:
            list: list of events produced by this module
        """

        return []

    def handleEvent(self, sfEvent) -> None:
        """Handle events to this module.
        Will usually be overriden by the implementer, unless it doesn't handle any events.

        Args:
            sfEvent (SpiderFootEvent): event
        """

        return

    def asdict(self) -> dict:
        return {
            'name': self.meta.get('name'),
            'descr': self.meta.get('summary'),
            'cats': self.meta.get('categories', []),
            'group': self.meta.get('useCases', []),
            'labels': self.meta.get('flags', []),
            'provides': self.producedEvents(),
            'consumes': self.watchedEvents(),
            'meta': self.meta,
            'opts': self.opts,
            'optdescs': self.optdescs,
        }

    def start(self) -> None:
        self.thread = threading.Thread(target=self.threadWorker)
        self.thread.start()

    def finish(self):
        """Perform final/cleanup functions before module exits
        Note that this function may be called multiple times
        Overridden by the implementer
        """

        return

    def threadWorker(self) -> None:
        try:
            # create new database handle since we're in our own thread
            from spiderfoot import SpiderFootDb
            self.setDbh(SpiderFootDb(self.opts))
            self.sf._dbh = self.__sfdb__

            if not (self.incomingEventQueue and self.outgoingEventQueue):
                self.sf.error("Please set up queues before starting module as thread")
                return

            while not self.checkForStop():
                try:
                    sfEvent = self.incomingEventQueue.get_nowait()
                except queue.Empty:
                    sleep(.3)
                    continue
                if sfEvent == 'FINISHED':
                    self.sf.debug(f"{self.__name__}.threadWorker() got \"FINISHED\" from incomingEventQueue.")
                    self.poolExecute(self.finish)
                else:
                    self.sf.debug(f"{self.__name__}.threadWorker() got event, {sfEvent.eventType}, from incomingEventQueue.")
                    self.poolExecute(self.handleEvent, sfEvent)
        except KeyboardInterrupt:
            self.sf.debug(f"Interrupted module {self.__name__}.")
            self._stopScanning = True
        except Exception as e:
            import traceback
            self.sf.error(f"Exception ({e.__class__.__name__}) in module {self.__name__}."
                          + traceback.format_exc())
            # set errorState
            self.sf.debug(f"Setting errorState for module {self.__name__}.")
            self.errorState = True
            # clear incoming queue
            if self.incomingEventQueue:
                self.sf.debug(f"Emptying incomingEventQueue for module {self.__name__}.")
                with suppress(queue.Empty):
                    while 1:
                        self.incomingEventQueue.get_nowait()
                # set queue to None to prevent its use
                # if there are leftover objects in the queue, the scan will hang.
                self.incomingEventQueue = None

    def poolExecute(self, callback, *args, **kwargs) -> None:
        """Execute a callback with the given args.
        If we're in a storage module, execute normally.
        Otherwise, use the shared thread pool.

        Args:
            callback: function to call
            args: args (passed through to callback)
            kwargs: kwargs (passed through to callback)
        """
        if self.__name__.startswith('sfp__stor_'):
            callback(*args, **kwargs)
        else:
            self.sharedThreadPool.submit(callback, *args, taskName=f"{self.__name__}_threadWorker", maxThreads=self.maxThreads, **kwargs)

    def threadPool(self, *args, **kwargs):
        return SpiderFootThreadPool(*args, **kwargs)

    def setSharedThreadPool(self, sharedThreadPool) -> None:
        self.sharedThreadPool = sharedThreadPool

# end of SpiderFootPlugin class
