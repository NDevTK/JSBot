"""JSBot 5.0 — Opinionated JavaScript security scanner.

Async pipeline: domain discovery → page crawling → JS audit.
All three stages run concurrently via asyncio.Queue.
"""
import argparse
import asyncio
import concurrent.futures
import json
import os
import re
import sys
from collections import namedtuple
from dataclasses import dataclass, field
from random import shuffle
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

import output
from output import log_message
from scoring import score_url, url_path_key, path_segments, combined_url_score
from patterns import JS_PATH_FINDER
from analysis import (
    format_javascript, structural_hash, get_sha256, get_ast_analyzer,
    check_script_safety,
    SEEN_SCRIPTS, CHECKED_JS_URLS, IGNORED_HASHES,
    CrossFileState,
)
from sourcemaps import try_fetch_sourcemap, get_original_source
from discovery import (
    discover_paths, spider_links, fetch_commoncrawl_urls,
    ct_load_state, ct_save_state, ct_fetch_next_month,
)
from anomaly import AnomalyDetector
from semgrep_runner import SemgrepBatch

# --- Global State ---
CHECKED_URLS = set()
DISCOVERED_URLS = set()
DEAD_DOMAINS = set()  # domains that failed with connection errors — skip future requests
SEEN_PATH_KEYS = set()  # normalized URL paths — for exact-URL novelty dedup
SEEN_PATH_SEGMENTS = set()  # unique path segments — for novelty scoring across sessions


# --- Configuration ---
class Config:
    USER_AGENT = 'JSBot/5.0 (Autonomous Security Agent)'

# --- Scan State Persistence ---
_STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.ct_cache')


def _get_scan_domain(args, initial_urls):
    """Extract base domain for scan state storage."""
    if args.ct:
        return args.ct
    for url in initial_urls:
        parsed = urlparse(url)
        if parsed.hostname:
            parts = parsed.hostname.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
    return None


def _load_scan_state(domain):
    """Load persisted path segments from previous scans."""
    if not domain:
        return
    path = os.path.join(_STATE_DIR, domain, 'scan_state.json')
    if not os.path.exists(path):
        return
    try:
        with open(path) as f:
            data = json.load(f)
        loaded = data.get('seen_path_segments', [])
        SEEN_PATH_SEGMENTS.update(loaded)
        log_message("INFO", f"Loaded {len(loaded)} seen path segments from previous scans")
    except Exception as e:
        log_message("ERROR", f"Failed to load scan state: {e}")


def _save_scan_state(domain):
    """Persist path segments for future scan novelty scoring."""
    if not domain:
        return
    d = os.path.join(_STATE_DIR, domain)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, 'scan_state.json')
    try:
        with open(path, 'w') as f:
            json.dump({'seen_path_segments': sorted(SEEN_PATH_SEGMENTS)}, f)
        log_message("INFO", f"Saved {len(SEEN_PATH_SEGMENTS)} path segments to scan state")
    except Exception as e:
        log_message("ERROR", f"Failed to save scan state: {e}")


def _load_anomaly_profiles(domain):
    """Load anomaly profiles from previous scans."""
    if not domain:
        return AnomalyDetector()
    path = os.path.join(_STATE_DIR, domain, 'anomaly_profiles.json')
    if not os.path.exists(path):
        return AnomalyDetector()
    try:
        with open(path) as f:
            data = json.load(f)
        detector = AnomalyDetector.from_dict(data)
        log_message("INFO", f"Loaded anomaly profiles for {len(detector.profiles)} subdomains")
        return detector
    except Exception as e:
        log_message("ERROR", f"Failed to load anomaly profiles: {e}")
        return AnomalyDetector()


def _save_anomaly_profiles(domain, anomaly_detector):
    """Persist anomaly profiles for cross-scan learning."""
    if not domain:
        return
    d = os.path.join(_STATE_DIR, domain)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, 'anomaly_profiles.json')
    try:
        with open(path, 'w') as f:
            json.dump(anomaly_detector.to_dict(), f)
        log_message("INFO", f"Saved anomaly profiles for {len(anomaly_detector.profiles)} subdomains")
    except Exception as e:
        log_message("ERROR", f"Failed to save anomaly profiles: {e}")


# --- Pipeline Data Structures ---
_POISON = object()

JsWorkItem = namedtuple('JsWorkItem', [
    'js_code', 'page_url', 'script_url', 'page_tracker',
])


@dataclass
class PageTracker:
    """Coordinates cross-file analysis — counts scripts remaining for one page."""
    page_url: str
    cross_file: CrossFileState
    total: int
    remaining: int = field(init=False)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    def __post_init__(self):
        self.remaining = self.total


_FINDING_BOOST = 3  # each finding = N "free" crawl credits for host selection


class HostBalancedQueue:
    """URL queue that balances across hosts at dequeue time.

    put() adds URLs to per-host buckets (no scoring yet).
    get() picks the host with fewest effective crawls, then scores all its
    URLs against the *current* SEEN_PATH_KEYS/SEEN_PATH_SEGMENTS and returns
    the most novel one. Finding-rich hosts get crawl credits so the scanner
    digs deeper where it's finding results.
    """

    def __init__(self):
        self._buckets = {}      # host -> list of urls
        self._host_crawls = {}  # host -> count of URLs dequeued
        self._host_findings = {}  # host -> count of findings (heat)
        self._lock = asyncio.Lock()
        self._not_empty = asyncio.Event()
        self._poison_count = 0
        self._total = 0

    async def put(self, url):
        async with self._lock:
            if url is _POISON:
                self._poison_count += 1
                self._not_empty.set()
                return
            parsed = urlparse(url)
            host = parsed.hostname or 'unknown'
            if host not in self._buckets:
                self._buckets[host] = []
            self._buckets[host].append(url)
            self._total += 1
            self._not_empty.set()

    async def get(self):
        while True:
            async with self._lock:
                if self._poison_count > 0:
                    self._poison_count -= 1
                    return _POISON
                # Pick host with fewest effective crawls (findings = free credits)
                best_host = None
                min_effective = float('inf')
                for host, urls in self._buckets.items():
                    if urls:
                        crawls = self._host_crawls.get(host, 0)
                        heat = self._host_findings.get(host, 0)
                        effective = crawls - heat * _FINDING_BOOST
                        if effective < min_effective:
                            min_effective = effective
                            best_host = host
                if best_host is not None:
                    # Score against current seen state — most novel URL first
                    bucket = self._buckets[best_host]
                    best_idx = 0
                    best_score = combined_url_score(bucket[0], SEEN_PATH_KEYS, SEEN_PATH_SEGMENTS)
                    for i in range(1, len(bucket)):
                        s = combined_url_score(bucket[i], SEEN_PATH_KEYS, SEEN_PATH_SEGMENTS)
                        if s > best_score:
                            best_score = s
                            best_idx = i
                    url = bucket.pop(best_idx)
                    self._host_crawls[best_host] = self._host_crawls.get(best_host, 0) + 1
                    self._total -= 1
                    if not any(b for b in self._buckets.values()) and self._poison_count == 0:
                        self._not_empty.clear()
                    return url
                # Nothing available — clear and wait
                self._not_empty.clear()
            await self._not_empty.wait()

    def task_done(self):
        pass  # compatibility with asyncio.Queue interface

    def record_finding(self, host):
        """Boost a host's priority — each finding earns free crawl credits."""
        self._host_findings[host] = self._host_findings.get(host, 0) + 1

    def qsize(self):
        return self._total


class ProducerTracker:
    """Tracks active producers for a queue. Sends poison pills when all finish."""

    def __init__(self, queue, num_consumers):
        self._queue = queue
        self._num_consumers = num_consumers
        self._active = 0
        self._lock = asyncio.Lock()
        self._done = False

    async def register(self):
        async with self._lock:
            self._active += 1

    async def unregister(self):
        async with self._lock:
            self._active -= 1
            if self._active <= 0 and not self._done:
                self._done = True
                for _ in range(self._num_consumers):
                    await self._queue.put(_POISON)


# --- Worker Coroutines ---

async def domain_discovery_worker(domain_queue, url_queue, client, args):
    """Pulls domains from domain_queue, runs discover_paths, puts URLs into url_queue."""
    while True:
        domain = await domain_queue.get()
        if domain is _POISON:
            domain_queue.task_done()
            break
        try:
            if domain in DEAD_DOMAINS:
                continue
            discovered = await discover_paths(domain, client)
            added = 0
            for url in discovered:
                url_hash = get_sha256(url)
                if url_hash not in DISCOVERED_URLS:
                    DISCOVERED_URLS.add(url_hash)
                    await url_queue.put(url)  # HostBalancedQueue handles scoring
                    added += 1
            if added:
                log_message("INFO", f"Found {added} paths from robots.txt/sitemap for {domain}")
        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            DEAD_DOMAINS.add(domain)
            log_message("ERROR", f"Domain unreachable, skipping: {domain} ({e})")
        except Exception as e:
            log_message("ERROR", f"Discovery failed for {domain}: {e}")
        finally:
            domain_queue.task_done()


async def page_crawl_worker(url_queue, js_queue, client, args, url_tracker):
    """Pulls URLs, fetches pages, puts scripts into js_queue, spiders back into url_queue."""
    timeout = httpx.Timeout(10.0, connect=5.0)

    while True:
        url = await url_queue.get()
        if url is _POISON:
            url_queue.task_done()
            break

        await url_tracker.register()
        try:
            hashed_url = get_sha256(url)
            if hashed_url in CHECKED_URLS:
                continue
            CHECKED_URLS.add(hashed_url)

            # Track path segments for novelty scoring of future URLs
            SEEN_PATH_KEYS.add(url_path_key(url))
            SEEN_PATH_SEGMENTS.update(path_segments(url))

            # Skip URLs on domains we already know are dead
            parsed = urlparse(url)
            if parsed.hostname and parsed.hostname in DEAD_DOMAINS:
                continue

            log_message("INFO", f"Crawling: {url}")
            response = await client.get(url, timeout=timeout)
            page_url = str(response.url)  # Final URL after redirects
            content_type = response.headers.get('content-type', '').lower()

            # Direct JS file
            if 'javascript' in content_type:
                await js_queue.put(JsWorkItem(
                    js_code=response.text,
                    page_url=page_url,
                    script_url=page_url,
                    page_tracker=None,
                ))

            # HTML content
            elif 'html' in content_type:
                page_parser = BeautifulSoup(response.text, 'lxml')

                # Collect all scripts for this page
                script_items = []
                for script in page_parser.find_all('script'):
                    if not script.get('src'):
                        js = script.string or ""
                        if js.strip():
                            script_items.append((js, None))

                for script in page_parser.find_all('script', src=True):
                    script_url = urljoin(page_url, script['src'])
                    hashed_script_url = get_sha256(script_url)
                    if hashed_script_url in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed_script_url)
                    try:
                        resp = await client.get(script_url, timeout=timeout)
                        if resp.status_code < 400:
                            script_items.append((resp.text, str(resp.url)))
                    except httpx.RequestError as e:
                        log_message("ERROR", f"Failed to fetch script {script_url}: {e}")

                # Build PageTracker for cross-file analysis
                tracker = None
                if script_items:
                    cross_file = CrossFileState()
                    tracker = PageTracker(
                        page_url=page_url,
                        cross_file=cross_file,
                        total=len(script_items),
                    )

                # Enqueue each script
                for js_code, script_url in script_items:
                    await js_queue.put(JsWorkItem(
                        js_code=js_code,
                        page_url=page_url,
                        script_url=script_url,
                        page_tracker=tracker,
                    ))

                # Discover JS paths referenced in HTML
                for match in re.finditer(JS_PATH_FINDER, response.text):
                    path = match.group(1).replace('\\/', '/')
                    if '%{' in path or '${' in path or '{{' in path:
                        continue
                    if path.startswith('//'):
                        path = f"https:{path}"
                    js_url = urljoin(page_url, path)
                    hashed = get_sha256(js_url)
                    if hashed in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed)
                    try:
                        js_resp = await client.get(js_url, timeout=timeout)
                        if js_resp.status_code < 400:
                            await js_queue.put(JsWorkItem(
                                js_code=js_resp.text,
                                page_url=page_url,
                                script_url=js_url,
                                page_tracker=None,
                            ))
                    except httpx.RequestError:
                        pass

                # Spider: feed links back into url_queue
                parsed_url = urlparse(page_url)
                base_domain = '.'.join((parsed_url.hostname or '').split('.')[-2:])
                new_links = spider_links(response.text, response.url, base_domain)
                for link in new_links:
                    link_hash = get_sha256(link)
                    if link_hash not in DISCOVERED_URLS and link_hash not in CHECKED_URLS:
                        DISCOVERED_URLS.add(link_hash)
                        await url_queue.put(link)

            else:
                log_message("INFO", f"Skipping non-HTML/JS content at {url}")

        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            host = urlparse(url).hostname
            if host:
                DEAD_DOMAINS.add(host)
            log_message("ERROR", f"Domain unreachable, skipping future requests: {url} ({e})")
        except httpx.RequestError as e:
            log_message("ERROR", f"HTTP request failed for {url}: {e}")
        except Exception as e:
            log_message("ERROR", f"Unexpected error for {url}: {e}")
        finally:
            await url_tracker.unregister()
            url_queue.task_done()


async def js_audit_worker(js_queue, client, args, executor,
                          semgrep_batch, anomaly_detector, url_queue=None):
    """Pulls JS from js_queue, runs taint analysis + feature extraction."""
    loop = asyncio.get_event_loop()
    fetch_timeout = httpx.Timeout(10.0, connect=5.0)

    while True:
        item = await js_queue.get()
        if item is _POISON:
            js_queue.task_done()
            break

        try:
            js_code = item.js_code
            if not js_code or not js_code.strip():
                # Still need to decrement PageTracker for empty scripts
                await _decrement_page_tracker(item.page_tracker, executor, loop, url_queue)
                continue

            js_code = format_javascript(js_code)
            raw_hash = get_sha256(js_code)
            struct_hash = structural_hash(js_code)

            # Dedup (on event loop thread — safe)
            skip_analysis = False
            if raw_hash in IGNORED_HASHES:
                skip_analysis = True
            elif raw_hash in SEEN_SCRIPTS or struct_hash in SEEN_SCRIPTS:
                skip_analysis = True
            else:
                SEEN_SCRIPTS.add(raw_hash)
                SEEN_SCRIPTS.add(struct_hash)

            if not skip_analysis:
                # Heavy sync work → thread pool (taint flow + feature extraction)
                await loop.run_in_executor(
                    executor,
                    check_script_safety, js_code, raw_hash, item.page_url, item.script_url,
                    struct_hash, anomaly_detector, semgrep_batch,
                )

                # Source map (async fetch, sync re-analysis)
                if item.script_url and item.script_url != "inline":
                    try:
                        sourcemap = await try_fetch_sourcemap(item.script_url, js_code, client)
                        if sourcemap:
                            original = get_original_source(sourcemap)
                            if original and len(original) > 50:
                                original_hash = get_sha256(original)
                                if original_hash not in SEEN_SCRIPTS:
                                    SEEN_SCRIPTS.add(original_hash)
                                    log_message("INFO", f"Re-analyzing source map for {item.script_url}")
                                    original_struct = structural_hash(original)
                                    await loop.run_in_executor(
                                        executor,
                                        check_script_safety, original, original_hash,
                                        item.page_url, item.script_url + " (source map)",
                                        original_struct, anomaly_detector, semgrep_batch,
                                    )
                    except Exception as e:
                        log_message("ERROR", f"Source map failed for {item.script_url}: {e}")

                # Save to disk
                if args.save:
                    try:
                        with open(f"{raw_hash}.js", 'w', encoding='utf-8') as f:
                            f.write(f"// Source: {item.page_url}\n"
                                    f"// Script URL: {item.script_url or 'inline'}\n\n{js_code}")
                    except IOError as e:
                        log_message("ERROR", f"Failed to save script {raw_hash}: {e}")

                # Discover JS paths referenced inside JS code
                for match in re.finditer(JS_PATH_FINDER, js_code):
                    path = match.group(1).replace('\\/', '/')
                    if '%{' in path or '${' in path or '{{' in path:
                        continue
                    if path.startswith('//'):
                        path = f"https:{path}"
                    script_url = urljoin(item.page_url, path)
                    hashed_url = get_sha256(script_url)
                    if hashed_url in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed_url)
                    log_message("INFO", f"Discovered JS via regex: {script_url}")
                    try:
                        resp = await client.get(script_url, timeout=fetch_timeout)
                        if resp.status_code < 400:
                            await js_queue.put(JsWorkItem(
                                js_code=resp.text,
                                page_url=item.page_url,
                                script_url=script_url,
                                page_tracker=None,
                            ))
                    except httpx.RequestError:
                        pass

            # Cross-file tracking (always, even for deduped scripts)
            if item.page_tracker is not None:
                pt = item.page_tracker
                pt.cross_file.add_script(js_code, item.script_url or "inline", raw_hash)
                await _decrement_page_tracker(pt, executor, loop, url_queue)

        except Exception as e:
            log_message("ERROR", f"JS audit error: {e}")
        finally:
            js_queue.task_done()


async def _decrement_page_tracker(page_tracker, executor, loop, url_queue=None):
    """Decrement a PageTracker and run cross-file analysis when all scripts are done."""
    if page_tracker is None:
        return
    async with page_tracker.lock:
        page_tracker.remaining -= 1
        if page_tracker.remaining <= 0 and page_tracker.cross_file.scripts:
            analyzer = get_ast_analyzer()
            try:
                await loop.run_in_executor(
                    executor,
                    page_tracker.cross_file.collect_globals, analyzer,
                )
                count = page_tracker.cross_file.emit_cross_file_findings(page_tracker.page_url)
                if count and url_queue is not None:
                    host = urlparse(page_tracker.page_url).hostname
                    if host:
                        for _ in range(count):
                            url_queue.record_finding(host)
            except Exception as e:
                log_message("ERROR", f"Cross-file analysis failed for {page_tracker.page_url}: {e}")


# --- Producer Coroutines ---

def _clean_urls(urls):
    """Strip query params/fragments, keep highest-scored version of each URL."""
    cleaned = {}
    for url in urls:
        clean = url.split('?')[0].split('#')[0]
        existing_score = cleaned.get(clean, -1)
        new_score = score_url(url)
        if new_score > existing_score:
            cleaned[clean] = new_score
    return set(cleaned.keys())


async def _seed_urls(urls, url_queue, domain_queue):
    """Clean, dedup, and push URLs into the host-balanced pipeline queue."""
    cleaned = _clean_urls(urls)

    # Extract domains for discovery
    domains = set()
    for url in cleaned:
        parsed = urlparse(url)
        if parsed.hostname:
            domains.add(parsed.hostname)
    for domain in domains:
        await domain_queue.put(domain)

    added = 0
    for url in cleaned:
        url_hash = get_sha256(url)
        if url_hash not in DISCOVERED_URLS:
            DISCOVERED_URLS.add(url_hash)
            SEEN_PATH_KEYS.add(url_path_key(url))
            SEEN_PATH_SEGMENTS.update(path_segments(url))
            await url_queue.put(url)  # HostBalancedQueue scores + interleaves
            added += 1
    return added


async def seed_urls_into_pipeline(initial_urls, url_queue, domain_queue, args, executor):
    """Seed initial URLs into the pipeline immediately."""
    added = await _seed_urls(initial_urls, url_queue, domain_queue)
    log_message("INFO", f"Seeded {added} initial URLs into pipeline")


async def cc_producer(url_queue, domain_queue, hosts, executor):
    """Fetch Common Crawl URLs for a set of hostnames and feed into the pipeline."""
    if not hosts:
        return
    loop = asyncio.get_event_loop()
    log_message("INFO", f"Fetching Common Crawl URLs for {len(hosts)} hosts...")
    cc_urls = await loop.run_in_executor(
        executor, fetch_commoncrawl_urls, list(hosts), Config.USER_AGENT,
    )
    if not cc_urls:
        log_message("INFO", "Common Crawl: no new URLs found")
        return
    added = await _seed_urls(cc_urls, url_queue, domain_queue)
    log_message("INFO", f"Common Crawl added {added} new URLs")


# --- Pipeline Orchestrator ---

async def run_pipeline(args, client, initial_urls):
    """Set up queues, workers, and producers; run until all work is done."""
    scan_domain = _get_scan_domain(args, initial_urls)
    _load_scan_state(scan_domain)

    domain_queue = asyncio.Queue(maxsize=100)
    url_queue = HostBalancedQueue()  # balances across hosts at dequeue time
    js_queue = asyncio.Queue()  # unbounded — JS audit must not block crawl workers

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=max(4, args.concurrency // 2),
    )

    # Analysis systems
    semgrep_batch = SemgrepBatch()
    anomaly_detector = _load_anomaly_profiles(scan_domain)

    num_domain_workers = 5
    num_crawl_workers = args.concurrency
    num_js_workers = max(4, args.concurrency // 2)

    # url_queue producer tracker — poison pills go to page_crawl_workers
    url_tracker = ProducerTracker(url_queue, num_crawl_workers)

    # Start workers
    domain_tasks = [
        asyncio.create_task(domain_discovery_worker(domain_queue, url_queue, client, args))
        for _ in range(num_domain_workers)
    ]
    crawl_tasks = [
        asyncio.create_task(page_crawl_worker(url_queue, js_queue, client, args, url_tracker))
        for _ in range(num_crawl_workers)
    ]
    js_tasks = [
        asyncio.create_task(js_audit_worker(
            js_queue, client, args, executor, semgrep_batch, anomaly_detector,
            url_queue,
        ))
        for _ in range(num_js_workers)
    ]

    # Shared state: CT pushes subdomains here, CC consumes them in batches
    ct_discovered_subs = set()
    ct_discovered_lock = asyncio.Lock()
    ct_done = asyncio.Event()

    # Domain discovery workers are also url_queue producers
    for _ in range(num_domain_workers):
        await url_tracker.register()

    # Seed URLs producer
    async def seed_producer():
        await url_tracker.register()
        try:
            await seed_urls_into_pipeline(initial_urls, url_queue, domain_queue, args, executor)
        finally:
            await url_tracker.unregister()

    # CT producer — streams subdomains into shared set as they're found
    async def ct_wrapper():
        await url_tracker.register()
        try:
            domain = args.ct
            loop = asyncio.get_event_loop()
            state = await loop.run_in_executor(executor, ct_load_state, domain)

            if state['related_domains']:
                log_message("INFO", f"Known related domains: "
                            f"{', '.join(state['related_domains'][:20])}"
                            + (f" ... +{len(state['related_domains'])-20} more"
                               if len(state['related_domains']) > 20 else ""))

            # Re-seed previously discovered subdomains — cached != crawled
            prev_subs = set(state['scanned_subdomains'])
            if prev_subs:
                log_message("INFO", f"CT: re-seeding {len(prev_subs)} previously discovered subdomains")
                for sub in prev_subs:
                    await url_queue.put(f'https://{sub}/')
                for sub in prev_subs:
                    await domain_queue.put(sub)
                async with ct_discovered_lock:
                    ct_discovered_subs.update(prev_subs)

            while True:
                log_message("INFO", f"CT: fetching next month for {domain}...")
                new_subs, new_related, exhausted = await loop.run_in_executor(
                    executor, ct_fetch_next_month, domain, state,
                )

                if exhausted:
                    log_message("INFO", "CT: all months exhausted.")
                    break

                if new_related:
                    log_message("INFO", f"CT: {len(new_related)} new related domains: "
                                f"{', '.join(sorted(new_related))}")

                if new_subs:
                    log_message("INFO", f"CT: {len(new_subs)} new subdomains to scan")
                    for sub in new_subs:
                        await url_queue.put(f'https://{sub}/')
                    for sub in new_subs:
                        await domain_queue.put(sub)
                    async with ct_discovered_lock:
                        ct_discovered_subs.update(new_subs)
                    state['scanned_subdomains'] = sorted(
                        set(state['scanned_subdomains']) | new_subs
                    )

                await loop.run_in_executor(executor, ct_save_state, state, domain)

            await loop.run_in_executor(executor, ct_save_state, state, domain)
            log_message("INFO", f"CT complete: {len(state['scanned_subdomains'])} subdomains total")
        finally:
            ct_done.set()
            await url_tracker.unregister()

    # CC producer — starts with seed hosts, then queries CT subdomains in batches
    async def cc_wrapper():
        await url_tracker.register()
        try:
            cc_queried = set()
            max_cc_hosts = 20

            # Round 1: seed hosts immediately
            seed_hosts = set()
            for url in initial_urls:
                parsed = urlparse(url)
                if parsed.hostname:
                    seed_hosts.add(parsed.hostname)
            if seed_hosts:
                await cc_producer(url_queue, domain_queue, seed_hosts, executor)
                cc_queried.update(seed_hosts)

            # Subsequent rounds: pick up CT subdomains in batches
            while True:
                # Wait for CT to find more, or finish
                try:
                    await asyncio.wait_for(ct_done.wait(), timeout=10)
                except asyncio.TimeoutError:
                    pass  # Check for new subs periodically

                async with ct_discovered_lock:
                    new_hosts = ct_discovered_subs - cc_queried
                remaining_slots = max(0, max_cc_hosts - len(cc_queried))
                if new_hosts and remaining_slots > 0:
                    batch = sorted(new_hosts)
                    shuffle(batch)
                    batch = set(batch[:remaining_slots])
                    await cc_producer(url_queue, domain_queue, batch, executor)
                    cc_queried.update(batch)

                if ct_done.is_set():
                    # One final check after CT is done
                    async with ct_discovered_lock:
                        new_hosts = ct_discovered_subs - cc_queried
                    remaining_slots = max(0, max_cc_hosts - len(cc_queried))
                    if new_hosts and remaining_slots > 0:
                        batch = sorted(new_hosts)
                        shuffle(batch)
                        batch = set(batch[:remaining_slots])
                        await cc_producer(url_queue, domain_queue, batch, executor)
                        cc_queried.update(batch)
                    break
        finally:
            await url_tracker.unregister()

    # --- Periodic findings flusher ---
    anomaly_emitted = set()  # shared dedup set for anomaly findings

    def _boost_finding_host(finding):
        """Extract host from finding and boost its queue priority."""
        src = finding.get('source_url', '')
        if src:
            host = urlparse(src).hostname
            if host:
                url_queue.record_finding(host)

    async def findings_flusher():
        """Periodically flush Semgrep batch and anomaly findings."""
        loop = asyncio.get_event_loop()
        while True:
            await asyncio.sleep(60)
            if semgrep_batch.script_count > 0:
                log_message("INFO", f"Running Semgrep on {semgrep_batch.script_count} scripts...")
                findings = await loop.run_in_executor(executor, semgrep_batch.run_and_reset)
                for f in findings:
                    log_message("FINDING", f)
                    _boost_finding_host(f)
                log_message("INFO", f"Semgrep: {len(findings)} findings")
            anomaly_findings = anomaly_detector.score(anomaly_emitted)
            for f in anomaly_findings:
                log_message("FINDING", f)
                _boost_finding_host(f)
            if anomaly_findings:
                log_message("INFO", f"Anomaly: {len(anomaly_findings)} findings")

    flusher_task = asyncio.create_task(findings_flusher())

    # Launch all three concurrently
    producers = [asyncio.create_task(seed_producer())]
    if args.ct:
        producers.append(asyncio.create_task(ct_wrapper()))
    producers.append(asyncio.create_task(cc_wrapper()))
    await asyncio.gather(*producers)

    # Shut down domain_queue
    for _ in range(num_domain_workers):
        await domain_queue.put(_POISON)
    await asyncio.gather(*domain_tasks)

    # Domain workers done — unregister them as url producers
    for _ in range(num_domain_workers):
        await url_tracker.unregister()

    # url_tracker will send poison pills to crawl workers when all producers are done
    await asyncio.gather(*crawl_tasks)

    # Crawl workers done — shut down js_queue
    for _ in range(num_js_workers):
        await js_queue.put(_POISON)
    await asyncio.gather(*js_tasks)

    # Cancel periodic flusher and do one final flush
    flusher_task.cancel()
    loop = asyncio.get_event_loop()

    if semgrep_batch.script_count > 0:
        log_message("INFO", f"Final Semgrep on {semgrep_batch.script_count} scripts...")
        semgrep_findings = await loop.run_in_executor(executor, semgrep_batch.run_and_reset)
        for finding in semgrep_findings:
            log_message("FINDING", finding)
        log_message("INFO", f"Semgrep: {len(semgrep_findings)} findings")

    anomaly_findings = anomaly_detector.score(anomaly_emitted)
    for finding in anomaly_findings:
        log_message("FINDING", finding)
    if anomaly_findings:
        log_message("INFO", f"Anomaly: {len(anomaly_findings)} findings")

    anomaly_detector.update_profiles()
    executor.shutdown(wait=False)
    _save_scan_state(scan_domain)
    _save_anomaly_profiles(scan_domain, anomaly_detector)


# --- Main ---

async def main(args):
    """Main execution function — sets up and runs the async pipeline."""
    import analysis
    output.ARGS = args
    analysis.ARGS = args

    if args.ignore_hashes:
        try:
            with open(args.ignore_hashes, 'r', encoding='utf-8') as f:
                IGNORED_HASHES.update(line.strip() for line in f if line.strip())
                log_message("INFO", f"Loaded {len(IGNORED_HASHES)} hashes to ignore.")
        except IOError as e:
            log_message("ERROR", f"Unable to read ignore_hashes file '{args.ignore_hashes}': {e}")
            return

    # Load initial URLs based on auto-detected input type
    initial_urls = []
    if args._input_type == 'stdin':
        initial_urls = [line.strip() for line in sys.stdin if line.strip()]
    elif args._input_type == 'file':
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                initial_urls = [line.strip() for line in f if line.strip()]
        except IOError as e:
            log_message("ERROR", f"Unable to read file '{args.input}': {e}")
            return
    elif args._input_type == 'url':
        initial_urls = [args.input]
    elif args._input_type == 'domain':
        initial_urls = [f'https://{args.input}/']

    # Client configuration
    headers = {'User-Agent': Config.USER_AGENT}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    if args.cookie:
        headers['Cookie'] = args.cookie

    limits = httpx.Limits(
        max_connections=args.concurrency + 15,  # crawl + domain + JS workers
        max_keepalive_connections=args.concurrency,
    )

    async with httpx.AsyncClient(
        http2=True, limits=limits,
        follow_redirects=True, verify=True, headers=headers,
    ) as client:
        await run_pipeline(args, client, initial_urls)

    log_message("INFO", "Scan finished.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="JSBot — Opinionated JavaScript security scanner. Give it a domain, it does the rest.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('input', nargs='?', default=None,
                        help="Domain, URL, file of URLs, or '-' for stdin.")
    parser.add_argument('-H', '--header', action='append',
                        help="Custom HTTP header (repeatable).")
    parser.add_argument('-b', '--cookie',
                        help="Cookie header value.")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Verbose logging to stderr.")
    parser.add_argument('--show-errors', action='store_true',
                        help="Show HTTP error details on stderr.")
    parser.add_argument('-s', '--save', action='store_true',
                        help="Save unique JS files to disk (SHA256-named).")
    parser.add_argument('--ignore-hashes',
                        help="File of SHA256 hashes to skip.")

    if len(sys.argv) == 1 and sys.stdin.isatty():
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # --- Auto-detect input type ---
    if args.input is None:
        if not sys.stdin.isatty():
            args._input_type = 'stdin'
        else:
            parser.print_help(sys.stderr)
            sys.exit(1)
    elif args.input == '-':
        args._input_type = 'stdin'
    elif os.path.isfile(args.input):
        args._input_type = 'file'
    elif args.input.startswith(('http://', 'https://')):
        args._input_type = 'url'
    else:
        args._input_type = 'domain'

    args.concurrency = 20

    # CT discovery: automatic for domain input
    args.ct = args.input if args._input_type == 'domain' else None

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted.", file=sys.stderr)
        sys.exit(0)
