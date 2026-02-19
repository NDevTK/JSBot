"""Target discovery: CT logs, Common Crawl, robots/sitemap, spider."""
import json
import os
import time
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

from output import log_message

import psycopg2


# --- Certificate Transparency Discovery ---
CT_CONN_PARAMS = dict(host='crt.sh', port=5432, user='guest', dbname='certwatch', connect_timeout=15)


def ct_query_month(domain, yr_start, yr_end, limit=5000, retries=2):
    """Query crt.sh PostgreSQL for certs matching a domain in one time window."""
    rev = domain[::-1]
    for attempt in range(retries):
        try:
            conn = psycopg2.connect(**CT_CONN_PARAMS)
            conn.set_session(autocommit=True)
            cur = conn.cursor()
            cur.execute("""
                SELECT x509_altNames(c.certificate, 2)
                FROM certificate c
                WHERE identities(c.certificate) @@ to_tsquery('certwatch', %s)
                    AND COALESCE(x509_notafter(c.certificate), 'infinity') >= %s
                    AND COALESCE(x509_notafter(c.certificate), 'infinity') < %s
                    AND x509_commonName(c.certificate) LIKE %s
                LIMIT %s
            """, (rev, yr_start, yr_end, f'%.{domain}', limit))
            rows = cur.fetchall()
            cur.close()
            conn.close()
            return rows
        except Exception:
            try: conn.close()
            except: pass
            if attempt < retries - 1:
                time.sleep(1)
    return None


def ct_extract_domains(rows, domain):
    """Extract subdomains and related root domains from cert SANs."""
    subdomains = set()
    related = set()
    brand_tld = '.' not in domain
    for row in rows:
        if not row[0]:
            continue
        for n in row[0].split('\n'):
            n = n.strip().lstrip('*.')
            if not n:
                continue
            if not brand_tld and '.' not in n:
                continue
            if n == domain or n.endswith('.' + domain):
                subdomains.add(n)
            else:
                parts = n.split('.')
                if len(parts) >= 2:
                    related.add('.'.join(parts[-2:]))
    return subdomains, related


def ct_month_sequence():
    """Generate (month_key, start_date, end_date) tuples from current month backward."""
    import datetime
    now = datetime.datetime.now()
    y, m = now.year, now.month
    stop_year = 2019
    while y >= stop_year:
        end_m, end_y = (m + 1, y) if m < 12 else (1, y + 1)
        month_key = f'{y}-{m:02d}'
        start_date = f'{y}-{m:02d}-01'
        end_date = f'{end_y}-{end_m:02d}-01'
        yield month_key, start_date, end_date
        m -= 1
        if m < 1:
            m = 12
            y -= 1


def ct_fetch_next_month(domain, state, store=None):
    """Fetch the next unfetched month from CT logs.

    Returns (new_subdomains set, new_related set, exhausted bool).
    On failure, skips to other months first. Failed months are retried
    at the end of the run, not persisted as fetched.

    Args:
        domain: Domain to query.
        state: Mutable state dict (fetched_months, scanned_subdomains, etc.).
        store: FindingsStore instance for CT cache persistence.
    """
    fetched = set(state['fetched_months'])
    failed = set(state.get('failed_months', []))
    known_subs = set(state['scanned_subdomains'])

    # Try unfailed, unfetched months first; then retry failed ones
    consecutive_failures = 0
    for month_key, start_date, end_date in ct_month_sequence():
        if month_key in fetched or month_key in failed:
            continue

        # Check cache first (from previous runs)
        cached = store.load_ct_cache(month_key) if store else None
        if cached:
            subs, related = cached
            state['fetched_months'].append(month_key)
            new_subs = subs - known_subs
            new_related = set(related) - set(state['related_domains'])
            state['related_domains'] = sorted(set(state['related_domains']) | related)
            return new_subs, new_related, False

        # Query crt.sh
        rows = ct_query_month(domain, start_date, end_date)
        if rows is None:
            log_message("ERROR", f"CT query failed for {domain} {month_key}, will retry later")
            failed.add(month_key)
            state['failed_months'] = sorted(failed)
            consecutive_failures += 1
            # Give up after 5 consecutive failures — crt.sh is overloaded or domain is too big
            if consecutive_failures >= 5:
                log_message("INFO", f"CT: {consecutive_failures} consecutive failures, stopping early")
                state.pop('failed_months', None)
                return set(), set(), True
            continue

        consecutive_failures = 0
        subs, related = ct_extract_domains(rows, domain)
        if store:
            store.save_ct_cache(month_key, subs, related)
        state['fetched_months'].append(month_key)
        new_subs = subs - known_subs
        new_related = set(related) - set(state['related_domains'])
        state['related_domains'] = sorted(set(state['related_domains']) | related)
        return new_subs, new_related, False

    # All non-failed months done. Retry failed months once (cap at 5).
    retry_list = sorted(failed)[:5]
    if retry_list:
        log_message("INFO", f"CT: retrying {len(retry_list)} of {len(failed)} failed months...")
        for month_key, start_date, end_date in ct_month_sequence():
            if month_key not in retry_list or month_key in fetched:
                continue

            rows = ct_query_month(domain, start_date, end_date)
            if rows is None:
                log_message("ERROR", f"CT retry failed for {domain} {month_key}")
                continue

            failed.discard(month_key)
            state['failed_months'] = sorted(failed)
            subs, related = ct_extract_domains(rows, domain)
            if store:
                store.save_ct_cache(month_key, subs, related)
            state['fetched_months'].append(month_key)
            new_subs = subs - known_subs
            new_related = set(related) - set(state['related_domains'])
            state['related_domains'] = sorted(set(state['related_domains']) | related)
            return new_subs, new_related, False

    # Clean up failed_months from state -- don't persist across runs
    state.pop('failed_months', None)
    return set(), set(), True  # All months exhausted


# --- Common Crawl URL Discovery ---

CC_CDX_BASE = 'https://index.commoncrawl.org'

# Query params that don't change the page — strip before dedup
_JUNK_PARAMS = {
    'authuser', 'hl', 'gl', '_gl', 'gclid', 'gclsrc', 'utm_source',
    'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'ref',
    '__hstc', '__hssc', '__hsfp', 'hsCtaTracking', 'vid', 'dclid',
    'fbclid', 'mc_cid', 'mc_eid', '_ga', 'sxsrf',
}


def _cc_get_indexes(user_agent, count=3):
    """Get the N most recent Common Crawl index URLs (with retry)."""
    for attempt in range(3):
        try:
            resp = requests.get(f'{CC_CDX_BASE}/collinfo.json',
                                headers={'User-Agent': user_agent}, timeout=15)
            resp.raise_for_status()
            indexes = resp.json()
            return [idx['cdx-api'] for idx in indexes[:count]]
        except Exception as e:
            if attempt < 2:
                import time
                time.sleep(2 ** attempt)
                continue
            log_message("ERROR", f"Failed to get Common Crawl indexes: {e}")
            return []


def _cc_clean_url(url):
    """Strip tracking/junk query params and normalize."""
    parsed = urlparse(url)
    if not parsed.query:
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    # Keep only non-junk params with actual alphanumeric keys
    from urllib.parse import parse_qs, urlencode
    params = parse_qs(parsed.query, keep_blank_values=True)
    kept = {k: v for k, v in params.items()
            if k.lower() not in _JUNK_PARAMS and k.isalnum()}
    if not kept:
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    clean_query = urlencode(kept, doseq=True)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{clean_query}"


def _cc_fetch_host(index_url, host, user_agent, limit, rate_lock=None):
    """Fetch URLs for one host from one CC index (with retry + rate limiting)."""
    params = {
        'url': f'{host}/*',
        'output': 'json',
        'limit': limit,
        'filter': '=status:200',
    }
    for attempt in range(3):
        if rate_lock is not None:
            with rate_lock:
                time.sleep(1)  # 1 req/sec across all threads
        try:
            resp = requests.get(index_url, params=params,
                                headers={'User-Agent': user_agent}, timeout=60)
            if resp.status_code == 429:
                wait = min(30, 5 * (attempt + 1))
                log_message("ERROR", f"CC rate limited for {host}, waiting {wait}s")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            urls = set()
            for line in resp.text.strip().split('\n'):
                if not line.strip():
                    continue
                record = json.loads(line)
                if 'url' in record:
                    urls.add(_cc_clean_url(record['url']))
            return urls
        except requests.exceptions.ConnectionError:
            time.sleep(2 ** attempt)
        except Exception as e:
            log_message("ERROR", f"Common Crawl query failed for {host}: {e}")
            time.sleep(2 ** attempt)
    log_message("ERROR", f"Common Crawl gave up on {host} after 3 attempts")
    return set()


def fetch_commoncrawl_urls(domains, user_agent, per_host_limit=2000):
    """Fetch historical URLs from Common Crawl CDX across multiple indexes."""
    indexes = _cc_get_indexes(user_agent, count=3)
    if not indexes:
        return []

    log_message("INFO", f"Querying {len(indexes)} Common Crawl indexes for {len(domains)} hosts")

    import threading
    rate_lock = threading.Lock()

    all_urls = set()
    # Query (host, index) pairs with rate limiting — 2 workers, 1 req/sec each
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {}
        for domain in domains:
            domain = domain.strip()
            if not domain:
                continue
            for index_url in indexes:
                future = pool.submit(_cc_fetch_host, index_url, domain,
                                     user_agent, per_host_limit, rate_lock)
                futures[future] = (domain, index_url)

        for future in as_completed(futures):
            domain, index_url = futures[future]
            urls = future.result()
            if urls:
                all_urls.update(urls)

    # Dedup by path (strip remaining query params for path-level dedup)
    seen_paths = set()
    deduped = []
    for url in all_urls:
        path_key = urlparse(url)
        key = f"{path_key.scheme}://{path_key.netloc}{path_key.path}".lower().rstrip('/')
        if key not in seen_paths:
            seen_paths.add(key)
            deduped.append(url)

    log_message("INFO", f"Common Crawl: {len(all_urls)} raw → {len(deduped)} unique paths")
    return deduped


# --- robots.txt & sitemap.xml Discovery ---

def _parse_sitemap(xml_text):
    """Parse a sitemap or sitemap index XML. Returns (page_urls, child_sitemap_urls)."""
    pages = set()
    children = set()
    try:
        root = ElementTree.fromstring(xml_text)
        ns = ''
        if root.tag.startswith('{'):
            ns = root.tag.split('}')[0] + '}'
        # Sitemap index: <sitemapindex> contains <sitemap><loc>...</loc></sitemap>
        is_index = 'sitemapindex' in root.tag.lower()
        for loc in root.iter(f'{ns}loc'):
            if loc.text:
                url = loc.text.strip()
                if is_index:
                    children.add(url)
                else:
                    pages.add(url)
    except ElementTree.ParseError:
        pass
    return pages, children


async def discover_paths(domain, client):
    """Discovers URLs from robots.txt and sitemap.xml for a domain."""
    import httpx
    discovered = set()
    base = f"https://{domain}"
    timeout = httpx.Timeout(10.0, connect=5.0)

    # robots.txt — extract Disallow/Allow paths and Sitemap: directives
    sitemap_locations = set()
    try:
        resp = await client.get(f"{base}/robots.txt", timeout=timeout)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(('disallow:', 'allow:')):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        clean_path = path.replace('*', '').rstrip('$')
                        if clean_path:
                            discovered.add(urljoin(base, clean_path))
                elif line.lower().startswith('sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    if sitemap_url:
                        sitemap_locations.add(sitemap_url)
            log_message("INFO", f"Found {len(discovered)} paths from robots.txt for {domain}")
    except (httpx.ConnectError, httpx.ConnectTimeout):
        # Domain is unreachable — don't bother with sitemap
        raise
    except Exception as e:
        log_message("ERROR", f"Failed to fetch robots.txt for {domain}: {e}")

    # Always try the default location too
    sitemap_locations.add(f"{base}/sitemap.xml")

    # Fetch sitemaps — follows sitemap indexes one level deep
    fetched_sitemaps = set()
    async def _fetch_sitemap(url):
        if url in fetched_sitemaps:
            return set(), set()
        fetched_sitemaps.add(url)
        try:
            resp = await client.get(url, timeout=timeout)
            if resp.status_code == 200:
                return _parse_sitemap(resp.text)
        except Exception as e:
            log_message("ERROR", f"Failed to fetch sitemap {url}: {e}")
        return set(), set()

    sitemap_urls = set()
    for sitemap_url in sitemap_locations:
        pages, children = await _fetch_sitemap(sitemap_url)
        sitemap_urls.update(pages)
        # Follow child sitemaps (one level — no recursive indexes)
        for child in children:
            child_pages, _ = await _fetch_sitemap(child)
            sitemap_urls.update(child_pages)

    if sitemap_urls:
        log_message("INFO", f"Found {len(sitemap_urls)} URLs from sitemaps for {domain}")

    discovered.update(sitemap_urls)
    return discovered


# --- Spider ---

def _is_same_domain(hostname, base_domain):
    """Check if hostname belongs to base_domain (exact match or subdomain)."""
    return hostname == base_domain or hostname.endswith('.' + base_domain)


def spider_links(response_text, response_url, base_domain):
    """Extracts same-domain links from an HTML page (a href, iframe src, form action)."""
    discovered = set()
    try:
        parser = BeautifulSoup(response_text, 'lxml')
        urls_to_check = []
        for a_tag in parser.find_all('a', href=True):
            urls_to_check.append(a_tag['href'])
        for iframe in parser.find_all('iframe', src=True):
            urls_to_check.append(iframe['src'])
        for form in parser.find_all('form', action=True):
            urls_to_check.append(form['action'])
        for href in urls_to_check:
            href = href.strip()
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            full_url = urljoin(str(response_url), href)
            parsed = urlparse(full_url)
            if parsed.hostname and _is_same_domain(parsed.hostname, base_domain):
                discovered.add(full_url)
    except Exception:
        pass
    return discovered
