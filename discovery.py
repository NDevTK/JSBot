"""Target discovery: CT logs, wayback, robots/sitemap, spider."""
import json
import os
import time
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

from bs4 import BeautifulSoup

from output import log_message

from waybackpy import WaybackMachineCDXServerAPI
import psycopg2


# --- Certificate Transparency Discovery ---
CT_CONN_PARAMS = dict(host='crt.sh', port=5432, user='guest', dbname='certwatch', connect_timeout=15)
CT_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.ct_cache')


def ct_cache_path(domain, month_key):
    """Return cache file path for a domain + month (YYYY-MM)."""
    d = os.path.join(CT_CACHE_DIR, domain)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f'{month_key}.json')


def ct_state_path(domain):
    """Return state file path for a domain."""
    d = os.path.join(CT_CACHE_DIR, domain)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, 'state.json')


def ct_load_state(domain):
    """Load CT scan state: which subdomains have been scanned, which months fetched."""
    path = ct_state_path(domain)
    if not os.path.exists(path):
        return {'scanned_subdomains': [], 'fetched_months': [], 'related_domains': []}
    with open(path) as f:
        return json.load(f)


def ct_save_state(state, domain):
    """Save CT scan state."""
    path = ct_state_path(domain)
    with open(path, 'w') as f:
        json.dump(state, f)


def ct_load_cache(domain, month_key):
    """Load cached CT results for a month. Returns (subdomains, related) or None."""
    path = ct_cache_path(domain, month_key)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    return set(data['subdomains']), set(data['related'])


def ct_save_cache(domain, month_key, subdomains, related):
    """Save CT results to cache."""
    path = ct_cache_path(domain, month_key)
    with open(path, 'w') as f:
        json.dump({'subdomains': sorted(subdomains), 'related': sorted(related)}, f)


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


def ct_fetch_next_month(domain, state):
    """Fetch the next unfetched month from CT logs.

    Returns (new_subdomains set, new_related set, exhausted bool).
    On failure, skips to other months first. Failed months are retried
    at the end of the run, not persisted as fetched.
    """
    fetched = set(state['fetched_months'])
    failed = set(state.get('failed_months', []))
    known_subs = set(state['scanned_subdomains'])

    # Try unfailed, unfetched months first; then retry failed ones
    for month_key, start_date, end_date in ct_month_sequence():
        if month_key in fetched or month_key in failed:
            continue

        # Check cache first (from previous ct_test.py runs)
        cached = ct_load_cache(domain, month_key)
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
            continue

        subs, related = ct_extract_domains(rows, domain)
        ct_save_cache(domain, month_key, subs, related)
        state['fetched_months'].append(month_key)
        new_subs = subs - known_subs
        new_related = set(related) - set(state['related_domains'])
        state['related_domains'] = sorted(set(state['related_domains']) | related)
        return new_subs, new_related, False

    # All non-failed months done. Retry failed months once.
    if failed:
        log_message("INFO", f"CT: retrying {len(failed)} previously failed months...")
        for month_key, start_date, end_date in ct_month_sequence():
            if month_key not in failed or month_key in fetched:
                continue

            rows = ct_query_month(domain, start_date, end_date)
            if rows is None:
                log_message("ERROR", f"CT retry failed for {domain} {month_key}")
                continue

            failed.discard(month_key)
            state['failed_months'] = sorted(failed)
            subs, related = ct_extract_domains(rows, domain)
            ct_save_cache(domain, month_key, subs, related)
            state['fetched_months'].append(month_key)
            new_subs = subs - known_subs
            new_related = set(related) - set(state['related_domains'])
            state['related_domains'] = sorted(set(state['related_domains']) | related)
            return new_subs, new_related, False

    # Clean up failed_months from state -- don't persist across runs
    state.pop('failed_months', None)
    return set(), set(), True  # All months exhausted


# --- Wayback Machine ---

def fetch_wayback_urls(domains, user_agent):
    """Fetches historical URLs from the Wayback Machine per-host."""
    all_urls = set()
    for domain in domains:
        domain = domain.strip()
        if not domain: continue
        # Append /* for CDX prefix matching — all paths on this host
        search_url = f'{domain}/*'
        log_message("INFO", f"Fetching wayback URLs for: {domain}")
        try:
            cdx = WaybackMachineCDXServerAPI(
                url=search_url, user_agent=user_agent, collapses=["urlkey"],
                filters=["statuscode:200", "mimetype:(text/html|application/javascript)"]
            )
            snapshots = {s.original for s in cdx.snapshots()}
            log_message("INFO", f"Found {len(snapshots)} URLs for {domain} from Wayback Machine.")
            all_urls.update(snapshots)
        except Exception as e:
            log_message("ERROR", f"Wayback Machine request failed for {domain}: {e}")
    return list(all_urls)


# --- robots.txt & sitemap.xml Discovery ---

async def discover_paths(domain, client):
    """Discovers URLs from robots.txt and sitemap.xml for a domain."""
    import httpx
    discovered = set()
    base = f"https://{domain}"
    timeout = httpx.Timeout(10.0, connect=5.0)

    # robots.txt
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
            log_message("INFO", f"Found {len(discovered)} paths from robots.txt for {domain}")
    except (httpx.ConnectError, httpx.ConnectTimeout):
        # Domain is unreachable — don't bother with sitemap
        raise
    except Exception as e:
        log_message("ERROR", f"Failed to fetch robots.txt for {domain}: {e}")

    # sitemap.xml
    sitemap_urls = set()
    try:
        resp = await client.get(f"{base}/sitemap.xml", timeout=timeout)
        if resp.status_code == 200:
            try:
                root = ElementTree.fromstring(resp.text)
                ns = ''
                if root.tag.startswith('{'):
                    ns = root.tag.split('}')[0] + '}'
                for loc in root.iter(f'{ns}loc'):
                    if loc.text:
                        sitemap_urls.add(loc.text.strip())
                log_message("INFO", f"Found {len(sitemap_urls)} URLs from sitemap.xml for {domain}")
            except ElementTree.ParseError:
                log_message("ERROR", f"Failed to parse sitemap.xml for {domain}")
    except Exception as e:
        log_message("ERROR", f"Failed to fetch sitemap.xml for {domain}: {e}")

    discovered.update(sitemap_urls)
    return discovered


# --- Spider ---

def spider_links(response_text, response_url, base_domain):
    """Extracts same-domain <a href> links from an HTML page."""
    discovered = set()
    try:
        parser = BeautifulSoup(response_text, 'lxml')
        for a_tag in parser.find_all('a', href=True):
            href = a_tag['href'].strip()
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            full_url = urljoin(str(response_url), href)
            parsed = urlparse(full_url)
            if parsed.hostname and base_domain in parsed.hostname:
                discovered.add(full_url)
    except Exception:
        pass
    return discovered
