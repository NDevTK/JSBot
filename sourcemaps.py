"""Source map fetching and original source extraction."""
import json
import base64
import re
from urllib.parse import urljoin

from output import log_message

SOURCE_MAP_URL_RE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')


async def try_fetch_sourcemap(script_url, script_content, client):
    """Attempt to fetch a source map for the given script.

    Returns parsed source map JSON or None.
    """
    if not script_url or script_url == "inline":
        return None

    urls_to_try = []

    # Check for sourceMappingURL comment at end of file
    match = SOURCE_MAP_URL_RE.search(script_content[-500:])
    if match:
        map_ref = match.group(1)
        if map_ref.startswith('data:'):
            return _parse_data_uri_sourcemap(map_ref)
        urls_to_try.append(urljoin(script_url, map_ref))

    # Try <script_url>.map convention
    urls_to_try.append(script_url + '.map')

    for map_url in urls_to_try:
        try:
            resp = await client.get(map_url, timeout=5)
            if resp.status_code == 200:
                ct = resp.headers.get('content-type', '')
                if 'json' in ct or 'javascript' in ct or resp.text.strip().startswith('{'):
                    try:
                        sm = json.loads(resp.text)
                        if 'mappings' in sm and 'sources' in sm:
                            log_message("INFO", f"Found source map: {map_url}")
                            return sm
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass

    return None


def _parse_data_uri_sourcemap(data_uri):
    """Parse a data: URI source map (base64 encoded)."""
    try:
        _, encoded = data_uri.split(',', 1)
        decoded = base64.b64decode(encoded).decode('utf-8')
        sm = json.loads(decoded)
        if 'mappings' in sm and 'sources' in sm:
            return sm
    except Exception:
        pass
    return None


def get_original_source(sourcemap):
    """Extract original source code from a source map's sourcesContent."""
    if 'sourcesContent' in sourcemap:
        contents = sourcemap['sourcesContent']
        if contents and any(c for c in contents if c):
            return '\n// --- Source Boundary ---\n'.join(
                c or '' for c in contents
            )
    return None
