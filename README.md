# JSBot: JavaScript Security Reconnaissance Tool

JSBot is a powerful and extensible Python script for security researchers to crawl web pages, extract JavaScript files, and analyze them for potentially interesting or vulnerable patterns. It automates the discovery of inline and external JavaScript, scans for security-related code snippets, and presents the findings in a structured, machine-readable format.

Its primary purpose is to aid in the initial reconnaissance phase of a web application security assessment by highlighting JavaScript code that might be relevant for further investigation, such as potential XSS sinks, open redirects, or DOM clobbering vectors.

## Key Features

- **Structured JSON Output**: Findings are printed as JSON objects, making it easy to pipe output to other tools like `jq` or logging platforms.
- **Enhanced Security Patterns**: Uses an expanded and categorized list of regular expressions to identify potential vulnerabilities like DOM Clobbering, Open Redirects, Eval Injections, and more.
- **Asynchronous & Concurrent**: Built with `asyncio` and `httpx` for high-speed, concurrent scanning of many URLs.
- **Wayback Machine Integration**: Can automatically fetch and scan historical URLs from the Wayback Machine to dramatically expand scope.
- **Flexible Command-Line Interface**: Rich set of command-line arguments to customize scans (e.g., control concurrency, disable redirects, save scripts).
- **Link Finder Mode**: A dedicated mode (`--link-mode`) to extract all URLs found within JavaScript files.
- **Code Formatting**: Optionally beautifies JavaScript code before analysis for more accurate line numbers and easier manual review.
- **Extensible**: Organized code structure makes it easy to add new security patterns and functionality.

## Requirements

The script requires Python 3.8+ and several external libraries.

You can install all dependencies using the provided `requirements.txt` file:

```
httpx[http2]
beautifulsoup4
lxml
jsbeautifier
waybackpy
```

## Installation

1.  Clone the repository or download the `scan.py` and `requirements.txt` files.
2.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

The script is run from the command line, with the path to a URL file as its main argument.

### Basic Syntax

```bash
python scan.py [options] urls.txt
```

### Command-Line Arguments

```
usage: scan.py [-h] [-s] [-v] [--show-errors] [-c CONCURRENCY] [--no-external] [--no-redirects] [-k] [-w] [--no-clean-url] [--link-mode] [--format-js] url_file

JSBot - A script to find interesting JavaScript for security research.

positional arguments:
  url_file              Path to a file containing URLs to scan (one per line).

options:
  -h, --help            show this help message and exit
  -s, --save            Save unique JS files to disk.
  -v, --verbose         Enable verbose informational output.
  --show-errors         Show error messages for failed requests.
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent requests. (Default: 20)
  --no-external         Don't fetch external JavaScript files.
  --no-redirects        Don't follow HTTP redirects.
  -k, --insecure        Disable SSL/TLS certificate verification.
  -w, --wayback         Fetch URLs from the Wayback Machine for the given domains.
  --no-clean-url        Don't clean URL parameters before scanning.
  --link-mode           Only find and output links/URLs found in JS files.
  --format-js           Beautify JS code before analysis (requires 'jsbeautifier').
```

## Input File Format

The input `urls.txt` file should contain one URL or domain per line.

**Example `urls.txt`:**
```
https://example.com/login
https://sub.example.com
https://anotherexample.org/about
```

## Output Format

The primary output of the script is a stream of JSON objects, one for each finding. This allows for easy parsing and integration with other tools.

### Finding JSON Structure

Each JSON object represents a single matched security pattern and contains the following fields:

-   `source_url`: The original URL that was crawled where the script was found.
-   `script_url`: The URL of the JavaScript file. For inline scripts, this value is `"inline"`.
-   `category`: The type of finding (e.g., "Open Redirect", "DOM Clobbering").
-   `matched_text`: The exact string of code that matched the pattern.
-   `line_number`: The approximate line number within the script where the match was found.

### Example JSON Output

```json
{"source_url": "https://example.com", "script_url": "https://example.com/assets/main.js", "category": "Open Redirect", "matched_text": "location.href =", "line_number": 152}
{"source_url": "https://example.com/login", "script_url": "inline", "category": "DOM Clobbering", "matched_text": "innerHTML =", "line_number": 88}
```

## Example Usage Scenarios

#### 1. Standard Scan

Run a standard scan on a list of URLs, showing verbose output and any errors.

```bash
python scan.py --verbose --show-errors urls.txt > results.json
```

#### 2. Deep Discovery with Wayback Machine

Scan a list of root domains and use the Wayback Machine to find and scan historical URLs.

```bash
# urls.txt contains "example.com"
python scan.py -w -v urls.txt | tee results.json
```

#### 3. Extracting Endpoints and URLs

Use `--link-mode` to only extract URLs found inside JavaScript files. This is useful for API endpoint discovery.

```bash
python scan.py --link-mode urls.txt | jq '.matched_text' | sort -u
```

#### 4. Saving Scripts for Offline Analysis

Crawl all pages and save every unique JavaScript file encountered for later analysis with other tools like `grep`.

```bash
# This will create .js files named by their SHA256 hash in the current directory
python scan.py -s urls.txt
```

## Security Patterns Detected

JSBot looks for patterns that fall into the following categories:

-   **DOM Clobbering**: Identifies assignments to `innerHTML`, `outerHTML`, etc.
-   **Open Redirect**: Looks for manipulations of `location.href`, `location.assign`, and other redirect vectors.
-   **Eval Injection**: Flags usage of dangerous functions like `eval()`, `setTimeout()` with non-literal arguments, and `execScript()`.
-   **Cookie Manipulation**: Highlights direct assignments to `document.cookie`.
-   **Potentially Unsafe Sinks**: Finds common client-side storage and messaging functions like `postMessage`, `localStorage`, and `sessionStorage`.
-   **Link Finder**: A general-purpose regex to extract any URL from code (used in `--link-mode`).

## Disclaimer

This tool is intended for educational purposes and authorized security research only. Do not use this tool to scan websites without explicit permission from the owner. The developers are not responsible for any misuse or damage caused by this script.
