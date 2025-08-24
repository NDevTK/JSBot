### README.md

---
# JSBot: Autonomous JavaScript Security Reconnaissance Tool

JSBot is a powerful and extensible Python script for security researchers and autonomous agents to crawl web pages, extract JavaScript files, and analyze them for potentially interesting or vulnerable patterns. It automates the discovery of inline and external JavaScript, scans for security-related code snippets, and presents the findings in a structured, machine-readable format.

Its primary purpose is to serve as the core analysis engine in an automated security pipeline, allowing for continuous, large-scale reconnaissance of web application JavaScript.

## Key Features

-   **Automation-Friendly**: Accepts URLs from files or `stdin`, making it easy to chain with other tools in a pipeline.
-   **Structured JSON Output**: Findings are printed as JSON objects, ideal for ingestion into databases or other analysis tools.
-   **Intelligent Filtering**: Can ignore known, benign third-party scripts via a hash-based ignore file, focusing analysis on custom code.
-   **Enhanced Security Patterns**: Uses an expanded and categorized list of regular expressions to identify potential vulnerabilities.
-   **Asynchronous & Concurrent**: Built with `asyncio` and `httpx` for high-speed, concurrent scanning.
-   **Wayback Machine Integration**: Can automatically fetch and scan historical URLs to dramatically expand scope.
-   **Flexible Command-Line Interface**: Rich set of arguments to customize scans (e.g., control concurrency, disable redirects, save scripts).
-   **Link Finder Mode**: A dedicated mode (`--link-mode`) to extract all URLs found within JavaScript files.
-   **Extensible**: Organized code structure makes it easy to add new security patterns and functionality.

## Requirements

The script requires Python 3.8+ and several external libraries.

You can install all dependencies using the provided `requirements.txt` file:

```
pip install -r requirements.txt
```

## Usage

The script is run from the command line, accepting a URL file or `stdin` as its main input.

### Basic Syntax

```bash
# Scan URLs from a file
python scan.py [options] urls.txt

# Pipe URLs from another tool (e.g., subfinder)
subfinder -d example.com | python scan.py -
```

### Command-Line Arguments

```
usage: scan.py [-h] [-s] [-v] [--show-errors] [-c CONCURRENCY] [--ignore-hashes IGNORE_HASHES] [--no-external] [--no-redirects] [-k] [-w] [--no-clean-url] [--link-mode] [--format-js] url_file

JSBot 2.1 - An autonomous script to find interesting JavaScript for security research.

positional arguments:
  url_file              Path to a file with URLs, or '-' to read from stdin.

options:
  -h, --help            show this help message and exit
  -s, --save            Save unique JS files to disk, named by SHA256 hash.
  -v, --verbose         Enable verbose informational output.
  --show-errors         Show error messages for failed requests.
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent requests. (Default: 20)
  --ignore-hashes IGNORE_HASHES
                        Path to a file containing SHA256 hashes of JS files to ignore.
  --no-external         Don't fetch external JavaScript files.
  --no-redirects        Don't follow HTTP redirects.
  -k, --insecure        Disable SSL/TLS certificate verification.
  -w, --wayback         Fetch historical URLs from the Wayback Machine for the given domains.
  --no-clean-url        Don't clean URL parameters before scanning.
  --link-mode           Only find and output links/URLs found in JS files.
  --format-js           Beautify JS code before analysis (requires 'jsbeautifier').
```

## Example Usage Scenarios

#### 1. Standard Scan from a File

Run a standard scan on a list of URLs, saving findings to a JSONL file.

```bash
python scan.py --verbose urls.txt > results.jsonl
```

#### 2. Usage in an Automation Chain

Use `subfinder` to discover subdomains and pipe them directly into JSBot, leveraging the Wayback Machine to find historical URLs for analysis.

```bash
subfinder -d example.com | python scan.py -w - > results.jsonl```

#### 3. Focused Analysis by Ignoring Common Libraries

Scan a site but ignore common, benign libraries like jQuery and React to focus only on custom-written code.

```bash
# known_hashes.txt contains the SHA256 hashes of libraries to ignore
python scan.py --ignore-hashes known_hashes.txt urls.txt
```

#### 4. Saving Scripts for Offline Analysis

Crawl all pages and save every unique JavaScript file encountered for later analysis.

```bash
# This will create .js files named by their SHA256 hash
python scan.py -s urls.txt
```
