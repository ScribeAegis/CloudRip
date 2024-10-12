# CloudRip

CloudRip is a CloudFlare bypassing tool designed to help find real IP addresses of domains behind Cloudflare protection by enumerating subdomains.

## Features
- Multithreaded subdomain resolution for faster scanning
- Option to save results to an output file
- Supports custom wordlists
- Color-coded terminal output for readability

## Installation
CloudRip requires Python 3 and the following libraries:
- `colorama`
- `pyfiglet`

To install dependencies, run:
```bash
pip install colorama pyfiglet

### Usage
python3 cloudrip.py <domain> -w <wordlist> -t <threads> -o <output_file>
<domain>: The target domain (e.g., example.com)
-w <wordlist>: Path to a custom wordlist (default is dom.txt)
-t <threads>: Number of threads to use for scanning (default is 10)
-o <output_file>: Save results to a file (optional)

### Example
python3 cloudrip.py example.com -w dom.txt -t 20 -o results.txt

### Disclaimer
This tool is intended for research, educational purposes and ethical testing. Do not use it against websites without proper authorization.
