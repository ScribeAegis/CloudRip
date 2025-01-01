# CloudRip

CloudRip is designed to bypass Cloudflare protection and help discover the real IP addresses of domains by enumerating subdomains. It can be used for ethical research, educational purposes, and penetration testing to identify the actual servers behind Cloudflare.

## Features
- **Multithreaded Subdomain Resolution:** Faster scanning with configurable threading.
- **Cloudflare IP Filtering:** Automatically filters out IPs known to belong to Cloudflare, improving the accuracy of the results.
- **Customizable Wordlists:** Supports user-defined wordlists for subdomain enumeration.
- **Terminal Output:** Easy-to-read results with color-coded output for status and findings.
- **Interrupt Handling:** Allows users to pause the scan with `Ctrl+C` and choose whether to quit or resume.
- **Option to Save Results:** Save found IPs to an output file for further analysis.

## Installation
CloudRip requires Python 3 and the following libraries:
- `colorama`
- `pyfiglet`

### To install dependencies, run:
```
pip install colorama pyfiglet
```
## Usage
```
python3 cloudrip.py <domain> -w <wordlist> -t <threads> -o <output_file> <domain>: The target domain (e.g., example.com)
-w <wordlist>: Path to a custom wordlist (default is dom.txt)
-t <threads>: Number of threads to use for concurrent scanning (default is 10)
-o <output_file>: Optional. If specified, saves the results to a file
```
## Example
```
python3 cloudrip.py example.com -w dom.txt -t 20 -o results.txt
```
**New Features**
- **Cloudflare IP Filtering:** Automatically checks and filters out IPs that are within Cloudflare’s known IP ranges to improve accuracy.
- **Interruption Handling:** Press Ctrl+C to pause the scan and choose whether to quit or continue.
- **Error Handling:** Provides detailed feedback for various DNS resolution issues such as timeouts and no responses.
- **Rate Limiting:** Adjustable rate limiting to prevent getting blocked during scans.
- **Extended Wordlist Support:** Includes a comprehensive and categorized default wordlist (dom.txt) for better results.

## Disclaimer
CloudRip is intended for research, educational purposes, and ethical testing only. Do not use this tool against websites without proper authorization. Misuse of this tool may be illegal and is solely the responsibility of the user.
