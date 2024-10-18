import dns.resolver
import sys
import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import pyfiglet
import time
import signal

# Initialize colorama
init(autoreset=True)

# Define colors
RED = Fore.RED
GREEN = Fore.GREEN
BLUE = Fore.LIGHTBLUE_EX
YELLOW = Fore.LIGHTYELLOW_EX
WHITE = Fore.WHITE

# Global flag to track requested to stop
stop_requested = False

def banner():
    """Displays the banner"""
    figlet_text = pyfiglet.Figlet(font="slant").renderText("CloudRip")
    print(BLUE + figlet_text)
    print(RED + "CloudFlare Bypasser - Find Real IP Addresses Behind Cloudflare")

def resolve_subdomain(subdomain, domain):
    """Attempts to resolve a subdomain."""
    # Properly format domain
    full_domain = f"{subdomain}.{domain}" if subdomain else domain

    try:
        # Use dns.resolver to resolve the subdomain
        answers = dns.resolver.resolve(full_domain, "A")
        for rdata in answers:
            ip = rdata.address
            # Check if IP belongs to Cloudflare
            if not is_cloudflare_ip(ip):
                print(GREEN + f"[FOUND] {full_domain} -> {ip}")
                return full_domain, ip
    except dns.resolver.NXDOMAIN:
        print(RED + f"[NOT FOUND] {full_domain}")
    except dns.resolver.NoAnswer:
        print(YELLOW + f"[NO ANSWER] {full_domain}")
    except dns.resolver.NoNameservers:
        print(YELLOW + f"[NO NAMESERVERS] {full_domain}")
    except dns.resolver.Timeout:
        print(YELLOW + f"[TIMEOUT] {full_domain}")
    except Exception as e:
        print(YELLOW + f"[ERROR] {full_domain}: {str(e)}")
    return None

def is_cloudflare_ip(ip):
    """Check if the IP belongs to Cloudflare's known IP ranges."""
    cloudflare_ip_ranges = [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", 
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"
    ]
    from ipaddress import ip_address, ip_network
    ip_addr = ip_address(ip)
    return any(ip_addr in ip_network(cidr) for cidr in cloudflare_ip_ranges)

def load_wordlist(wordlist_path):
    """Loads the wordlist from a file."""
    if os.path.exists(wordlist_path):
        with open(wordlist_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    else:
        print(RED + f"[ERROR] Wordlist file not found: {wordlist_path}")
        sys.exit(1)

def save_results_to_file(results, output_file):
    """Saves the results to a specified file."""
    try:
        with open(output_file, "w") as file:
            for subdomain, ip in results.items():
                file.write(f"{subdomain} -> {ip}\n")
        print(GREEN + f"[INFO] Results saved to {output_file}")
    except Exception as e:
        print(RED + f"[ERROR] Failed to save results: {str(e)}")

def signal_handler(sig, frame):
    """Handles SIGINT (Ctrl+C) to prompt whether to quit."""
    global stop_requested
    if stop_requested:
        print(RED + "\n[INFO] Force quitting...")
        sys.exit(0)
    print(RED + "\n[INFO] Ctrl+C detected. Do you want to quit? (y/n): ", end="")
    choice = input().strip().lower()
    if choice == 'y':
        stop_requested = True
    else:
        print(YELLOW + "[INFO] Resuming...")

def main():
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Parse arguments
    parser = argparse.ArgumentParser(description="CloudRip - CloudFlare Bypasser")
    parser.add_argument("domain", help="The domain to resolve (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", default="dom.txt", help="Path to the wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for concurrent scanning")
    parser.add_argument("-o", "--output", help="Save the results to a file (optional)")
    args = parser.parse_args()

    # Display banner
    banner()

    # Load wordlist
    subdomains = load_wordlist(args.wordlist)
    print(YELLOW + f"[INFO] Loaded {len(subdomains)} subdomains from {args.wordlist}")

    # Start resolving subdomains concurrently
    print(YELLOW + "[INFO] Starting subdomain resolution...")
    found_results = {}
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(resolve_subdomain, subdomain, args.domain): subdomain for subdomain in subdomains}
        for future in as_completed(futures):
            if stop_requested:
                print(RED + "[INFO] Operation was interrupted.")
                break
            result = future.result()
            if result:
                subdomain, ip = result
                found_results[subdomain] = ip
                time.sleep(0.1)  # Add rate limiting

    # Save results if output file is specified
    if args.output:
        save_results_to_file(found_results, args.output)

    print(WHITE + "The operation has completed successfully.")

if __name__ == "__main__":
    main()
