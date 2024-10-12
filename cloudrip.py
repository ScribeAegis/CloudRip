import socket
import sys
import os
import argparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
import pyfiglet

# Initialize colorama
init(autoreset=True)

# Define colors
RED = Fore.RED
GREEN = Fore.GREEN
BLUE = Fore.LIGHTBLUE_EX
YELLOW = Fore.LIGHTYELLOW_EX
WHITE = Fore.WHITE

def banner():
    """Displays the banner"""
    figlet_text = pyfiglet.Figlet(font="slant").renderText("CloudRip")
    print(BLUE + figlet_text)
    print(RED + "CloudFlare Bypasser - Find Real IP Addresses Behind Cloudflare")

def resolve_subdomain(subdomain, domain):
    """Attempts to resolve a subdomain."""
    # Properly format the domain
    if subdomain:
        full_domain = f"{subdomain}.{domain}"
    else:
        full_domain = domain

    try:
        ip = socket.gethostbyname(full_domain)
        print(GREEN + f"[FOUND] {full_domain} -> {ip}")
        return full_domain, ip
    except socket.gaierror:
        # If the subdomain cannot be resolved, ignore the error
        print(RED + f"[NOT FOUND] {full_domain}")
        return None
    except Exception as e:
        print(YELLOW + f"[ERROR] {full_domain}: {str(e)}")
        return None

def load_wordlist(wordlist_path):
    """Loads the wordlist from a file."""
    if os.path.exists(wordlist_path):
        with open(wordlist_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    else:
        print(RED + f"[ERROR] Wordlist file not found: {wordlist_path}")
        sys.exit(1)

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="CloudRip - CloudFlare Bypasser")
    parser.add_argument("domain", help="The domain to resolve (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", default="dom.txt", help="Path to the wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for concurrent scanning")
    parser.add_argument("-o", "--output", help="Save the results to a file (optional)")
    args = parser.parse_args()

    # Display the banner
    banner()

    # Load wordlist
    subdomains = load_wordlist(args.wordlist)
    print(YELLOW + f"[INFO] Loaded {len(subdomains)} subdomains from {args.wordlist}")

    # Start resolving subdomains concurrently
    print(YELLOW + "[INFO] Starting subdomain resolution...")
    found_results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(resolve_subdomain, subdomain, args.domain) for subdomain in subdomains]
        for future in futures:
            result = future.result()
            if result:
                found_results.append(result)

    # Save results if output file is specified
    if args.output:
        try:
            with open(args.output, "w") as output_file:
                for subdomain, ip in found_results:
                    output_file.write(f"{subdomain} -> {ip}\n")
            print(GREEN + f"[INFO] Results saved to {args.output}")
        except Exception as e:
            print(RED + f"[ERROR] Failed to save results: {str(e)}")

    print(WHITE + "The operation has completed successfully :)")

if __name__ == "__main__":
    main()