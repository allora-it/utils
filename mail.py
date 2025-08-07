# Email Security Checker
# This script checks the SPF, DKIM, and DMARC records for a given domain.
#
# Installation:
# pip install checkdmarc dnspython termcolor
#
# Usage:
# python mail.py -d example.com
# python mail.py --domain example.com
# python mail.py  (interactive mode)

import dns.resolver
from termcolor import colored
import checkdmarc
import sys
import argparse

def print_header(text):
    """Prints a formatted header."""
    print("\n" + "="*50)
    print(colored(text.center(50), 'cyan', attrs=['bold']))
    print("="*50)

def print_status(label, status, message=""):
    """Prints a status line with colored output."""
    if status == "PASS":
        color = 'green'
    elif status == "WARN":
        color = 'yellow'
    else: # FAIL
        color = 'red'
    # The formatting for the status color was a bit off, let's fix it
    print(f"{label:<15} [{colored(status, color, attrs=['bold']):<18}] {message}")

def check_spf(domain, results):
    """Checks for an SPF record using the results from checkdmarc."""
    print_header("SPF (Sender Policy Framework) Check")
    spf_result = results.get('spf', {})
    if not spf_result or not spf_result.get('record'):
        print_status("SPF Record", "FAIL", "No SPF record found.")
        return

    if spf_result.get("valid"):
        print_status("SPF Record", "PASS", f"Found: {spf_result['record']}")
        if spf_result.get("warnings"):
            for warning in spf_result["warnings"]:
                print_status("SPF Warning", "WARN", warning)
    else:
        print_status("SPF Record", "FAIL", f"Invalid SPF record: {spf_result['record']}")
        if spf_result.get("errors"):
            for error in spf_result["errors"]:
                print_status("SPF Error", "FAIL", error)

def check_dkim(domain, selectors):
    """
    Checks for DKIM records using provided selectors.
    Note: A comprehensive DKIM check requires analyzing an email header.
    This function checks for provided selectors.
    """
    print_header("DKIM (DomainKeys Identified Mail) Check")
    found_selectors = []
    errors = []
    
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            dns.resolver.resolve(dkim_domain, 'TXT')
            found_selectors.append(selector)
        except dns.resolver.NXDOMAIN:
            continue
        except dns.resolver.NoAnswer:
            errors.append((selector, "Found DKIM record, but no TXT record"))
        except Exception as e:
            errors.append((selector, f"Error: {e}"))
    
    # Report results
    if found_selectors:
        for selector in found_selectors:
            print_status("DKIM Record", "PASS", f"Found a DKIM record with selector: '{selector}'")
    else:
        print_status("DKIM Record", "WARN", f"No DKIM records found for selectors: {', '.join(selectors)}")
        if errors:
            for selector, error in errors:
                print_status("DKIM Check", "FAIL", f"Selector '{selector}': {error}")


def check_dmarc(domain, results):
    """Checks for a DMARC record using the results from checkdmarc."""
    print_header("DMARC (Domain-based Message Authentication, Reporting & Conformance) Check")
    dmarc_result = results.get('dmarc', {})
    if not dmarc_result or not dmarc_result.get("record"):
        print_status("DMARC Record", "FAIL", "No DMARC record found.")
        return

    if dmarc_result.get("valid"):
        print_status("DMARC Record", "PASS", f"Found: {dmarc_result['record']}")
        policy = dmarc_result.get("tags", {}).get("p", {}).get("value")
        if policy == "none":
            print_status("DMARC Policy", "WARN", "Policy is 'none'. This allows for monitoring but doesn't block spoofing.")
        elif policy == "quarantine":
            print_status("DMARC Policy", "PASS", "Policy is 'quarantine'. Suspicious emails will be sent to spam.")
        elif policy == "reject":
            print_status("DMARC Policy", "PASS", "Policy is 'reject'. Suspicious emails will be blocked.")

        if dmarc_result.get("warnings"):
            for warning in dmarc_result["warnings"]:
                print_status("DMARC Warning", "WARN", warning)
    else:
        print_status("DMARC Record", "FAIL", f"Invalid DMARC record: {dmarc_result['record']}")
        if dmarc_result.get("errors"):
            for error in dmarc_result["errors"]:
                print_status("DMARC Error", "FAIL", error)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Email Security Checker - Checks SPF, DKIM, and DMARC records for a domain',
        epilog='Example: python mail.py -d example.com'
    )
    parser.add_argument('-d', '--domain', 
                        help='Domain to check (e.g., example.com)',
                        type=str)
    parser.add_argument('--dkim',
                        help='Comma-separated list of DKIM selectors to check (default: default,google)',
                        type=str,
                        default='default,google')
    
    args = parser.parse_args()
    
    if args.domain:
        domain_to_check = args.domain
    else:
        try:
            domain_to_check = input("Enter the domain to check (e.g., google.com): ")
        except EOFError:
            print("No domain provided. Use -d/--domain or enter interactively.")
            parser.print_help()
            sys.exit(1)
    
    if domain_to_check:
        print(f"\nChecking records for {domain_to_check}...")
        try:
            # Use individual check functions to avoid MTA-STS issues
            domain_results = {}
            
            # Check SPF
            try:
                spf_result = checkdmarc.check_spf(domain_to_check)
                domain_results['spf'] = spf_result
            except Exception as e:
                domain_results['spf'] = {'error': str(e)}
            
            # Check DMARC
            try:
                dmarc_result = checkdmarc.check_dmarc(domain_to_check)
                domain_results['dmarc'] = dmarc_result
            except Exception as e:
                domain_results['dmarc'] = {'error': str(e)}
            
            # Parse DKIM selectors
            dkim_selectors = [s.strip() for s in args.dkim.split(',') if s.strip()]
            
            check_spf(domain_to_check, domain_results)
            check_dkim(domain_to_check, dkim_selectors)
            check_dmarc(domain_to_check, domain_results)

        except Exception as e:
            print(colored(f"An unexpected error occurred: {e}", "red"))
            import traceback
            traceback.print_exc()

        print("\n" + "="*50)
        print(colored("Check Complete".center(50), 'cyan', attrs=['bold']))
        print("="*50)
    else:
        print("No domain entered. Exiting.")

