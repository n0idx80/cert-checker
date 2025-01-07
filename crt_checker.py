import requests
import json
from datetime import datetime, timedelta
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import argparse

# Function to query crt.sh for a domain
def query_crtsh(domain):
    print(f"Starting crt.sh query for {domain}...", flush=True)
    url = f"https://crt.sh/?q={domain}&output=json"
    
    try:
        response = requests.get(url, timeout=10)  # Add timeout
        response.raise_for_status()
        print(f"Successfully queried crt.sh for {domain}", flush=True)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error querying crt.sh for {domain}: {str(e)}", flush=True)
        return []

# Function to process a single domain
def process_domain(domain):
    current_date = datetime.utcnow()
    print(f"Checking {domain}...")
    results = []
    certs = query_crtsh(domain)
    
    for cert in certs:
        not_before = datetime.strptime(cert['not_before'], '%Y-%m-%dT%H:%M:%S')
        not_after = datetime.strptime(cert['not_after'], '%Y-%m-%dT%H:%M:%S')
        
        # Calculate days until expiration (negative if expired)
        days_until_expiry = (not_after - current_date).days
        
        # Check if certificate is currently valid (not before current date)
        is_not_before_valid = not_before <= current_date
        
        # Determine status based on expiry and validity period
        if not is_not_before_valid:
            status = "Not Yet Valid"
            days_status = f"Becomes valid in {(not_before - current_date).days} days"
        elif days_until_expiry < 0:
            status = "Expired"
            days_status = f"Expired {abs(days_until_expiry)} days ago"
        elif days_until_expiry <= 90:
            status = "Expiring Soon"
            days_status = f"Expires in {days_until_expiry} days"
        else:
            status = "Valid"
            days_status = f"Expires in {days_until_expiry} days"

        results.append({
            'Domain': cert['name_value'],
            'Issuer': cert['issuer_name'],
            'Status': status,
            'Time Until Expiry': days_status,
            'Expiration Date': not_after.strftime('%Y-%m-%d'),
            'Valid From': not_before.strftime('%Y-%m-%d')
        })
    
    return results

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='''
Certificate Expiration Checker
-----------------------------
Checks SSL/TLS certificates for expiration dates and generates a report.
Identifies certificates that are expired or will expire within 90 days.
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Basic usage (both arguments are required)
    python crt_checker.py -i domains.txt -o report.xlsx

    # Using long-form arguments
    python crt_checker.py --input domains.txt --output report.xlsx
        '''
    )
    
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Input file containing list of domains (one domain per line)'
    )
    
    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output Excel file for the expiration report'
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='Certificate Checker v1.0.0'
    )

    return parser.parse_args()

def main():
    start_time = time.time()
    args = parse_arguments()
    
    print(f"Starting certificate check at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Read domains from the specified file
    with open(args.input, 'r') as file:
        domains = [line.strip() for line in file]
    print(f"Loaded {len(domains)} domains to check")

    # Process domains in parallel
    all_results = []
    processed_domains = 0
    domains_with_findings = 0
    max_workers = min(32, len(domains))
    print(f"Processing with {max_workers} parallel threads...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(process_domain, domain): domain for domain in domains}
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            processed_domains += 1
            try:
                domain_results = future.result()
                if domain_results:
                    domains_with_findings += 1
                    all_results.extend(domain_results)
                print(f"Progress: {processed_domains}/{len(domains)} domains processed", end='\r')
            except Exception as e:
                print(f"\nError processing {domain}: {str(e)}")

    print(f"\nProcessing complete!")
    print(f"Total domains processed: {processed_domains}")
    print(f"Domains with findings: {domains_with_findings}")
    print(f"Total certificates flagged: {len(all_results)}")

    # Save the results to the specified Excel file
    if all_results:
        df = pd.DataFrame(all_results)
        df.to_excel(args.output, index=False)
        print(f"Results saved to {args.output}")
    else:
        print("No expired or soon-to-expire certificates found.")

    end_time = time.time()
    duration = end_time - start_time
    print(f"\nTotal execution time: {duration:.2f} seconds")
    print(f"Average time per domain: {(duration/len(domains)):.2f} seconds")
    print(f"Finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()

