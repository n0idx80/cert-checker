import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime, timedelta
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import argparse
import json
import socket
import ssl
import OpenSSL.crypto as crypto

def get_cert_direct(domain, port=443):
    """Directly get certificate from domain"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
                
                # Extract certificate information
                issuer = dict(cert.get_issuer().get_components())
                not_before = datetime.strptime(cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ')
                not_after = datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
                
                return [{
                    'issuer_name': issuer.get(b'O', b'Unknown').decode(),
                    'not_before': not_before.strftime('%Y-%m-%dT%H:%M:%S'),
                    'not_after': not_after.strftime('%Y-%m-%dT%H:%M:%S')
                }]
    except Exception as e:
        print(f"Error getting direct certificate for {domain}: {str(e)}")
        return []

def query_crtsh(domain):
    print(f"Starting crt.sh query for {domain}...", flush=True)
    url = f"https://crt.sh/?q={domain}&output=json"
    
    # Create session with retry logic
    session = requests.Session()
    retries = Retry(
        total=5,  # increased retries
        backoff_factor=1,  # wait 1, 2, 4, 8, 16 seconds between retries
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    session.mount('https://', HTTPAdapter(max_retries=retries))
    
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        print(f"Successfully queried crt.sh for {domain}", flush=True)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error querying crt.sh for {domain}: {str(e)}")
        print(f"Falling back to direct certificate check for {domain}")
        return get_cert_direct(domain)
    finally:
        session.close()

def process_domain(domain):
    current_date = datetime.utcnow()
    print(f"Checking {domain}...")
    results = []
    certs = query_crtsh(domain)
    
    for cert in certs:
        try:
            not_before = datetime.strptime(cert['not_before'], '%Y-%m-%dT%H:%M:%S')
            not_after = datetime.strptime(cert['not_after'], '%Y-%m-%dT%H:%M:%S')
            
            # Calculate days until expiration (negative if expired)
            days_until_expiry = (not_after - current_date).days
            
            # Determine status
            expired = days_until_expiry < 0
            expiring = not expired and days_until_expiry <= 90
            
            result = {
                'domain': domain,
                'issuer': cert.get('issuer_name', 'Unknown'),
                'valid_from': not_before.strftime('%Y-%m-%d'),
                'valid_until': not_after.strftime('%Y-%m-%d'),
                'days_remaining': days_until_expiry,
                'expired': expired,
                'expiring': expiring
            }
            
            print(f"Processed cert for {domain}: {result}")  # Debug log
            results.append(result)
            
        except Exception as e:
            print(f"Error processing certificate for {domain}: {str(e)}")
            continue
    
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
        version='Certificate Checker v1.0.1'
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
        
        # Calculate summary statistics
        total_certs = len(df)
        status_counts = df['Status'].value_counts()
        valid_certs = status_counts.get('Valid', 0)
        expiring_soon = status_counts.get('Expiring Soon', 0)
        expired = status_counts.get('Expired', 0)
        not_yet_valid = status_counts.get('Not Yet Valid', 0)
        
        # Create summary data
        summary_data = [
            ['Certificate Scan Summary'],
            [f'Total Domains Scanned: {len(domains)}'],
            [f'Domains with Certificates: {domains_with_findings}'],
            [f'Total Certificates Found: {total_certs}'],
            [''],
            ['Certificate Status Breakdown:'],
            [f'Valid Certificates: {valid_certs}'],
            [f'Expiring Soon: {expiring_soon}'],
            [f'Expired: {expired}'],
            [f'Not Yet Valid: {not_yet_valid}'],
            [''],  # Empty row before the main data
        ]
        
        # Create a new Excel writer
        with pd.ExcelWriter(args.output, engine='openpyxl') as writer:
            # Write summary at the top
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, index=False, header=False, sheet_name='Sheet1')
            
            # Write main data below summary
            df.to_excel(writer, index=False, startrow=len(summary_data), sheet_name='Sheet1')
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

