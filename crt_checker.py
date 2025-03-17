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
from urllib.parse import urlparse, urlunparse
import re
from openai import OpenAI  # or import your preferred LLM client
import os

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
    print(f"\n=== Starting crt.sh query for {domain} ===", flush=True)
    url = f"https://crt.sh/?q={domain}&output=json"
    
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    session.mount('https://', HTTPAdapter(max_retries=retries))
    
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        certs = response.json()
        print(f"Raw response from crt.sh:", flush=True)
        print(json.dumps(certs[0], indent=2), flush=True)  # Print first certificate as example
        return certs
    except Exception as e:
        print(f"Error querying crt.sh: {str(e)}", flush=True)
        return get_cert_direct(domain)

def process_domain(domain):
    current_date = datetime.utcnow()
    print(f"\nChecking {domain}...", flush=True)
    results = []
    
    try:
        certs = query_crtsh(domain)
        print(f"Processing {len(certs)} certificates for {domain}", flush=True)
        
        valid_count = 0
        expiring_count = 0
        expired_count = 0
        
        for cert in certs:
            try:
                # Debug: Print raw date strings
                print("\nRaw certificate dates:", flush=True)
                print(f"not_before: {cert.get('not_before')}", flush=True)
                print(f"not_after: {cert.get('not_after')}", flush=True)
                
                # Parse dates from certificate
                not_before = datetime.strptime(cert['not_before'], '%Y-%m-%dT%H:%M:%S')
                not_after = datetime.strptime(cert['not_after'], '%Y-%m-%dT%H:%M:%S')
                
                # Calculate days until expiration
                days_until_expiry = (not_after - current_date).days
                print(f"Days until expiry: {days_until_expiry}", flush=True)
                
                # Determine certificate status
                expired = days_until_expiry < 0
                expiring = not expired and days_until_expiry <= 90
                valid = not expired and not expiring
                
                print("Status determination:", flush=True)
                print(f"- Days remaining: {days_until_expiry}", flush=True)
                print(f"- Expired: {expired} (days < 0)", flush=True)
                print(f"- Expiring soon: {expiring} (not expired and days <= 90)", flush=True)
                print(f"- Valid: {valid} (not expired and not expiring)", flush=True)
                
                # Update counters
                if expired:
                    expired_count += 1
                elif expiring:
                    expiring_count += 1
                else:
                    valid_count += 1
                
                result = {
                    'domain': domain,
                    'issuer': cert.get('issuer_name', 'Unknown'),
                    'valid_from': not_before.strftime('%Y-%m-%d'),
                    'valid_until': not_after.strftime('%Y-%m-%d'),
                    'days_remaining': days_until_expiry,
                    'expired': expired,
                    'expiring': expiring,
                    'valid': valid
                }
                
                results.append(result)
                
            except Exception as e:
                print(f"Error processing certificate: {str(e)}", flush=True)
                continue
        
        print(f"\n=== Final Certificate Counts for {domain} ===", flush=True)
        print(f"Total certificates: {len(results)}", flush=True)
        print(f"Valid (>90 days): {valid_count}", flush=True)
        print(f"Expiring Soon (≤90 days): {expiring_count}", flush=True)
        print(f"Expired: {expired_count}", flush=True)
        
        return results
        
    except Exception as e:
        print(f"Error processing domain: {str(e)}", flush=True)
        return []

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

def normalize_url(url):
    """Normalize URLs to a consistent format"""
    try:
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Parse URL
        parsed = urlparse(url)
        
        # Clean up the netloc (domain)
        netloc = parsed.netloc.lower().strip()
        # Remove extra colons and port numbers if standard
        if ':' in netloc:
            domain, port = netloc.split(':')
            if (parsed.scheme == 'https' and port == '443') or \
               (parsed.scheme == 'http' and port == '80'):
                netloc = domain
                
        # Remove www. if present
        if netloc.startswith('www.'):
            netloc = netloc[4:]
            
        # Remove trailing dots
        netloc = netloc.rstrip('.')
        
        # Rebuild URL with only scheme and netloc
        normalized = urlunparse((
            parsed.scheme,
            netloc,
            '', '', '', ''  # Path, params, query, and fragment are removed
        ))
        
        return normalized.rstrip('/')
        
    except Exception as e:
        print(f"Error normalizing URL {url}: {str(e)}")
        return None

def check_certificate_status(cert_info):
    """Check certificate validity and expiration status"""
    try:
        current_date = datetime.utcnow()
        not_after = datetime.strptime(cert_info['not_after'], '%Y-%m-%dT%H:%M:%S')
        days_until_expiry = (not_after - current_date).days
        
        # Standardize status values
        if days_until_expiry < 0:
            status = 'expired'
        elif days_until_expiry <= 90:
            status = 'expiring_soon'
        else:
            status = 'valid'
            
        return {
            'status': status,  # Using standardized lowercase status
            'days_until_expiry': days_until_expiry,
            'expiry_date': not_after.strftime('%Y-%m-%d'),
            'issuer': cert_info['issuer_name']
        }
    except Exception as e:
        return {
            'status': 'invalid',
            'error': str(e)
        }

def validate_url_connection(url, timeout=5):
    """Test if URL is accessible and validate its certificate"""
    try:
        # Suppress insecure request warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        print(f"\nChecking: {url}")
        response = requests.head(url, 
                               timeout=timeout, 
                               allow_redirects=True, 
                               verify=False)
        
        if response.status_code == 200:
            print(f"✓ Connection successful")
            
            # Get and validate certificate
            try:
                domain = urlparse(url).netloc
                cert_info = get_cert_direct(domain)
                if cert_info:
                    cert_status = check_certificate_status(cert_info[0])
                    print(f"Certificate Info:")
                    print(f"  Status: {cert_status['status'].upper()}")
                    print(f"  Expiry: {cert_status.get('expiry_date')} ({cert_status.get('days_until_expiry')} days)")
                    print(f"  Issuer: {cert_status.get('issuer', 'Unknown')}")
                    return True, cert_status
                else:
                    print("✗ No certificate found")
                    return False, {'status': 'invalid', 'error': 'No certificate found'}
            except Exception as e:
                print(f"✗ Certificate validation error: {str(e)}")
                return False, {'status': 'invalid', 'error': str(e)}
        else:
            print(f"✗ Connection failed (HTTP {response.status_code})")
            return False, {'status': 'invalid', 'error': f'HTTP {response.status_code}'}
            
    except requests.exceptions.RequestException as e:
        print(f"✗ Connection error: {str(e)}")
        return False, {'status': 'invalid', 'error': str(e)}

def normalize_url_with_llm(url):
    """Use LLM to intelligently normalize URLs"""
    try:
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment")
            
        client = OpenAI(api_key=api_key)
        
        prompt = f"""
        Analyze this URL and return the normalized version that would reach the main domain:
        URL: {url}
        
        Rules:
        1. Remove unnecessary parts (utm params, fragments, etc)
        2. Fix common typos or formatting issues
        3. Ensure proper protocol (https://)
        4. Remove unnecessary subdomains
        5. Return only the base domain if it's clearly a subpage
        
        Return only the normalized URL, nothing else.
        """
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        
        normalized_url = response.choices[0].message.content.strip()
        if normalized_url != url:
            print(f"Normalized: {url} → {normalized_url}")
        
        # Validate the normalized URL
        success, cert_status = validate_url_connection(normalized_url)
        if success:
            return normalized_url
        return None
            
    except Exception as e:
        print(f"Error normalizing URL with LLM: {str(e)}")
        return None

def get_cert_domain_key(url):
    """Get the key for certificate checking, preserving relevant paths and subdomains"""
    try:
        parsed = urlparse(url)
        # Split domain into parts
        domain_parts = parsed.netloc.split('.')
        
        # If it's a subdomain, keep it
        if len(domain_parts) > 2:
            base_domain = '.'.join(domain_parts[-2:])
            subdomain = '.'.join(domain_parts[:-2])
            cert_key = f"{subdomain}.{base_domain}"
        else:
            cert_key = parsed.netloc
            
        # If there's a path that might indicate a different service, include it
        if parsed.path and len(parsed.path) > 1:
            cert_key = f"{cert_key}{parsed.path}"
            
        return cert_key.lower()
    except Exception as e:
        print(f"Error getting cert domain key: {str(e)}")
        return url.lower()

def process_url_list(urls):
    """Process a list of URLs and check their certificates"""
    results = []
    processed_urls = {}  # Track normalized URLs by their cert domain key
    
    print(f"\nProcessing {len(urls)} URLs...")
    for i, url in enumerate(urls):
        url = url.strip()
        if not url:
            continue
            
        print(f"\n{'='*50}")
        print(f"Processing [{i+1}/{len(urls)}]: {url}")
        
        # First try LLM normalization
        normalized = normalize_url_with_llm(url)
        if not normalized:
            print("Falling back to basic normalization...")
            normalized = normalize_url(url)
        
        if not normalized:
            print(f"✗ Could not normalize URL: {url}")
            result = {
                'url': url,
                'status': 'invalid',
                'cert_info': {'status': 'invalid', 'error': 'URL normalization failed'},
                'error': 'URL normalization failed'
            }
        else:
            # Get the certificate domain key
            cert_key = get_cert_domain_key(normalized)
            
            # Check if we've already processed this exact cert domain
            if cert_key in processed_urls:
                base_url = processed_urls[cert_key]
                print(f"⚠ Similar URL already processed: {url} → {normalized}")
                print(f"  Previously checked as: {base_url}")
                
                # If it's not exactly the same URL, check it anyway
                if normalized != base_url:
                    print("  Checking for different certificate...")
                    success, cert_status = validate_url_connection(normalized)
                    if cert_status != processed_urls.get(f"{base_url}_cert"):
                        print("  Found different certificate, processing...")
                    else:
                        print("  Same certificate found, skipping...")
                        continue
                else:
                    continue
                
            processed_urls[cert_key] = normalized
            print(f"✓ Normalized: {url} → {normalized}")
            
            # Now check the certificate
            success, cert_status = validate_url_connection(normalized)
            processed_urls[f"{normalized}_cert"] = cert_status
            result = {
                'url': url,
                'normalized_url': normalized,
                'status': cert_status['status'],
                'cert_info': cert_status
            }
        
        results.append(result)
        print(f"Yielding update for {url} with {len(results)} total results")
        
        yield {
            'progress': ((i + 1) / len(urls)) * 100,
            'current_url': url,
            'results': results,
            'total_processed': i + 1,
            'total_urls': len(urls),
            'stats': {
                'valid': sum(1 for r in results if r['status'] == 'valid'),
                'expiring_soon': sum(1 for r in results if r['status'] == 'expiring_soon'),
                'expired': sum(1 for r in results if r['status'] == 'expired'),
                'invalid': sum(1 for r in results if r['status'] == 'invalid')
            }
        }
        
        print(f"{'='*50}")
    
    print(f"\nProcessing complete:")
    print(f"- Total URLs: {len(urls)}")
    print(f"- Unique normalized URLs: {len(processed_urls)}")
    print(f"- Results: {len(results)}")

if __name__ == "__main__":
    main()

