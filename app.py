print("Starting to import modules...")
from flask import Flask, render_template, jsonify, request
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
print("About to import from crt_checker...")
from crt_checker import process_domain
print("Finished importing from crt_checker...")

# Initialize Flask app
app = Flask(__name__)

# Initialize empty results dictionary
scan_results = {
    'results': [],
    'total_domains': 0,
    'domains_with_issues': 0,
    'last_scan': None
}

@app.route('/')
def index():
    return render_template('index.html', 
                         last_scan=scan_results['last_scan'],
                         has_results=len(scan_results['results']) > 0)

@app.route('/start-scan', methods=['POST'])
def start_scan():
    # Only run scan when POST request is made to /start-scan
    domains = request.form.get('domains').split('\n')
    domains = [domain.strip() for domain in domains if domain.strip()]
    
    if not domains:
        return jsonify({'error': 'No domains provided'}), 400
    
    results = []
    processed = 0
    total = len(domains)
    
    with ThreadPoolExecutor(max_workers=min(32, total)) as executor:
        future_to_domain = {executor.submit(process_domain, domain): domain for domain in domains}
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            processed += 1
            try:
                domain_results = future.result()
                if domain_results:
                    results.extend(domain_results)
            except Exception as e:
                results.append({
                    'Domain': domain,
                    'Status': 'Error',
                    'Error': str(e)
                })
    
    scan_results['results'] = results
    scan_results['total_domains'] = total
    scan_results['domains_with_issues'] = len(set(r['Domain'] for r in results))
    scan_results['last_scan'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    return jsonify(scan_results)

@app.route('/get-results')
def get_results():
    return jsonify(scan_results)

# Only run the Flask app when this file is run directly
if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(debug=True) 