from flask import Flask, render_template, request, jsonify, send_file, Response
import pandas as pd
import asyncio
import aiohttp
from urllib.parse import urlparse
import socket
from concurrent.futures import ThreadPoolExecutor
import time
from crt_checker import process_domain, query_crtsh
import json
import sys
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
import uuid
import atexit
from io import BytesIO
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os
import subprocess
import tempfile

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Store results globally (you might want to use a proper database in production)
current_results = []

# Initialize scheduler with SQLite job store
jobstores = {
    'default': SQLAlchemyJobStore(url='sqlite:///jobs.sqlite')
}
scheduler = BackgroundScheduler(jobstores=jobstores)
scheduler.start()

# Add this at the top of your file, after imports
scan_progress = {}

def is_valid_domain(domain):
    """Quick check if domain might be valid without making HTTP request"""
    try:
        # Remove any protocol and path components
        domain = domain.strip().lower()
        if '://' in domain:
            domain = urlparse(domain).netloc
        elif '/' in domain:
            domain = domain.split('/')[0]
            
        # Try to resolve the domain
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, UnicodeError):
        return False

async def validate_domains_async(domains):
    """Validate multiple domains concurrently"""
    async def check_domain(domain):
        try:
            if not is_valid_domain(domain):
                return None
            return domain
        except Exception:
            return None

    async with aiohttp.ClientSession() as session:
        tasks = [check_domain(domain) for domain in domains]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

@app.route('/')
def index():
    return render_template('index.html')

def perform_certificate_scan(domains, name=None, job_id=None):
    """Perform the actual certificate scanning"""
    try:
        print(f"Starting scan job: {job_id} for {name}")
        print(f"Found {len(domains)} domains to process")
        
        current_results = []
        total_domains = len(domains)
        processed = 0
        
        for domain in domains:
            try:
                print(f"Processing domain: {domain}", flush=True)
                domain_results = process_domain(domain)
                print(f"Raw results for {domain}: {len(domain_results)} certificates")  # Debug log
                
                # Convert results to the format expected by the frontend
                formatted_results = []
                for result in domain_results:
                    try:
                        # Parse the expiry information
                        days_text = result['Time Until Expiry']
                        if 'Expired' in days_text:
                            days_remaining = -int(days_text.split()[1])
                            expired = True
                            expiring = False
                        else:
                            days_remaining = int(days_text.split()[2])
                            expired = False
                            expiring = days_remaining <= 90
                        
                        formatted_result = {
                            'domain': result['Domain'],
                            'issuer': result['Issuer'],
                            'valid_from': result['Valid From'],
                            'valid_until': result['Expiration Date'],
                            'days_remaining': days_remaining,
                            'expired': expired,
                            'expiring': expiring,
                            'valid': not (expired or expiring)
                        }
                        formatted_results.append(formatted_result)
                        print(f"Formatted result: {formatted_result}")  # Debug log
                        
                    except Exception as e:
                        print(f"Error formatting individual result: {str(e)}")
                        print(f"Problematic result: {result}")
                        continue
                
                if formatted_results:
                    current_results.extend(formatted_results)
                    print(f"Total results so far: {len(current_results)}")  # Debug log
                
                processed += 1
                
                # Update progress with current results
                if job_id and job_id in scan_progress:
                    progress_data = {
                        'progress': (processed / total_domains) * 100,
                        'processed': processed,
                        'total': total_domains,
                        'current_domain': domain,
                        'results': current_results,  # Include all results in progress updates
                        'complete': False
                    }
                    print(f"Sending progress update with {len(current_results)} results")  # Debug log
                    scan_progress[job_id].update(progress_data)
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Error processing domain {domain}: {str(e)}", flush=True)
                continue
        
        print(f"Scan complete. Total results: {len(current_results)}")
        
        # Send final update with all results
        if job_id in scan_progress:
            final_update = {
                'progress': 100,
                'processed': total_domains,
                'total': total_domains,
                'current_domain': 'Complete',
                'results': current_results,
                'complete': True
            }
            print(f"Sending final update with {len(current_results)} results")  # Debug log
            scan_progress[job_id].update(final_update)
            time.sleep(2)  # Give time for final update to be sent
        
        return current_results
        
    except Exception as e:
        print(f"Error in scan handler: {str(e)}", flush=True)
        if job_id and job_id in scan_progress:
            del scan_progress[scan_id]
        return None

@app.route('/check_certificates', methods=['POST'])
def check_certificates(domains=None, name=None):
    """Route handler for certificate checking"""
    print("\n=== Starting Certificate Check ===", flush=True)
    
    if request.method == 'GET':
        return jsonify({'error': 'POST method required'}), 405
    
    try:
        # Log request details
        print("Request form data:", request.form, flush=True)
        print("Request files:", request.files, flush=True)
        
        # If domains weren't passed (regular file upload)
        if domains is None:
            if 'file' not in request.files:
                # Check if we have form data instead
                data = request.form.get('domains')
                print("Form data domains:", data, flush=True)
                if data:
                    domains = [d.strip() for d in data.split('\n') if d.strip()]
                else:
                    print("No domains provided in request", flush=True)
                    return jsonify({'error': 'No domains provided'}), 400
            else:
                file = request.files['file']
                if file.filename == '':
                    return jsonify({'error': 'No file selected'}), 400
                domains = [line.decode('utf-8').strip() for line in file.readlines() if line.strip()]

        print(f"\nProcessing {len(domains)} domains: {domains}", flush=True)
        
        def generate():
            scan_id = str(uuid.uuid4())
            print(f"\nStarting scan {scan_id}", flush=True)
            
            all_results = []
            total = len(domains)
            
            for idx, domain in enumerate(domains, 1):
                try:
                    print(f"\nProcessing domain {idx}/{total}: {domain}", flush=True)
                    results = process_domain(domain)
                    print(f"Got {len(results)} certificates for {domain}", flush=True)
                    
                    if results:
                        all_results.extend(results)
                    
                    # Send progress update
                    progress = (idx / total) * 100
                    data = {
                        'progress': progress,
                        'current_domain': domain,
                        'processed': idx,
                        'total': total,
                        'results': all_results,
                        'complete': False
                    }
                    print(f"Sending progress update: {progress}%", flush=True)
                    yield 'data: ' + json.dumps(data) + '\n\n'
                    
                except Exception as e:
                    print(f"Error processing {domain}: {str(e)}", flush=True)
                    continue
            
            # Send final update
            print(f"\n=== Scan Complete ===", flush=True)
            print(f"Total certificates found: {len(all_results)}", flush=True)
            print("Certificate breakdown:", flush=True)
            valid_certs = sum(1 for cert in all_results if not cert.get('expired') and not cert.get('expiring'))
            expiring_certs = sum(1 for cert in all_results if cert.get('expiring'))
            expired_certs = sum(1 for cert in all_results if cert.get('expired'))
            print(f"- Valid: {valid_certs}", flush=True)
            print(f"- Expiring Soon: {expiring_certs}", flush=True)
            print(f"- Expired: {expired_certs}", flush=True)
            
            final_data = {
                'progress': 100,
                'current_domain': 'Complete',
                'processed': total,
                'total': total,
                'results': all_results,
                'complete': True
            }
            yield 'data: ' + json.dumps(final_data) + '\n\n'
    
        return Response(generate(), mimetype='text/event-stream')
        
    except Exception as e:
        print(f"Error in route handler: {str(e)}", flush=True)
        return jsonify({'error': str(e)}), 500

@app.route('/export_results')
def export_results():
    global current_results
    
    if not current_results:
        return jsonify({'error': 'No results to export'}), 400
    
    # Create DataFrame from results
    df = pd.DataFrame(current_results)
    
    # Create temporary file
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, 'certificate_results.xlsx')
    
    # Save to Excel
    df.to_excel(temp_path, index=False)
    
    return send_file(
        temp_path,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='certificate_results.xlsx'
    )

@app.route('/schedule_scan', methods=['POST'])
def schedule_scan():
    try:
        data = request.get_json()
        name = data.get('name')
        domains = data.get('domains', [])
        frequency = data.get('frequency')
        time_str = data.get('time')
        
        if not all([name, domains, frequency, time_str]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
            
        # Parse time
        hour, minute = map(int, time_str.split(':'))
        
        # Create a unique job ID using timestamp
        job_id = f"scan_{name}_{int(time.time())}"
        
        # Initialize progress tracking
        scan_progress[job_id] = {
            'progress': 0,
            'processed': 0,
            'total': len(domains),
            'current_domain': 'Not started',
            'name': name
        }
        
        # Add job to scheduler
        job = scheduler.add_job(
            func=perform_certificate_scan,
            trigger='cron',
            hour=hour,
            minute=minute,
            id=job_id,
            kwargs={
                'domains': domains,
                'name': name,
                'job_id': job_id
            }
        )
        
        return jsonify({
            'success': True,
            'job_id': job_id
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/scheduled_tasks', methods=['GET'])
def get_scheduled_tasks():
    jobs = scheduler.get_jobs()
    tasks = []
    
    for job in jobs:
        tasks.append({
            'id': job.id,
            'name': job.kwargs.get('name', 'Unnamed'),
            'frequency': str(job.trigger),  # Convert trigger to string instead of accessing expression
            'time': f"{job.trigger.fields[3]}:{job.trigger.fields[4]}" if hasattr(job.trigger, 'fields') else 'N/A',
            'next_run': job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else 'N/A'
        })
    
    return jsonify({'success': True, 'tasks': tasks})

@app.route('/scheduled_task/<task_id>', methods=['DELETE'])
def delete_scheduled_task(task_id):
    try:
        scheduler.remove_job(task_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def run_scheduled_scan(name):
    # Implement the actual scan logic here
    print(f"Running scheduled scan: {name}")
    # You'll need to implement the actual scan functionality
    pass

# Make sure to stop the scheduler when the app stops
@atexit.register
def shutdown():
    scheduler.shutdown()

@app.route('/export_excel', methods=['POST'])
def export_excel():
    try:
        data = request.json['data']
        filename = request.json['filename']
        
        # Create Excel file in memory
        output = BytesIO()
        
        # Create DataFrame and write to Excel
        df = pd.DataFrame(data)
        df.to_excel(output, index=False)
        
        # Seek to beginning of file
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    
    except Exception as e:
        print(f"Error in export_excel: {str(e)}")  # Add debugging
        return jsonify({'error': str(e)}), 500

@app.route('/scan_progress/<scan_id>')
def get_scan_progress(scan_id):
    def generate():
        while scan_id in scan_progress:
            progress_data = scan_progress[scan_id]
            print(f"Sending progress update for {scan_id}: {progress_data}")  # Debug log
            yield f"data: {json.dumps(progress_data)}\n\n"
            time.sleep(1)
            
            # If scan is complete, break after sending final update
            if progress_data.get('complete', False):
                print(f"Scan {scan_id} complete, breaking loop")
                break
            
        # Send final completion message if no results were found
        if scan_id not in scan_progress:
            final_message = {'complete': True, 'results': []}
            print(f"Sending final message for {scan_id}: {final_message}")  # Debug log
            yield f"data: {json.dumps(final_message)}\n\n"
            
    return Response(generate(), mimetype='text/event-stream')

def create_session():
    """Create a requests session with retry logic"""
    session = requests.Session()
    
    # Configure retry strategy
    retries = Retry(
        total=3,  # number of retries
        backoff_factor=1,  # wait 1, 2, 4 seconds between retries
        status_forcelist=[429, 500, 502, 503, 504],  # retry on these status codes
    )
    
    # Add retry strategy to the session
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    return session

@app.route('/test_domain/<domain>')
def test_domain(domain):
    """Test route to check certificate processing for a single domain"""
    try:
        results = process_domain(domain)
        return jsonify({
            'domain': domain,
            'results_count': len(results),
            'results': results
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'domain': domain
        })

@app.route('/scan_certificates', methods=['POST'])
def scan_certificates():
    try:
        print("\n=== Starting Certificate Scan ===", flush=True)
        print("Request method:", request.method, flush=True)
        print("Request form:", request.form, flush=True)
        
        # Create temporary file for targets
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'targets.txt')
        
        # Get targets from request
        targets = request.form.get('targets', '')
        if not targets:
            return jsonify({'error': 'No targets provided'}), 400
            
        with open(temp_path, 'w') as f:
            f.write(targets)
        
        def generate():
            try:
                # Count total targets
                with open(temp_path, 'r') as f:
                    total_targets = sum(1 for line in f if line.strip())
                
                scanner_path = './cert_scanner'
                if not os.path.exists(scanner_path):
                    error_msg = f"Scanner not found at {scanner_path}"
                    yield f'data: {{"error": "{error_msg}"}}\n\n'
                    return
                
                process = subprocess.Popen(
                    [scanner_path, temp_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=1,
                    universal_newlines=True
                )
                
                processed = 0
                for line in process.stdout:
                    try:
                        result = json.loads(line)
                        processed += 1
                        
                        update = {
                            'progress': (processed / total_targets) * 100,
                            'processed': processed,
                            'total': total_targets,
                            'results': [result],
                            'complete': False
                        }
                        yield f'data: {json.dumps(update)}\n\n'
                        
                    except json.JSONDecodeError as e:
                        print(f"Error parsing scanner output: {e}", flush=True)
                        continue
                
                yield f'data: {{"progress": 100, "processed": {total_targets}, "total": {total_targets}, "complete": true}}\n\n'
                
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        
        return Response(generate(), mimetype='text/event-stream')
        
    except Exception as e:
        print(f"Error in scan_certificates: {str(e)}", flush=True)
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 