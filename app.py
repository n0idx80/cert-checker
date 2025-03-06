from flask import Flask, render_template, request, jsonify, send_file, Response
import pandas as pd
import asyncio
import aiohttp
from urllib.parse import urlparse
import socket
from concurrent.futures import ThreadPoolExecutor
import time
from crt_checker import process_domain, query_crtsh, process_url_list
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
from werkzeug.utils import secure_filename

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
def check_certificates():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Read and normalize URLs
        urls = [line.decode('utf-8').strip() for line in file.readlines() if line.strip()]
        
        def generate():
            # Process URLs and stream results
            for update in process_url_list(urls):
                yield f"data: {json.dumps(update)}\n\n"
        
        return Response(generate(), mimetype='text/event-stream')
            
    except Exception as e:
        print(f"Error in main handler: {str(e)}")
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
    BATCH_SIZE = 200
    
    print("\n=== Starting Certificate Scan ===", flush=True)
    print(f"Time: {datetime.now()}", flush=True)
    
    # Store request data before entering generator
    file_data = None
    if 'file' in request.files:
        file_data = request.files['file'].read()
        print(f"Received file upload of size: {len(file_data)} bytes", flush=True)
    text_data = request.form.get('targets', '')
    input_type = request.form.get('type', 'ip')  # Get the input type, default to 'ip'
    
    print(f"Received input type: {input_type}", flush=True)
    print(f"Form data: {dict(request.form)}", flush=True)
    if 'file' in request.files:
        print("File received in request", flush=True)
    
    def generate():
        temp_path = None
        process = None
        start_time = time.time()
        batch_start_time = time.time()
        batch_count = 0
        total_certs = 0
        processed = 0
        current_batch = []
        last_progress_time = time.time()
        
        try:
            print("Creating temporary file...", flush=True)
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f'targets_{uuid.uuid4()}.txt')
            
            # Write the stored data to temp file
            with open(temp_path, 'wb' if file_data else 'w') as f:
                if file_data:
                    f.write(file_data)
                else:
                    f.write(text_data)
            
            print(f"Temporary file created: {temp_path}", flush=True)
            with open(temp_path, 'r') as f:
                content = f.read()
                print(f"File contents ({len(content.splitlines())} lines):", flush=True)
                print(content[:500] + ('...' if len(content) > 500 else ''), flush=True)
            
            # Count total targets
            with open(temp_path, 'r') as f:
                total_targets = sum(1 for line in f if line.strip())
            
            print(f"Found {total_targets} targets to process", flush=True)
            print("Starting scanner process...", flush=True)
            
            # Simplify the scanner command setup
            scanner_cmd = ['./cert_scanner', temp_path]

            print(f"Executing scanner command: {' '.join(scanner_cmd)}", flush=True)

            process = subprocess.Popen(
                scanner_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                universal_newlines=True
            )

            print("Scanner process started", flush=True)

            # Create a thread to read stderr without blocking
            def read_stderr():
                for line in process.stderr:
                    print(f"Scanner stderr: {line.strip()}", flush=True)

            import threading
            stderr_thread = threading.Thread(target=read_stderr)
            stderr_thread.daemon = True
            stderr_thread.start()

            # Continue with the main process output handling
            processed = 0
            current_batch = []
            last_progress_time = time.time()
            total_certs = 0
            
            for line in process.stdout:
                try:
                    current_time = time.time()
                    result = json.loads(line)
                    cert_count = 1 if result.get('has_cert', False) else 0
                    total_certs += cert_count
                    current_batch.append(result)
                    processed += 1
                    
                    # Print progress for every result
                    elapsed = current_time - start_time
                    rate = processed / elapsed if elapsed > 0 else 0
                    print(f"Progress: {processed}/{total_targets} ({processed/total_targets*100:.2f}%) - Rate: {rate:.2f} IPs/sec", flush=True)
                    
                    # Send batch when it reaches size or is last item
                    if len(current_batch) >= BATCH_SIZE or processed == total_targets:
                        batch_count += 1
                        batch_elapsed = time.time() - batch_start_time
                        
                        print(f"\nBatch {batch_count} Statistics:", flush=True)
                        print(f"- Batch size: {len(current_batch)} IPs", flush=True)
                        print(f"- Certificates found in batch: {cert_count}", flush=True)
                        print(f"- Total certificates so far: {total_certs}", flush=True)
                        print(f"- Batch processing time: {batch_elapsed:.2f} seconds", flush=True)
                        
                        progress = (processed / total_targets) * 100
                        update = {
                            'progress': progress,
                            'processed': processed,
                            'total': total_targets,
                            'total_certificates': total_certs,
                            'results': current_batch,
                            'complete': processed == total_targets
                        }
                        
                        try:
                            json_data = json.dumps(update)
                            # Split large updates into smaller chunks if needed
                            if len(json_data) > 1000000:  # If JSON is larger than ~1MB
                                # Send the update without the results first
                                status_update = {
                                    'progress': progress,
                                    'processed': processed,
                                    'total': total_targets,
                                    'total_certificates': total_certs,
                                    'results': [],
                                    'complete': False
                                }
                                yield f'data: {json.dumps(status_update)}\n\n'
                                
                                # Then send the results in smaller batches
                                chunk_size = 50  # Adjust this value as needed
                                for i in range(0, len(current_batch), chunk_size):
                                    chunk = current_batch[i:i + chunk_size]
                                    chunk_update = {
                                        'progress': progress,
                                        'processed': processed,
                                        'total': total_targets,
                                        'total_certificates': total_certs,
                                        'results': chunk,
                                        'complete': (processed == total_targets and i + chunk_size >= len(current_batch))
                                    }
                                    yield f'data: {json.dumps(chunk_update)}\n\n'
                            else:
                                # Send the complete update if it's small enough
                                yield f'data: {json_data}\n\n'
                        
                        except Exception as e:
                            print(f"Error serializing JSON update: {str(e)}", flush=True)
                            # Send minimal update without results
                            try:
                                minimal_update = {
                                    'progress': progress,
                                    'processed': processed,
                                    'total': total_targets,
                                    'total_certificates': total_certs,
                                    'results': [],
                                    'complete': processed == total_targets
                                }
                                yield f'data: {json.dumps(minimal_update)}\n\n'
                            except Exception as e2:
                                print(f"Error sending minimal update: {str(e2)}", flush=True)
                        
                        current_batch = []
                        batch_start_time = time.time()
                        
                except json.JSONDecodeError as e:
                    print(f"Error parsing scanner output: {e}", flush=True)
                    print(f"Problematic line: {line}", flush=True)
                    continue
                
            # Final statistics
            try:
                total_time = time.time() - start_time
                print(f"\n=== Scan Complete ===", flush=True)
                print(f"Total time: {total_time:.2f} seconds", flush=True)
                print(f"Total IPs/Domains processed: {processed}", flush=True)
                print(f"Total certificates found: {total_certs}", flush=True)
                
                # Add checks to prevent division by zero and invalid calculations
                if total_time > 0 and processed > 0:
                    print(f"Average rate: {processed/total_time:.2f} targets/sec", flush=True)
                    print(f"Average certificates per target: {total_certs/processed:.2f}", flush=True)
                else:
                    if processed == 0:
                        print("No targets were processed successfully", flush=True)
                    else:
                        print("Scan completed too quickly to measure rate", flush=True)
                    
            except Exception as e:
                print(f"Error calculating final statistics: {str(e)}", flush=True)
            
            # Send final update if there are remaining results
            if current_batch:
                final_update = {
                    'progress': 100,
                    'processed': processed,
                    'total': total_targets,
                    'total_certificates': total_certs,
                    'results': current_batch,
                    'complete': True
                }
                try:
                    json_data = json.dumps(final_update)
                    # Split large updates into smaller chunks if needed
                    if len(json_data) > 1000000:  # If JSON is larger than ~1MB
                        # Send the update without the results first
                        status_update = {
                            'progress': 100,
                            'processed': processed,
                            'total': total_targets,
                            'total_certificates': total_certs,
                            'results': [],
                            'complete': False
                        }
                        yield f'data: {json.dumps(status_update)}\n\n'
                        
                        # Then send the results in smaller batches
                        chunk_size = 50  # Adjust this value as needed
                        for i in range(0, len(current_batch), chunk_size):
                            chunk = current_batch[i:i + chunk_size]
                            chunk_update = {
                                'progress': 100,
                                'processed': processed,
                                'total': total_targets,
                                'total_certificates': total_certs,
                                'results': chunk,
                                'complete': (processed == total_targets and i + chunk_size >= len(current_batch))
                            }
                            yield f'data: {json.dumps(chunk_update)}\n\n'
                    else:
                        # Send the complete update if it's small enough
                        yield f'data: {json_data}\n\n'
                except Exception as e:
                    print(f"Error serializing final update: {str(e)}", flush=True)
            
        except Exception as e:
            print(f"Error in scan_certificates: {str(e)}", flush=True)
            import traceback
            traceback.print_exc()
            yield f'data: {{"error": "{str(e)}"}}\n\n'
            
        finally:
            if process:
                process.terminate()
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                    print("Cleaned up temporary file", flush=True)
                except Exception as e:
                    print(f"Error removing temp file: {str(e)}", flush=True)
    
    return Response(generate(), mimetype='text/event-stream')

def get_certificates(domain):
    """
    Query certificates for a domain using crt.sh
    """
    print(f"\n=== Checking certificates for {domain} ===", flush=True)
    
    try:
        processed_certs = []
        
        # Query crt.sh
        try:
            print(f"Querying crt.sh for {domain}", flush=True)
            session = create_session()
            url = f"https://crt.sh/?q={domain}&output=json"
            response = session.get(url, timeout=30)
            response.raise_for_status()
            
            crt_sh_certs = response.json()
            print(f"Found {len(crt_sh_certs)} certificates in crt.sh for {domain}", flush=True)
            
            # Process crt.sh certificates
            for cert in crt_sh_certs:
                try:
                    # Use the correct field names from the crt.sh response
                    not_after = datetime.strptime(cert['not_after'], '%Y-%m-%dT%H:%M:%S')
                    not_before = datetime.strptime(cert['not_before'], '%Y-%m-%dT%H:%M:%S')
                    now = datetime.now()
                    
                    # Calculate status and days until expiry
                    days_until_expiry = (not_after - now).days
                    
                    if now > not_after:
                        status = 'Expired'
                        color = 'danger'
                    elif now < not_before:
                        status = 'Not Yet Valid'
                        color = 'warning'
                    else:
                        if days_until_expiry <= 30:
                            status = f'Expiring Soon ({days_until_expiry} days)'
                            color = 'warning'
                        else:
                            status = 'Valid'
                            color = 'success'
                    
                    # Create the certificate record with all required fields
                    processed_cert = {
                        'Domain': domain,
                        'Status': status,
                        'Issuer': cert['issuer_name'],
                        'Time Until Expiry': f"{days_until_expiry} days",
                        'Expiration Date': not_after.strftime('%Y-%m-%d'),
                        'common_name': cert['common_name'],
                        'serial_number': cert['serial_number']
                    }
                    processed_certs.append(processed_cert)
                    
                except Exception as e:
                    print(f"Error processing individual certificate: {str(e)}", flush=True)
                    continue
                    
        except Exception as e:
            print(f"Error querying crt.sh: {str(e)}", flush=True)
            raise
            
        return processed_certs
            
    except Exception as e:
        print(f"Fatal error in get_certificates: {str(e)}", flush=True)
        return []

@app.route('/query_ctl', methods=['POST'])
def query_ctl():
    print("\n=== Starting CT Log Query ===", flush=True)
    
    # Get domains from request
    domains = []
    if 'file' in request.files:
        file = request.files['file']
        file_data = file.read().decode('utf-8').splitlines()
        domains = [d.strip() for d in file_data if d.strip()]
    else:
        text_data = request.form.get('targets', '')
        domains = [d.strip() for d in text_data.splitlines() if d.strip()]

    def generate():
        try:
            total = len(domains)
            processed = 0
            all_results = []
            
            for domain in domains:
                try:
                    print(f"Processing domain: {domain}", flush=True)
                    session = create_session()
                    url = f"https://crt.sh/?q={domain}&output=json"
                    response = session.get(url, timeout=30)
                    response.raise_for_status()
                    
                    certs = response.json()
                    domain_results = []
                    
                    for cert in certs:
                        try:
                            not_after = datetime.strptime(cert['not_after'], '%Y-%m-%dT%H:%M:%S')
                            not_before = datetime.strptime(cert['not_before'], '%Y-%m-%dT%H:%M:%S')
                            now = datetime.now()
                            days_until_expiry = (not_after - now).days
                            
                            if now > not_after:
                                status = 'Expired'
                                priority = 1
                            elif now < not_before:
                                status = 'Not Yet Valid'
                                priority = 4
                            else:
                                if days_until_expiry <= 30:
                                    status = 'Expiring Soon'
                                    priority = 2
                                else:
                                    status = 'Valid'
                                    priority = 3
                            
                            result = {
                                'Domain': domain,
                                'Common Name': cert.get('common_name', 'Unknown'),
                                'Status': status,
                                'Issuer': cert.get('issuer_name', 'Unknown'),
                                'Expiration Date': not_after.strftime('%Y-%m-%d'),
                                'Days Until Expiry': str(days_until_expiry),
                                'priority': priority
                            }
                            domain_results.append(result)
                            
                        except Exception as e:
                            print(f"Error processing certificate: {str(e)}", flush=True)
                            continue
                    
                    # Sort domain results by priority
                    domain_results.sort(key=lambda x: (x['priority'], x.get('Days Until Expiry', 0)))
                    # Remove priority field before adding to results
                    for result in domain_results:
                        del result['priority']
                    all_results.extend(domain_results)
                    
                    processed += 1
                    progress = (processed / total) * 100
                    
                    update = {
                        'progress': progress,
                        'current_domain': domain,
                        'processed': processed,
                        'total': total,
                        'results': all_results,
                        'complete': (processed == total)
                    }
                    
                    yield f"data: {json.dumps(update)}\n\n"
                    
                except Exception as e:
                    print(f"Error processing domain {domain}: {str(e)}", flush=True)
                    continue
            
        except Exception as e:
            print(f"Fatal error in CT log query: {str(e)}", flush=True)
            error_update = {
                'error': str(e),
                'progress': 0,
                'current_domain': None,
                'processed': 0,
                'total': 0,
                'complete': True
            }
            yield f"data: {json.dumps(error_update)}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/check', methods=['POST'])
def check_domain():
    domain = request.form.get('domain')
    if not domain:
        return jsonify({'error': 'No domain provided'}), 400

    try:
        # Get certificates for domain
        certs = get_certificates(domain)
        
        # Process results
        cert_count = len(certs)
        latest_expiry = None
        issuers = set()
        
        for cert in certs:
            expiry = cert.get('not_after')
            if latest_expiry is None or expiry > latest_expiry:
                latest_expiry = expiry
            issuers.add(cert.get('issuer'))

        result = {
            'progress': 100.0,
            'current_domain': domain,
            'processed': 1,
            'total': 1,
            'results': [{
                'domain': domain,
                'cert_count': cert_count,
                'latest_expiry': latest_expiry,
                'issuers': sorted(list(issuers))
            }]
        }
        
        return jsonify(result)

    except Exception as e:
        app.logger.error(f"Error checking domain {domain}: {str(e)}")
        return jsonify({'error': f'Error checking domain: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True) 