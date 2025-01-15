from flask import Flask, render_template, request, jsonify, send_file, Response
import pandas as pd
import asyncio
import aiohttp
from urllib.parse import urlparse
import socket
from concurrent.futures import ThreadPoolExecutor
import time
from crt_checker import process_domain
import json
import sys
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
import uuid
import atexit
from io import BytesIO
import requests

app = Flask(__name__)

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
                print(f"Results for {domain}:", domain_results)  # Debug log
                
                if domain_results:
                    current_results.extend(domain_results)
                    print(f"Total results so far: {len(current_results)}")  # Debug log
                
                processed += 1
                
                # Update progress and include current results
                if job_id and job_id in scan_progress:
                    progress_data = {
                        'progress': (processed / total_domains) * 100,
                        'processed': processed,
                        'total': total_domains,
                        'current_domain': domain,
                        'results': current_results,  # Include all results so far
                        'complete': False
                    }
                    print(f"Updating progress with results count: {len(current_results)}")  # Debug log
                    scan_progress[job_id].update(progress_data)
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Error processing domain {domain}: {str(e)}", flush=True)
                continue
        
        print(f"Scan complete. Total results: {len(current_results)}")  # Debug log
        
        # Send final update with complete flag
        if job_id in scan_progress:
            final_update = {
                'progress': 100,
                'processed': total_domains,
                'total': total_domains,
                'current_domain': 'Complete',
                'results': current_results,
                'complete': True
            }
            scan_progress[job_id].update(final_update)
            print(f"Final update sent with {len(current_results)} results")  # Debug log
            
            # Keep the progress data briefly to allow final update to be sent
            time.sleep(2)
        
        # Clean up progress tracking
        if job_id and job_id in scan_progress:
            del scan_progress[job_id]
            
        return current_results
        
    except Exception as e:
        print(f"Error in scan handler: {str(e)}", flush=True)
        if job_id and job_id in scan_progress:
            del scan_progress[job_id]
        return None

@app.route('/check_certificates', methods=['POST'])
def check_certificates(domains=None, name=None):
    """Route handler for certificate checking"""
    if request.method == 'GET':
        return jsonify({'error': 'POST method required'}), 405
    
    try:
        # If domains weren't passed (regular file upload)
        if domains is None:
            if 'file' not in request.files:
                return jsonify({'error': 'No file uploaded'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400

            # Read domains from uploaded file
            domains = [line.decode('utf-8').strip() for line in file.readlines() if line.strip()]
        
        def generate():
            results = perform_certificate_scan(domains, name)
            total_domains = len(domains)
            
            for i, result in enumerate(results or []):
                progress = {
                    'progress': ((i + 1) / total_domains) * 100,
                    'current_domain': domains[i],
                    'processed': i + 1,
                    'total': total_domains
                }
                yield f"data: {json.dumps(progress)}\n\n"
            
            # Send final results
            yield f"data: {json.dumps({'complete': True, 'results': results})}\n\n"
    
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
            
        # Send final completion message with empty results if none were found
        final_message = {'complete': True, 'results': []}
        print(f"Sending final message for {scan_id}: {final_message}")  # Debug log
        yield f"data: {json.dumps(final_message)}\n\n"
            
    return Response(generate(), mimetype='text/event-stream')

def process_domain(domain):
    """Process a single domain to check its certificates"""
    print(f"\n=== Starting certificate check for domain: {domain} ===")
    try:
        crt_url = f"https://crt.sh/?q={domain}&output=json"
        print(f"Querying crt.sh: {crt_url}")
        
        response = requests.get(crt_url)
        print(f"Response status code: {response.status_code}")
        
        if response.status_code == 200:
            try:
                certs = response.json()
                print(f"Found {len(certs)} certificates for {domain}")
                
                if not certs:
                    print(f"No certificates found for {domain}")
                    return []
                
                results = []
                for cert in certs:
                    try:
                        # Parse dates
                        valid_from = datetime.strptime(cert['not_before'], '%Y-%m-%dT%H:%M:%S')
                        valid_until = datetime.strptime(cert['not_after'], '%Y-%m-%dT%H:%M:%S')
                        days_remaining = (valid_until - datetime.now()).days
                        
                        # Determine certificate status
                        is_expired = days_remaining < 0
                        is_expiring = not is_expired and days_remaining < 90
                        is_valid = not is_expired and not is_expiring
                        
                        result = {
                            'domain': domain,
                            'issuer': cert.get('issuer_name', 'Unknown'),
                            'valid_from': valid_from.strftime('%Y-%m-%d'),
                            'valid_until': valid_until.strftime('%Y-%m-%d'),
                            'days_remaining': days_remaining,
                            'expired': is_expired,
                            'expiring': is_expiring,
                            'valid': is_valid
                        }
                        
                        print(f"Processed certificate result: {result}")
                        results.append(result)
                        
                    except Exception as e:
                        print(f"Error processing individual certificate: {str(e)}")
                        continue
                
                # Sort results by valid_until date in descending order (newest first)
                if results:
                    results.sort(key=lambda x: datetime.strptime(x['valid_until'], '%Y-%m-%d'), reverse=True)
                    
                    # Get the current certificate (most recent valid_until date)
                    current_cert = results[0]
                    print(f"Current certificate for {domain}: {current_cert}")
                    
                    # Get the most recent expired certificate if any
                    expired_certs = [r for r in results if r['expired']]
                    if expired_certs:
                        expired_certs.sort(key=lambda x: datetime.strptime(x['valid_until'], '%Y-%m-%d'), reverse=True)
                        recent_expired = expired_certs[0]
                        print(f"Most recent expired certificate for {domain}: {recent_expired}")
                        
                        # Return both current and most recent expired certificate
                        return [current_cert, recent_expired]
                    
                    # If no expired certificates, just return the current one
                    return [current_cert]
                else:
                    print(f"No valid results processed for {domain}")
                    return []
                
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON response: {str(e)}")
                return []
            
        else:
            print(f"Error querying crt.sh for {domain}: {response.status_code}")
            return []
            
    except Exception as e:
        print(f"Error processing domain {domain}: {str(e)}")
        return []
    finally:
        print(f"=== Completed processing for domain: {domain} ===\n")

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

if __name__ == '__main__':
    app.run(debug=True) 