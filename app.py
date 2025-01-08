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

app = Flask(__name__)

# Store results globally (you might want to use a proper database in production)
current_results = []

# Initialize scheduler with SQLite job store
jobstores = {
    'default': SQLAlchemyJobStore(url='sqlite:///jobs.sqlite')
}
scheduler = BackgroundScheduler(jobstores=jobstores)
scheduler.start()

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

@app.route('/check_certificates', methods=['POST'])
def check_certificates():
    if request.method == 'GET':
        return jsonify({'error': 'POST method required'}), 405
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Read domains from uploaded file
        domains = [line.decode('utf-8').strip() for line in file.readlines() if line.strip()]
        print(f"Found {len(domains)} domains to process")
        
        def generate():
            current_results = []
            total_domains = len(domains)
            processed = 0
            
            for domain in domains:
                try:
                    print(f"Processing domain: {domain}", flush=True)  # Debug log with flush
                    results = process_domain(domain)
                    current_results.extend(results)
                    processed += 1
                    
                    # Send progress update
                    progress = {
                        'progress': (processed / total_domains) * 100,
                        'current_domain': domain,
                        'processed': processed,
                        'total': total_domains
                    }
                    yield f"data: {json.dumps(progress)}\n\n"
                    sys.stdout.flush()  # Force flush stdout
                    
                except Exception as e:
                    print(f"Error processing domain {domain}: {str(e)}", flush=True)
                    continue
            
            # Send final results
            yield f"data: {json.dumps({'complete': True, 'results': current_results})}\n\n"
            sys.stdout.flush()
    
        return Response(generate(), mimetype='text/event-stream')
        
    except Exception as e:
        print(f"Error in main handler: {str(e)}", flush=True)
        return jsonify({'error': str(e)}), 500

    if all_results:
        # Calculate summary statistics
        df = pd.DataFrame(all_results)
        total_certs = len(df)
        status_counts = df['Status'].value_counts()
        
        summary_data = {
            'total_domains': len(domains),
            'domains_with_certs': domains_with_findings,
            'total_certificates': total_certs,
            'valid_certs': status_counts.get('Valid', 0),
            'expiring_soon': status_counts.get('Expiring Soon', 0),
            'expired': status_counts.get('Expired', 0),
            'not_yet_valid': status_counts.get('Not Yet Valid', 0)
        }
        
        return jsonify({
            'success': True,
            'results': all_results,
            'summary': summary_data
        })
    else:
        return jsonify({'success': False, 'error': 'No results found'})

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
        
        # Generate unique ID for the job
        job_id = str(uuid.uuid4())
        
        # Parse schedule time
        schedule_time = datetime.strptime(data['time'], '%H:%M').time()
        
        # Create the job based on frequency
        if data['frequency'] == 'daily':
            scheduler.add_job(
                run_scheduled_scan,
                'cron',
                hour=schedule_time.hour,
                minute=schedule_time.minute,
                id=job_id,
                replace_existing=True,
                kwargs={'name': data['name']}
            )
        elif data['frequency'] == 'weekly':
            scheduler.add_job(
                run_scheduled_scan,
                'cron',
                day_of_week='mon',
                hour=schedule_time.hour,
                minute=schedule_time.minute,
                id=job_id,
                replace_existing=True,
                kwargs={'name': data['name']}
            )
        elif data['frequency'] == 'monthly':
            scheduler.add_job(
                run_scheduled_scan,
                'cron',
                day=1,
                hour=schedule_time.hour,
                minute=schedule_time.minute,
                id=job_id,
                replace_existing=True,
                kwargs={'name': data['name']}
            )
        
        return jsonify({'success': True, 'job_id': job_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/scheduled_tasks', methods=['GET'])
def get_scheduled_tasks():
    jobs = scheduler.get_jobs()
    tasks = []
    
    for job in jobs:
        tasks.append({
            'id': job.id,
            'name': job.kwargs.get('name', 'Unnamed'),
            'frequency': job.trigger.expression,
            'time': f"{job.trigger.fields[3]}:{job.trigger.fields[4]}",
            'next_run': job.next_run_time.strftime('%Y-%m-%d %H:%M:%S')
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

if __name__ == '__main__':
    app.run(debug=True) 