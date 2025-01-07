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

app = Flask(__name__)

# Store results globally (you might want to use a proper database in production)
current_results = []

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

@app.route('/check_certificates', methods=['POST', 'GET'])
def check_certificates():
    print(f"Request method: {request.method}")  # Debug log
    
    if request.method == 'GET':
        # Initial SSE connection
        def generate():
            print("Establishing SSE connection")  # Debug log
            yield "data: {\"status\": \"connected\"}\n\n"
        return Response(generate(), mimetype='text/event-stream')
    
    # Handle POST request
    global current_results
    print("Processing POST request")  # Debug log
    
    try:
        if 'file' not in request.files:
            print("No file in request")  # Debug log
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            print("Empty filename")  # Debug log
            return jsonify({'error': 'No file selected'}), 400

        # Read domains from uploaded file
        try:
            domains = [line.decode('utf-8').strip() for line in file.readlines() if line.strip()]
            print(f"Found {len(domains)} domains to process")  # Debug log
        except Exception as e:
            print(f"Error reading file: {str(e)}")  # Debug log
            return jsonify({'error': f'Error reading file: {str(e)}'}), 400
        
        def generate():
            try:
                current_results.clear()
                total_domains = len(domains)
                processed = 0
                
                # Process domains and collect results
                for domain in domains:
                    try:
                        print(f"Processing domain: {domain}")  # Debug log
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
                    except Exception as e:
                        print(f"Error processing domain {domain}: {str(e)}")  # Debug log
                        # Continue processing other domains
                        continue
                
                print("Processing complete")  # Debug log
                # Send final results
                yield f"data: {json.dumps({'complete': True, 'results': current_results})}\n\n"
                
            except Exception as e:
                print(f"Error in generate: {str(e)}")  # Debug log
                yield f"data: {json.dumps({'error': f'Processing error: {str(e)}'})}\n\n"
    
        return Response(generate(), mimetype='text/event-stream')
        
    except Exception as e:
        print(f"Error in main handler: {str(e)}")  # Debug log
        return jsonify({'error': f'Server error: {str(e)}'}), 500

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

if __name__ == '__main__':
    app.run(debug=True) 