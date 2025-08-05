import os
import subprocess
import pickle
import sqlite3
import requests
import random
import tempfile
import yaml
import xml.etree.ElementTree as ET
from flask import Flask, request, session, make_response
from urllib.parse import urlparse
import ssl
import socket

app = Flask(__name__)

def add(a, b):
    return a + b

# 1. Command Injection vulnerability
def run_command(user_input):
    # CodeQL will flag this as command injection
    command = f"echo {user_input}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

# 2. SQL Injection vulnerability
def get_user_data(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # CodeQL will flag this as SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

# 3. Path Traversal vulnerability
def read_file(filename):
    # CodeQL will flag this as path traversal
    file_path = os.path.join("/app/data/", filename)
    with open(file_path, 'r') as f:
        return f.read()

# 4. Deserialization vulnerability
def load_user_data(serialized_data):
    # CodeQL will flag this as unsafe deserialization
    return pickle.loads(serialized_data)

# NEW 5. YAML Deserialization vulnerability (unsafe_load)
def load_config(yaml_content):
    # CodeQL will flag this as unsafe YAML deserialization
    return yaml.unsafe_load(yaml_content)

# NEW 6. XML External Entity (XXE) vulnerability  
def parse_xml(xml_content):
    # CodeQL will flag this as XXE vulnerability
    parser = ET.XMLParser()
    root = ET.fromstring(xml_content, parser)
    return root

# NEW 7. Server-Side Request Forgery (SSRF)
def fetch_url(url):
    # CodeQL will flag this as SSRF vulnerability
    response = requests.get(url)
    return response.text

# NEW 8. Insecure Random Number Generation
def generate_token():
    # CodeQL will flag this as weak random number generation
    return random.randint(1000000, 9999999)

# NEW 9. Insecure SSL/TLS Configuration
def connect_insecure(hostname, port):
    # CodeQL will flag this as insecure SSL context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((hostname, port))
    ssock = context.wrap_socket(sock, server_hostname=hostname)
    return ssock

# NEW 10. Race Condition with Temporary Files
def create_temp_file(content):
    # CodeQL will flag this as insecure temp file creation
    temp_path = "/tmp/temp_" + str(random.randint(1000, 9999)) + ".txt"
    with open(temp_path, 'w') as f:
        f.write(content)
    return temp_path

# NEW 11. Log Injection vulnerability
def log_user_action(action, user_input):
    # CodeQL will flag this as log injection
    log_message = f"User performed action: {action} with input: {user_input}"
    print(log_message)  # This would go to logs in real app

# NEW 12. Cookie without Secure flag
@app.route('/login')
def login():
    resp = make_response("Logged in")
    # CodeQL will flag insecure cookie settings
    resp.set_cookie('session_id', 'abc123', httponly=False, secure=False)
    return resp

# NEW 13. Regular Expression Denial of Service (ReDoS)
def validate_email(email):
    import re
    # CodeQL will flag this as ReDoS vulnerability
    pattern = r'^(([a-zA-Z]|[0-9])+(\.([a-zA-Z]|[0-9])+)*)+@(([a-zA-Z]|[0-9])+(\.([a-zA-Z]|[0-9])+)*)+$'
    return re.match(pattern, email)

# 14. Flask route with multiple vulnerabilities
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # XSS vulnerability - unescaped user input
    return f"<h1>Search results for: {query}</h1>"

@app.route('/file')
def get_file():
    filename = request.args.get('name', '')
    # Path traversal vulnerability
    return read_file(filename)

@app.route('/exec')
def execute():
    cmd = request.args.get('cmd', '')
    # Command injection vulnerability
    return run_command(cmd)

# NEW 15. SSRF endpoint
@app.route('/proxy')
def proxy():
    url = request.args.get('url', '')
    # SSRF vulnerability
    return fetch_url(url)

# NEW 16. XML parsing endpoint
@app.route('/parse')
def parse():
    xml_data = request.get_data()
    # XXE vulnerability
    result = parse_xml(xml_data)
    return f"Parsed XML: {result.tag}"

# NEW 17. YAML loading endpoint
@app.route('/config')
def load_config_endpoint():
    yaml_data = request.get_data(as_text=True)
    # YAML deserialization vulnerability
    config = load_config(yaml_data)
    return str(config)

# NEW 18. Log injection endpoint
@app.route('/log')
def log_endpoint():
    action = request.args.get('action', '')
    user_data = request.args.get('data', '')
    # Log injection vulnerability
    log_user_action(action, user_data)
    return "Logged"

# 19. Hardcoded credentials
DATABASE_PASSWORD = "super_secret_password123"
API_KEY = "sk-1234567890abcdef"
# NEW hardcoded credentials
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET = "my-super-secret-jwt-key-123"

# 20. Weak cryptographic practice
def simple_hash(password):
    # CodeQL will flag weak hashing
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

# NEW 21. Another weak crypto function
def encrypt_data(data):
    import hashlib
    # CodeQL will flag SHA1 as weak
    return hashlib.sha1(data.encode()).hexdigest()

# 22. Information disclosure
def debug_info():
    import traceback
    try:
        1/0
    except:
        # CodeQL will flag information disclosure
        return traceback.format_exc()

# NEW 23. Directory listing vulnerability
def list_directory(path):
    # CodeQL will flag this as information disclosure
    try:
        return os.listdir(path)
    except:
        return []

# NEW 24. Weak session configuration
app.secret_key = "weak_key_123"  # CodeQL will flag weak secret key

if __name__ == "__main__":
    print(add(2, 3))
    
    # Examples that will trigger alerts
    print(run_command("test"))
    print(get_user_data("1"))
    print(simple_hash("password"))
    print(generate_token())
    print(encrypt_data("sensitive_data"))
    
    # NEW examples
    temp_file = create_temp_file("test content")
    print(f"Created temp file: {temp_file}")
    
    log_user_action("login", "user123\n[INJECTED] Admin logged in")
    
    app.run(debug=True, host='0.0.0.0')  # Debug mode + bind to all interfaces