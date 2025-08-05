import os
import subprocess
import pickle
import sqlite3
from flask import Flask, request

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

# 5. Flask route with multiple vulnerabilities
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

# 6. Hardcoded credentials
DATABASE_PASSWORD = "super_secret_password123"
API_KEY = "sk-1234567890abcdef"

# 7. Weak cryptographic practice
def simple_hash(password):
    # CodeQL will flag weak hashing
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

# 8. Information disclosure
def debug_info():
    import traceback
    try:
        1/0
    except:
        # CodeQL will flag information disclosure
        return traceback.format_exc()

if __name__ == "__main__":
    print(add(2, 4))
    
    # Examples that will trigger alerts
    print(run_command("test"))
    print(get_user_data("1"))
    print(simple_hash("password"))
    
    app.run(debug=True)  # Debug mode in production is also flagged