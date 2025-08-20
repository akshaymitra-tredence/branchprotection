import os
import subprocess
import pickle
import sqlite3
import requests
import random
import tempfile
import yaml
import xml.etree.ElementTree as ET
import ssl
import socket
import hashlib
import re
from typing import Optional
from fastapi import FastAPI, Request, Response, HTTPException, Cookie, Form, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="Vulnerable FastAPI App", debug=True)
security = HTTPBasic()

# Pydantic models
class UserData(BaseModel):
    user_id: str
    data: str

class CommandRequest(BaseModel):
    command: str

class ConfigData(BaseModel):
    config: str

def add(a, b):
    return a + b

# 1. Command Injection vulnerability
@app.post("/execute")
async def execute_command(cmd_request: CommandRequest):
    # CodeQL will flag this as command injection
    command = f"echo {cmd_request.command}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return {"output": result.stdout, "error": result.stderr}

# 2. SQL Injection vulnerability
@app.get("/user/{user_id}")
async def get_user_data(user_id: str):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # CodeQL will flag this as SQL injection
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    result = cursor.fetchall()
    conn.close()
    return {"user_data": result}

# 3. Path Traversal vulnerability
@app.get("/file")
async def read_file(filename: str):
    # CodeQL will flag this as path traversal
    file_path = os.path.join("/app/data/", filename)
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return {"content": content}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")

# 4. Deserialization vulnerability
@app.post("/deserialize")
async def load_user_data(request: Request):
    # CodeQL will flag this as unsafe deserialization
    data = await request.body()
    try:
        result = pickle.loads(data)
        return {"result": str(result)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 5. YAML Deserialization vulnerability
@app.post("/config")
async def load_config(config_data: ConfigData):
    # CodeQL will flag this as unsafe YAML deserialization
    try:
        result = yaml.unsafe_load(config_data.config)
        return {"config": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 6. XML External Entity (XXE) vulnerability
@app.post("/parse-xml")
async def parse_xml(request: Request):
    # CodeQL will flag this as XXE vulnerability
    xml_content = await request.body()
    try:
        parser = ET.XMLParser()
        root = ET.fromstring(xml_content, parser)
        return {"tag": root.tag, "text": root.text}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 7. Server-Side Request Forgery (SSRF)
@app.get("/proxy")
async def fetch_url(url: str):
    # CodeQL will flag this as SSRF vulnerability
    try:
        response = requests.get(url, timeout=10)
        return {"content": response.text[:1000], "status": response.status_code}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 8. Cross-Site Scripting (XSS) via HTML response
@app.get("/search", response_class=HTMLResponse)
async def search(q: str = ""):
    # CodeQL will flag this as XSS vulnerability
    html_content = f"""
    <html>
        <head><title>Searchs Results</title></head>
        <body>
            <h1>Searchs results for: {q}</h1>
            <p>You searched for: {q}</p>
        </body>
    </html>
    """
    return html_content

# 9. Insecure Cookie Settings
@app.post("/login")
async def login(response: Response, username: str = Form(...), password: str = Form(...)):
    # CodeQL will flag insecure cookie settings
    if username == "admin" and password == "password":  # Hardcoded credentials
        response.set_cookie(
            key="session_id", 
            value="abc123456789",
            httponly=False,  # Should be True
            secure=False,    # Should be True in production
            samesite="none"  # Should be "strict" or "lax"
        )
        return {"message": "Logged in successfully"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

# 10. Insecure Random Number Generation
@app.get("/token")
async def generate_token():
    # CodeQL will flag this as weak random number generation
    token = random.randint(1000000000, 9999999999)
    return {"token": str(token)}

# 11. Weak Cryptographic Practices
@app.post("/hash")
async def hash_password(password: str = Form(...)):
    # CodeQL will flag weak hashing algorithms
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    return {
        "md5": md5_hash,
        "sha1": sha1_hash
    }

# 12. Log Injection vulnerability
@app.post("/log")
async def log_action(action: str, user_input: str):
    # CodeQL will flag this as log injection
    log_message = f"User performed action: {action} with input: {user_input}"
    print(log_message)  # This would go to application logs
    return {"message": "Action logged"}

# 13. Regular Expression Denial of Service (ReDoS)
@app.get("/validate-email")
async def validate_email(email: str):
    # CodeQL will flag this as ReDoS vulnerability
    pattern = r'^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$'
    # Vulnerable pattern that can cause catastrophic backtracking
    vulnerable_pattern = r'^(([a-zA-Z]|[0-9])+(\.([a-zA-Z]|[0-9])+)*)+@(([a-zA-Z]|[0-9])+(\.([a-zA-Z]|[0-9])+)*)+$'
    
    match = re.match(vulnerable_pattern, email)
    return {"valid": bool(match), "email": email}

# 14. Information Disclosure
@app.get("/debug")
async def debug_info():
    # CodeQL will flag information disclosure
    import traceback
    try:
        # Intentionally cause an error
        result = 1 / 0
    except Exception:
        error_trace = traceback.format_exc()
        return {"error": error_trace}

# 15. Directory Traversal via File Upload
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    # CodeQL will flag this as path traversal
    file_path = os.path.join("/app/uploads/", file.filename)
    try:
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        return {"message": f"File {file.filename} uploaded successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 16. Insecure SSL Context
@app.get("/secure-connect")
async def connect_insecure(hostname: str, port: int = 443):
    # CodeQL will flag this as insecure SSL context
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.create_connection((hostname, port), timeout=5)
        ssock = context.wrap_socket(sock, server_hostname=hostname)
        return {"message": f"Connected to {hostname}:{port}"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 17. Race Condition with Temporary Files
@app.post("/temp-file")
async def create_temp_file(content: str = Form(...)):
    # CodeQL will flag this as insecure temp file creation
    temp_filename = f"temp_{random.randint(1000, 9999)}.txt"
    temp_path = os.path.join("/tmp", temp_filename)
    
    try:
        with open(temp_path, 'w') as f:
            f.write(content)
        return {"temp_file": temp_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 18. NoSQL Injection (if using MongoDB)
@app.get("/mongo-user")
async def get_mongo_user(user_filter: str):
    # CodeQL will flag this as NoSQL injection
    # Simulated - would be dangerous with real MongoDB
    import json
    try:
        filter_dict = json.loads(user_filter)  # Dangerous - allows injection
        return {"filter": filter_dict, "message": "This would query MongoDB"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 19. Hardcoded Secrets and Credentials
DATABASE_PASSWORD = "super_secret_password123"
API_KEY = "sk-1234567890abcdef"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET = "my-super-secret-jwt-key-123"
CRYPTO_KEY = "hardcoded-encryption-key-2024"

# 20. Authentication Bypass
@app.get("/admin")
async def admin_panel(credentials: HTTPBasicCredentials = security):
    # CodeQL will flag weak authentication
    if credentials.username == "admin" and credentials.password == "admin":
        return {"message": "Welcome to admin panel", "sensitive_data": "secret_info"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

# 21. Information Exposure through Error Messages
@app.get("/database-info")
async def get_database_info(table_name: str):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        # This will expose database structure in error messages
        cursor.execute(f"SELECT * FROM {table_name}")
        result = cursor.fetchall()
        conn.close()
        return {"data": result}
    except Exception as e:
        # CodeQL will flag information disclosure through error messages
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# 22. Unsafe Redirect
@app.get("/redirect")
async def unsafe_redirect(url: str):
    # CodeQL will flag this as open redirect vulnerability
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=url)

# Health check endpoint (safe)
@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

if __name__ == "__main__":
    print(add(2, 4))
    
    # Run the FastAPI app with insecure settings
    uvicorn.run(
        app, 
        host="0.0.0.0",  # Binding to all interfaces
        port=8000, 
        debug=True,      # Debug mode in production
        reload=True
    )