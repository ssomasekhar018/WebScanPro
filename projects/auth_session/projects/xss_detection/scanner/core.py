import requests
import time
from urllib.parse import quote
from bs4 import BeautifulSoup

session = requests.Session()
session.headers.update({
    "User-Agent": "XSS-Scanner/1.0"
})

# === LOGIN & GET CSRF TOKEN ===
def login_and_get_token():
    # Login
    login_url = "http://localhost:3000/login.php"
    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login"
    }
    resp = session.post(login_url, data=login_data)
    print(f"[*] Login: {resp.status_code}")
    
    # Set security to Low
    sec_url = "http://localhost:3000/security.php"
    sec_data = {"security": "low", "seclev_submit": "Submit"}
    session.post(sec_url, data=sec_data)
    time.sleep(1)

login_and_get_token()

# === REFLECTED XSS ===
def send_reflected(payload):
    payload = str(payload)
    url = "http://localhost:3000/vulnerabilities/xss_r/"
    # Get CSRF token
    resp = session.get(url)
    soup = BeautifulSoup(resp.text, 'html.parser')
    token = soup.find("input", {"name": "user_token"})["value"]
    
    params = {
        "name": payload,
        "user_token": token
    }
    start = time.time()
    resp = session.get(url, params=params)
    rtime = time.time() - start
    return {
        "url": resp.url,
        "method": "GET",
        "status": resp.status_code,
        "body": resp.text,
        "rtime": rtime,
        "headers": dict(resp.headers)
    }

# === STORED XSS ===
def send_stored_insert(payload):
    payload = str(payload)
    url = "http://localhost:3000/vulnerabilities/xss_s/"
    # Get CSRF token
    resp = session.get(url)
    soup = BeautifulSoup(resp.text, 'html.parser')
    token = soup.find("input", {"name": "user_token"})["value"]
    
    data = {
        "txtName": "test",
        "mtxMessage": payload,
        "xss_s_button": "Submit",
        "user_token": token
    }
    start = time.time()
    resp = session.post(url, data=data)
    rtime = time.time() - start
    return {
        "url": resp.url,
        "method": "POST",
        "status": resp.status_code,
        "body": resp.text,
        "rtime": rtime,
        "headers": dict(resp.headers)
    }

def fetch_stored_view():
    url = "http://localhost:3000/vulnerabilities/xss_s/"
    time.sleep(2)
    start = time.time()
    resp = session.get(url)
    rtime = time.time() - start
    return {
        "url": resp.url,
        "method": "GET",
        "status": resp.status_code,
        "body": resp.text,
        "rtime": rtime,
        "headers": dict(resp.headers)
    }