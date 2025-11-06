from bs4 import BeautifulSoup
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import pandas as pd
import json
import time

# Setup Selenium
chrome_options = Options()
chrome_options.add_argument("--headless")  # Run without opening a browser window
service = Service(executable_path="C:\\Users\\somas\\OneDrive\\Documents\\Infosys Springboard\\chromedriver\\chromedriver.exe")  # Update with your ChromeDriver path
driver = webdriver.Chrome(service=service, options=chrome_options)

# List to store collected data
collected_data = []

# Target base URL (adjust as needed)
base_url = "http://localhost:8080"

# Step 1: Static pages with Requests + BeautifulSoup
def crawl_static_pages(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'lxml')
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            for input_tag in form.find_all('input'):
                param_name = input_tag.get('name', '')
                input_type = input_tag.get('type', '')
                default_value = input_tag.get('value', '')
                collected_data.append({
                    "url": url,
                    "method": method,
                    "param_name": param_name,
                    "input_type": input_type,
                    "default_value": default_value,
                    "form_action": form_action
                })
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")

# Step 2: Dynamic pages with Selenium
def crawl_dynamic_pages(url):
    try:
        driver.get(url)
        time.sleep(2)  # Wait for JS to render
        soup = BeautifulSoup(driver.page_source, 'lxml')
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            for input_tag in form.find_all('input'):
                param_name = input_tag.get('name', '')
                input_type = input_tag.get('type', '')
                default_value = input_tag.get('value', '')
                collected_data.append({
                    "url": url,
                    "method": method,
                    "param_name": param_name,
                    "input_type": input_type,
                    "default_value": default_value,
                    "form_action": form_action
                })
    except Exception as e:
        print(f"Error with Selenium on {url}: {e}")

# Main crawling logic
start_urls = [f"{base_url}/login.php"]  # Add more URLs as needed
for url in start_urls:
    crawl_static_pages(url)
    crawl_dynamic_pages(url)

# Print collected data (Deliverable for Step 2)
print("Collected forms/inputs:")
for item in collected_data:
    print(item)

# Step 3: Save to CSV and JSON
df = pd.DataFrame(collected_data)
df.to_csv("metadata.csv", index=False)
with open("metadata.json", "w") as f:
    json.dump(collected_data, f, indent=2)

# Cleanup
driver.quit()