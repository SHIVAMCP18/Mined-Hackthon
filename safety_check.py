import requests
import hashlib
import os
import time
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")

if API_KEY is None:
    raise ValueError("API_KEY environment variable not set")

BASE_URL = "https://www.virustotal.com/api/v3"
headers = {
    "x-apikey": API_KEY
}

def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()


def check_hash(file_hash):
    url = f"{BASE_URL}/files/{file_hash}"

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data["data"]["attributes"]["last_analysis_stats"]
    elif response.status_code == 404:
        return "NOT_FOUND"
    elif response.status_code == 429:
        print("Rate limit reached. Waiting 15 seconds.")
        time.sleep(15)
        return check_hash(file_hash)
    else:
        print("API Error:", response.text)
        return None


def upload_file(file_path):
    url = f"{BASE_URL}/files"
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        data = response.json()
        return data["data"]["id"]
    else:
        print("Upload failed:", response.text)
        return None


def poll_analysis(analysis_id):
    url = f"{BASE_URL}/analyses/{analysis_id}"
    while True:
        response = requests.get(url, headers=headers)
        data = response.json()

        status = data["data"]["attributes"]["status"]
        if status == "completed":
            stats = data["data"]["attributes"]["stats"]
            return stats
        print("Analysis running... waiting 10 seconds")
        time.sleep(10)


def classify(stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious > 0 or suspicious > 0: return "UNSAFE"
    return "SAFE"


def check_file_safety(file_path):
    print("Computing SHA256...")
    file_hash = compute_sha256(file_path)
    stats = check_hash(file_hash)

    if stats == "NOT_FOUND":
        print("File not found in database. Uploading..")
        analysis_id = upload_file(file_path)
        if analysis_id is None: return "ERROR"
        stats = poll_analysis(analysis_id)

    if stats is None: return "ERROR"
    result = classify(stats)

    print("Scan Results:", stats)
    return result